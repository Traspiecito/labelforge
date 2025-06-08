#!/usr/bin/env python3
"""
Sistema de Escaneo y Enrutamiento de Paquetes
============================================

Este programa permite escanear códigos de área y guías de paquetes,
asignando automáticamente las guías al último código de área escaneado.
Guarda automáticamente en CSV/Excel para prevenir pérdida de datos.

Autor: Asistente Claude
Fecha: 2025
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.live import Live
from rich.text import Text
from rich import print as rprint
import pandas as pd
import logging
from datetime import datetime
from pathlib import Path
import re
import sys
from typing import Dict, Set, List, Optional
import json
import signal
import atexit

# ================================
# CONFIGURACIÓN GLOBAL
# ================================

# Inicializar Typer y Rich
app = typer.Typer(help="Sistema de Escaneo y Enrutamiento de Paquetes")
console = Console()

# Configuración de archivos
DATA_DIR = Path("datos_escaneo")
BACKUP_DIR = Path("respaldos")
CONFIG_FILE = DATA_DIR / "config.json"
LOGS_DIR = Path("logs")

# Configuración de logging
LOGS_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / f'scanner_{datetime.now().strftime("%Y%m%d")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ================================
# CLASES PRINCIPALES
# ================================

class PackageScanner:
    """
    Clase principal para manejar el escaneo y procesamiento de paquetes.
    
    Mantiene el estado del programa, maneja la asignación de guías a códigos de área,
    y gestiona la persistencia de datos en tiempo real.
    """
    
    def __init__(self, output_file: str = None):
        """
        Inicializa el escáner de paquetes.
        
        Args:
            output_file: Nombre del archivo de salida (opcional)
        """
        # Crear directorios necesarios
        DATA_DIR.mkdir(exist_ok=True)
        BACKUP_DIR.mkdir(exist_ok=True)
        
        # Estado del programa
        self.current_area_code: Optional[str] = None
        self.area_guides: Dict[str, Set[str]] = {}  # {codigo_area: {guias}}
        self.all_guides: Set[str] = set()  # Para detectar duplicados globales
        self.scan_history: List[Dict] = []  # Historial de escaneos
        
        # Configuración de archivos
        self.output_file = output_file or f"paquetes_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.csv_file = DATA_DIR / f"{self.output_file}.csv"
        self.excel_file = DATA_DIR / f"{self.output_file}.xlsx"
        self.state_file = DATA_DIR / f"{self.output_file}_estado.json"
        
        # Cargar estado previo si existe
        self._load_state()
        
        # Registrar función de limpieza para cierre del programa
        atexit.register(self._cleanup)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info(f"Scanner inicializado. Archivo de salida: {self.output_file}")
    
    def _signal_handler(self, signum, frame):
        """Maneja señales del sistema para cierre controlado."""
        console.print("\n[yellow]Cerrando programa de forma segura...[/yellow]")
        self._cleanup()
        sys.exit(0)
    
    def _cleanup(self):
        """Realiza limpieza y guardado final antes del cierre."""
        try:
            self._save_state()
            self._save_to_files()
            logger.info("Limpieza completada exitosamente")
        except Exception as e:
            logger.error(f"Error durante limpieza: {e}")
    
    def _load_state(self):
        """Carga el estado previo del programa si existe."""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                
                self.current_area_code = state.get('current_area_code')
                
                # Convertir sets de vuelta desde listas
                self.area_guides = {
                    area: set(guides) 
                    for area, guides in state.get('area_guides', {}).items()
                }
                
                self.all_guides = set(state.get('all_guides', []))
                self.scan_history = state.get('scan_history', [])
                
                logger.info(f"Estado previo cargado: {len(self.all_guides)} guías, {len(self.area_guides)} áreas")
                console.print(f"[green]Estado previo cargado exitosamente[/green]")
                
        except Exception as e:
            logger.error(f"Error cargando estado previo: {e}")
            console.print(f"[yellow]No se pudo cargar estado previo, iniciando limpio[/yellow]")
    
    def _save_state(self):
        """Guarda el estado actual del programa."""
        try:
            state = {
                'current_area_code': self.current_area_code,
                'area_guides': {
                    area: list(guides) 
                    for area, guides in self.area_guides.items()
                },
                'all_guides': list(self.all_guides),
                'scan_history': self.scan_history,
                'last_save': datetime.now().isoformat()
            }
            
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"Error guardando estado: {e}")
    
    def _is_area_code(self, code: str) -> bool:
        """
        Determina si un código es un código de área.
        
        Personaliza esta función según tus códigos de área específicos.
        Por defecto, asume que códigos de área son alfanuméricos cortos (2-10 caracteres).
        
        Args:
            code: Código a verificar
            
        Returns:
            True si es código de área, False si es guía
        """
        # Personalizar según tus necesidades
        # Ejemplos de criterios:
        # - Códigos de área: A1, B2, ZONA-01, etc.
        # - Guías: números más largos, con formato específico
        
        code = code.strip().upper()
        
        # Criterio 1: Códigos cortos (2-10 caracteres) con letras
        if 2 <= len(code) <= 10 and any(c.isalpha() for c in code):
            return True
        
        # Criterio 2: Patrones específicos como ZONA-XX, AREA-XX
        if re.match(r'^(ZONA|AREA|SECTOR)-?\w+$', code):
            return True
        
        # Criterio 3: Códigos puramente alfabéticos cortos
        if code.isalpha() and len(code) <= 5:
            return True
        
        # Si no cumple criterios de área, es una guía
        return False
    
    def process_scan(self, scanned_code: str) -> Dict[str, str]:
        """
        Procesa un código escaneado, determinando si es área o guía.
        
        Args:
            scanned_code: Código escaneado
            
        Returns:
            Diccionario con información del procesamiento
        """
        try:
            code = scanned_code.strip()
            if not code:
                return {"status": "error", "message": "Código vacío"}
            
            # Registrar en historial
            scan_entry = {
                "timestamp": datetime.now().isoformat(),
                "code": code,
                "type": None,
                "action": None
            }
            
            if self._is_area_code(code):
                # Es un código de área
                self.current_area_code = code.upper()
                
                # Crear área si no existe
                if self.current_area_code not in self.area_guides:
                    self.area_guides[self.current_area_code] = set()
                
                scan_entry["type"] = "area"
                scan_entry["action"] = f"Área cambiada a {self.current_area_code}"
                
                result = {
                    "status": "success",
                    "type": "area",
                    "message": f"Área cambiada a: {self.current_area_code}",
                    "area_code": self.current_area_code
                }
                
                logger.info(f"Código de área escaneado: {self.current_area_code}")
                
            else:
                # Es una guía
                if not self.current_area_code:
                    result = {
                        "status": "error",
                        "type": "guide",
                        "message": "Error: Debe escanear un código de área primero"
                    }
                    scan_entry["action"] = "Error: Sin área asignada"
                    
                elif code in self.all_guides:
                    # Guía duplicada
                    result = {
                        "status": "warning",
                        "type": "guide",
                        "message": f"Guía duplicada ignorada: {code}",
                        "guide": code
                    }
                    scan_entry["action"] = f"Duplicada - Ignorada"
                    
                else:
                    # Nueva guía válida
                    self.area_guides[self.current_area_code].add(code)
                    self.all_guides.add(code)
                    
                    result = {
                        "status": "success",
                        "type": "guide",
                        "message": f"Guía {code} asignada a {self.current_area_code}",
                        "guide": code,
                        "area_code": self.current_area_code
                    }
                    scan_entry["action"] = f"Asignada a {self.current_area_code}"
                    
                    logger.info(f"Guía asignada: {code} -> {self.current_area_code}")
                
                scan_entry["type"] = "guide"
            
            # Guardar en historial y estado
            self.scan_history.append(scan_entry)
            self._save_state()
            self._save_to_files()
            
            return result
            
        except Exception as e:
            error_msg = f"Error procesando código {scanned_code}: {e}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}
    
    def _save_to_files(self):
        """Guarda los datos actuales en archivos CSV y Excel."""
        try:
            if not self.area_guides:
                return
            
            # Preparar datos para DataFrame
            max_guides = max(len(guides) for guides in self.area_guides.values()) if self.area_guides else 0
            
            # Crear diccionario para DataFrame
            data_dict = {}
            for area_code, guides in self.area_guides.items():
                guides_list = list(guides)
                # Rellenar con valores vacíos si es necesario
                while len(guides_list) < max_guides:
                    guides_list.append("")
                data_dict[area_code] = guides_list
            
            # Crear DataFrame
            df = pd.DataFrame(data_dict)
            
            # Guardar CSV
            df.to_csv(self.csv_file, index=False, encoding='utf-8-sig')
            
            # Guardar Excel con formato
            with pd.ExcelWriter(self.excel_file, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Paquetes', index=False)
                
                # Obtener el workbook y worksheet para formateo
                workbook = writer.book
                worksheet = writer.sheets['Paquetes']
                
                # Autoajustar columnas
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column_letter].width = adjusted_width
            
            logger.info(f"Archivos guardados: {self.csv_file.name}, {self.excel_file.name}")
            
        except Exception as e:
            logger.error(f"Error guardando archivos: {e}")
    
    def get_statistics(self) -> Dict:
        """Retorna estadísticas actuales del escaneo."""
        total_guides = len(self.all_guides)
        total_areas = len(self.area_guides)
        
        area_stats = {}
        for area, guides in self.area_guides.items():
            area_stats[area] = len(guides)
        
        return {
            "total_guides": total_guides,
            "total_areas": total_areas,
            "current_area": self.current_area_code,
            "area_stats": area_stats,
            "files": {
                "csv": str(self.csv_file),
                "excel": str(self.excel_file)
            }
        }
    
    def create_backup(self) -> str:
        """Crea un respaldo de los datos actuales."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_{self.output_file}_{timestamp}"
            
            # Copiar archivos principales
            if self.csv_file.exists():
                backup_csv = BACKUP_DIR / f"{backup_name}.csv"
                backup_csv.write_bytes(self.csv_file.read_bytes())
            
            if self.excel_file.exists():
                backup_excel = BACKUP_DIR / f"{backup_name}.xlsx"
                backup_excel.write_bytes(self.excel_file.read_bytes())
            
            # Copiar estado
            if self.state_file.exists():
                backup_state = BACKUP_DIR / f"{backup_name}_estado.json"
                backup_state.write_bytes(self.state_file.read_bytes())
            
            logger.info(f"Respaldo creado: {backup_name}")
            return backup_name
            
        except Exception as e:
            logger.error(f"Error creando respaldo: {e}")
            return None

# ================================
# FUNCIONES DE INTERFAZ
# ================================

def create_status_table(scanner: PackageScanner) -> Table:
    """Crea una tabla con el estado actual del escaneo."""
    table = Table(title="Estado Actual del Escaneo")
    
    table.add_column("Información", style="cyan", no_wrap=True)
    table.add_column("Valor", style="green")
    
    stats = scanner.get_statistics()
    
    table.add_row("Área Actual", stats["current_area"] or "Ninguna")
    table.add_row("Total Guías", str(stats["total_guides"]))
    table.add_row("Total Áreas", str(stats["total_areas"]))
    
    # Mostrar estadísticas por área
    for area, count in stats["area_stats"].items():
        table.add_row(f"  └─ {area}", str(count))
    
    return table

def display_help():
    """Muestra ayuda sobre el uso del programa."""
    help_text = """
[bold blue]Instrucciones de Uso:[/bold blue]

[green]Escaneo de Códigos:[/green]
• Escanee un código de área para cambiar la zona activa
• Luego escanee guías que se asignarán automáticamente a esa área
• Las guías duplicadas serán ignoradas automáticamente

[green]Comandos Especiales:[/green]
• [bold]quit[/bold] o [bold]salir[/bold]: Termina el programa
• [bold]stats[/bold] o [bold]estadisticas[/bold]: Muestra estadísticas
• [bold]help[/bold] o [bold]ayuda[/bold]: Muestra esta ayuda
• [bold]backup[/bold] o [bold]respaldo[/bold]: Crea respaldo manual
• [bold]clear[/bold]: Limpia la pantalla

[yellow]Identificación Automática:[/yellow]
• Códigos de área: Generalmente cortos (2-10 chars) con letras
• Guías: Números largos o códigos sin letras

[red]Importante:[/red]
• Los datos se guardan automáticamente en cada escaneo
• Se mantiene respaldo de estado para recuperación
• Revise los logs en caso de errores
    """
    console.print(Panel(help_text, title="Ayuda del Sistema"))

# ================================
# COMANDOS TYPER
# ================================

@app.command()
def scan(
    output_file: str = typer.Option(None, "--output", "-o", help="Nombre del archivo de salida"),
    interactive: bool = typer.Option(True, "--interactive/--no-interactive", help="Modo interactivo")
):
    """
    Inicia el sistema de escaneo interactivo.
    
    Este es el comando principal para escanear códigos de área y guías.
    """
    try:
        # Crear instancia del scanner
        scanner = PackageScanner(output_file)
        
        # Mostrar información inicial
        console.print(Panel.fit(
            "[bold blue]Sistema de Escaneo y Enrutamiento de Paquetes[/bold blue]\n"
            f"Archivo de salida: [green]{scanner.output_file}[/green]\n"
            "Escriba 'help' para instrucciones detalladas",
            title="Iniciando Sistema"
        ))
        
        if not interactive:
            console.print("[yellow]Modo no interactivo - use otros comandos[/yellow]")
            return
        
        # Mostrar estado inicial
        console.print(create_status_table(scanner))
        
        # Loop principal de escaneo
        while True:
            try:
                # Prompt para entrada
                prompt_text = f"[{'green' if scanner.current_area_code else 'yellow'}]"
                if scanner.current_area_code:
                    prompt_text += f"Área: {scanner.current_area_code}"
                else:
                    prompt_text += "Sin área asignada"
                prompt_text += "[/]"
                
                # Obtener entrada del usuario
                user_input = Prompt.ask(
                    f"{prompt_text} > Escanee código",
                    default=""
                ).strip()
                
                # Procesar comandos especiales
                if user_input.lower() in ['quit', 'salir', 'exit']:
                    break
                elif user_input.lower() in ['help', 'ayuda']:
                    display_help()
                    continue
                elif user_input.lower() in ['stats', 'estadisticas']:
                    console.print(create_status_table(scanner))
                    continue
                elif user_input.lower() in ['backup', 'respaldo']:
                    backup_name = scanner.create_backup()
                    if backup_name:
                        console.print(f"[green]Respaldo creado: {backup_name}[/green]")
                    else:
                        console.print("[red]Error creando respaldo[/red]")
                    continue
                elif user_input.lower() == 'clear':
                    console.clear()
                    console.print(create_status_table(scanner))
                    continue
                elif not user_input:
                    continue
                
                # Procesar código escaneado
                result = scanner.process_scan(user_input)
                
                # Mostrar resultado
                if result["status"] == "success":
                    if result["type"] == "area":
                        console.print(f"[bold green]✓ {result['message']}[/bold green]")
                    else:
                        console.print(f"[green]✓ {result['message']}[/green]")
                elif result["status"] == "warning":
                    console.print(f"[yellow]⚠ {result['message']}[/yellow]")
                else:
                    console.print(f"[red]✗ {result['message']}[/red]")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error en loop principal: {e}")
                console.print(f"[red]Error: {e}[/red]")
        
        # Mensaje de cierre
        stats = scanner.get_statistics()
        console.print(Panel.fit(
            f"[bold blue]Sesión Finalizada[/bold blue]\n"
            f"Total procesado: [green]{stats['total_guides']} guías[/green] en [green]{stats['total_areas']} áreas[/green]\n"
            f"Archivos guardados en: [cyan]{DATA_DIR}[/cyan]",
            title="Resumen Final"
        ))
        
    except Exception as e:
        logger.error(f"Error fatal en comando scan: {e}")
        console.print(f"[red]Error fatal: {e}[/red]")
        raise typer.Exit(1)

@app.command()
def stats(file_pattern: str = typer.Option("*", help="Patrón de archivos a analizar")):
    """Muestra estadísticas de archivos existentes."""
    try:
        # Buscar archivos de estado
        state_files = list(DATA_DIR.glob(f"{file_pattern}_estado.json"))
        
        if not state_files:
            console.print("[yellow]No se encontraron archivos de estado[/yellow]")
            return
        
        for state_file in state_files:
            try:
                with open(state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                
                # Crear tabla de estadísticas
                table = Table(title=f"Estadísticas: {state_file.stem.replace('_estado', '')}")
                table.add_column("Área", style="cyan")
                table.add_column("Guías", style="green", justify="right")
                
                area_guides = state.get('area_guides', {})
                total_guides = 0
                
                for area, guides in area_guides.items():
                    count = len(guides)
                    total_guides += count
                    table.add_row(area, str(count))
                
                table.add_row("[bold]TOTAL[/bold]", f"[bold]{total_guides}[/bold]")
                
                console.print(table)
                console.print(f"Última actualización: {state.get('last_save', 'Desconocido')}\n")
                
            except Exception as e:
                console.print(f"[red]Error leyendo {state_file.name}: {e}[/red]")
                
    except Exception as e:
        console.print(f"[red]Error en comando stats: {e}[/red]")

@app.command()
def backup(
    source: str = typer.Option("*", help="Patrón de archivos a respaldar"),
    destination: str = typer.Option(None, help="Directorio de destino personalizado")
):
    """Crea respaldos manuales de los datos."""
    try:
        backup_dir = Path(destination) if destination else BACKUP_DIR
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        files_backed_up = 0
        
        # Respaldar archivos CSV
        for csv_file in DATA_DIR.glob(f"{source}.csv"):
            backup_name = backup_dir / f"backup_{csv_file.stem}_{timestamp}.csv"
            backup_name.write_bytes(csv_file.read_bytes())
            files_backed_up += 1
        
        # Respaldar archivos Excel
        for excel_file in DATA_DIR.glob(f"{source}.xlsx"):
            backup_name = backup_dir / f"backup_{excel_file.stem}_{timestamp}.xlsx"
            backup_name.write_bytes(excel_file.read_bytes())
            files_backed_up += 1
        
        # Respaldar estados
        for state_file in DATA_DIR.glob(f"{source}_estado.json"):
            backup_name = backup_dir / f"backup_{state_file.stem}_{timestamp}.json"
            backup_name.write_bytes(state_file.read_bytes())
            files_backed_up += 1
        
        if files_backed_up > 0:
            console.print(f"[green]✓ {files_backed_up} archivos respaldados en {backup_dir}[/green]")
        else:
            console.print("[yellow]No se encontraron archivos para respaldar[/yellow]")
            
    except Exception as e:
        console.print(f"[red]Error creando respaldos: {e}[/red]")

@app.command()
def list_files():
    """Lista todos los archivos de datos disponibles."""
    try:
        console.print("[bold blue]Archivos de Datos Disponibles:[/bold blue]\n")
        
        # Archivos CSV
        csv_files = list(DATA_DIR.glob("*.csv"))
        if csv_files:
            console.print("[green]Archivos CSV:[/green]")
            for f in csv_files:
                size = f.stat().st_size
                modified = datetime.fromtimestamp(f.stat().st_mtime)
                console.print(f"  • {f.name} ({size:,} bytes, {modified.strftime('%Y-%m-%d %H:%M')})")
        
        # Archivos Excel  
        excel_files = list(DATA_DIR.glob("*.xlsx"))
        if excel_files:
            console.print("\n[green]Archivos Excel:[/green]")
            for f in excel_files:
                size = f.stat().st_size
                modified = datetime.fromtimestamp(f.stat().st_mtime)
                console.print(f"  • {f.name} ({size:,} bytes, {modified.strftime('%Y-%m-%d %H:%M')})")
        
        # Archivos de estado
        state_files = list(DATA_DIR.glob("*_estado.json"))
        if state_files:
            console.print("\n[green]Archivos de Estado:[/green]")
            for f in state_files:
                console.print(f"  • {f.name}")
        
        # Respaldos
        backup_files = list(BACKUP_DIR.glob("backup_*"))
        if backup_files:
            console.print(f"\n[green]Respaldos ({len(backup_files)}):[/green]")
            for f in sorted(backup_files, key=lambda x: x.stat().st_mtime, reverse=True)[:5]:
                modified = datetime.fromtimestamp(f.stat().st_mtime)
                console.print(f"  • {f.name} ({modified.strftime('%Y-%m-%d %H:%M')})")
            if len(backup_files) > 5:
                console.print(f"  ... y {len(backup_files) - 5} más")
        
        if not any([csv_files, excel_files, state_files]):
            console.print("[yellow]No se encontraron archivos de datos[/yellow]")
            
    except Exception as e:
        console.print(f"[red]Error listando archivos: {e}[/red]")

# ================================
# FUNCIÓN PRINCIPAL
# ================================

def main():
    """Función principal del programa."""
    try:
        app()
    except Exception as e:
        logger.error(f"Error fatal en main: {e}")
        console.print(f"[red]Error fatal: {e}[/red]")
        return 1
    return 0

if __name__ == "__main__":
    exit(main())