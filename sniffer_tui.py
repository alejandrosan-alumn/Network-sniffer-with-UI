import os
import sys
import threading
import subprocess
from datetime import datetime

# --- AUTO-INSTALACION ---
def verificar_dependencias():
    librerias = ["textual", "scapy", "psutil"]
    for lib in librerias:
        try:
            __import__(lib)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])

verificar_dependencias()

import psutil
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, RichLog, Label, Button, ListItem, ListView
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from scapy.all import sniff, IP, Ether

# --- VENTANA EMERGENTE PARA DETALLES ---
class DetalleIPScreen(ModalScreen):
    def __init__(self, ip, info_nmap):
        super().__init__()
        self.ip = ip
        self.info_nmap = info_nmap

    def compose(self) -> ComposeResult:
        with Vertical(id="modal_container"):
            yield Label(f"ANALISIS DE SEGURIDAD: {self.ip}", id="modal_title")
            yield RichLog(id="modal_log", markup=True, highlight=True)
            yield Button("CERRAR", variant="error", id="close_btn")

    def on_mount(self):
        log = self.query_one("#modal_log")
        log.write(self.info_nmap)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close_btn":
            self.app.pop_screen()

# --- APLICACION PRINCIPAL ---
class SnifferTUI(App):
    # CSS LIMPIO: Sin font-size ni text-size para evitar errores
    CSS = """
    Screen { layout: horizontal; }
    #sidebar { width: 35%; border-right: tall $primary; background: $surface; }
    #main_content { width: 65%; }
    .title { text-align: center; background: $primary; color: white; text-style: bold; padding: 1; }
    #controls { height: auto; border-top: solid $primary; padding: 1; align: center middle; }
    Button { margin: 1; width: 15; }
    
    #modal_container {
        width: 85%; height: 85%;
        background: $surface;
        border: thick $primary;
        align: center middle;
        padding: 2;
    }
    #modal_title { text-style: bold; margin-bottom: 1; color: $accent; }
    ListItem { padding: 0 1; height: auto; }
    """

    BINDINGS = [("q", "quit", "Salir")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label(" INTERFACES ", classes="title")
                yield ListView(id="iface_list")
                yield Label(" DISPOSITIVOS (Click) ", classes="title")
                yield ListView(id="device_list")
            with Vertical(id="main_content"):
                yield Label(" AUDITORIA EN TIEMPO REAL ", classes="title")
                yield RichLog(id="event_log", highlight=True, markup=True)
                with Horizontal(id="controls"):
                    yield Button("START", id="start", variant="success")
                    yield Button("STOP", id="stop", variant="error")
                    yield Button("EXPORTAR", id="export", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        self.sniffer_activo = False 
        self.seen_ips = {}
        self.selected_interface = None
        
        iface_list = self.query_one("#iface_list")
        for iface in psutil.net_if_addrs().keys():
            iface_list.append(ListItem(Label(f"IFACE: {iface}"), id=iface))
        
        self.log_widget = self.query_one("#event_log")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "iface_list":
            self.selected_interface = event.item.id
        elif event.list_view.id == "device_list":
            # Busqueda de la IP asociada al widget clickeado
            target_ip = None
            for ip, data in self.seen_ips.items():
                if data["widget"] == event.item.children[0]:
                    target_ip = ip
                    break
            
            if target_ip:
                info = self.seen_ips[target_ip].get("nmap", "Escaneando...")
                self.push_screen(DetalleIPScreen(target_ip, info))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start" and self.selected_interface:
            if not self.sniffer_activo:
                self.sniffer_activo = True
                self.log_widget.write("[bold green]START: ESCANEO INICIADO[/bold green]")
                threading.Thread(target=self.run_sniffer, daemon=True).start()
        elif event.button.id == "stop":
            self.sniffer_activo = False
            self.log_widget.write("[bold yellow]STOP: DETENIDO[/bold yellow]")

    def run_sniffer(self):
        def packet_callback(pkt):
            if not self.sniffer_activo: return True 
            if IP in pkt:
                ip_src = pkt[IP].src
                if ip_src not in self.seen_ips:
                    # Fabricante simplificado para evitar errores de importacion
                    nuevo_label = Label(f"IP: {ip_src} [bold yellow](...)[/]")
                    self.seen_ips[ip_src] = {
                        "nmap": "Ejecutando analisis de puertos críticos...", 
                        "widget": nuevo_label
                    }
                    
                    self.call_from_thread(self.add_device_to_list, nuevo_label)
                    threading.Thread(target=self.scan_ports_background, args=(ip_src,), daemon=True).start()

        sniff(iface=self.selected_interface, prn=packet_callback, store=0, stop_filter=lambda x: not self.sniffer_activo)

    def add_device_to_list(self, label_widget: Label):
        self.query_one("#device_list").append(ListItem(label_widget))

    def scan_ports_background(self, ip: str):
        try:
            # Los 20 puertos mas comunes y vulnerables
            puertos = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
            cmd = ["nmap", "-sV", "-O", "-p", puertos, "--open", ip]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=80)
            
            os_info = "desconocido"
            for line in res.stdout.splitlines():
                if "OS details" in line:
                    os_info = line.split(":")[1].strip().lower()
                    break
            
            color = "white"
            if "windows" in os_info: color = "dodger_blue"
            elif "linux" in os_info: color = "red"
            elif "apple" in os_info: color = "yellow"
            elif "android" in os_info: color = "green"

            self.seen_ips[ip]["nmap"] = f"[bold {color}]REPORTE PARA {ip}[/]\n\n{res.stdout}"
            self.call_from_thread(self.update_ui_finished, ip, color)
            
        except Exception as e:
            self.seen_ips[ip]["nmap"] = f"Error: {e}"
            self.call_from_thread(self.update_ui_finished, ip, "red")

    def update_ui_finished(self, ip, color):
        if ip in self.seen_ips:
            label = self.seen_ips[ip]["widget"]
            label.update(f"IP: {ip} [bold {color}](LISTO)[/]")
            self.log_widget.write(f"[{color}]AUDITORIA COMPLETADA: {ip}[/]")

if __name__ == "__main__":
    if os.name != 'nt' and os.getuid() != 0:
        print("ERROR: Debe ejecutar con privilegios de root (sudo).")
        sys.exit(1)
    SnifferTUI().run()