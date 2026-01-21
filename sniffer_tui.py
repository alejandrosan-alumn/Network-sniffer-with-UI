import os
import threading
import psutil
import subprocess
from datetime import datetime
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Log, Label, Button, ListItem, ListView
from textual.containers import Horizontal, Vertical
from scapy.all import sniff, IP, Ether

# --- CONFIGURACIÓN DE RUTAS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FOLDER = os.path.join(BASE_DIR, "Usuarios_capturados")
if not os.path.exists(FOLDER): os.makedirs(FOLDER)

class SnifferTUI(App):
    CSS = """
    Screen { layout: horizontal; }
    #sidebar { width: 30%; border-right: tall $primary; background: $surface; }
    #main_content { width: 70%; }
    .title { text-align: center; background: $primary; color: white; text-style: bold; padding: 1; }
    #controls { height: auto; border-top: solid $primary; padding: 1; align: center middle; }
    Button { margin: 1; width: 15; }
    """

    BINDINGS = [("q", "quit", "Salir"), ("e", "export_logs", "Exportar")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label(" 📡 INTERFACES ", classes="title")
                yield ListView(id="iface_list")
                yield Label(" 🌐 DISPOSITIVOS ", classes="title")
                yield ListView(id="device_list")
            with Vertical(id="main_content"):
                yield Label(" 🛠️ CONSOLA DE AUDITORÍA ", classes="title")
                yield Log(id="event_log")
                with Horizontal(id="controls"):
                    yield Button("START", id="start", variant="success")
                    yield Button("STOP", id="stop", variant="error")
                    yield Button("EXPORTAR", id="export", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        # Renombramos la variable para evitar el choque con Textual
        self.sniffer_activo = False 
        self.selected_interface = None
        self.seen_ips = set()
        
        # Cargar interfaces
        iface_list = self.query_one("#iface_list")
        for iface in psutil.net_if_addrs().keys():
            iface_list.append(ListItem(Label(iface), id=iface))
        
        self.log_widget = self.query_one("#event_log")
        self.log_widget.write_line("[!] Selecciona una interfaz y pulsa START.")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "iface_list":
            self.selected_interface = event.item.id
            self.log_widget.write_line(f"[*] Interfaz lista: {self.selected_interface}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            if not self.selected_interface:
                self.log_widget.write_line("[X] ERROR: Selecciona una interfaz primero.")
                return
            if not self.sniffer_activo:
                self.sniffer_activo = True
                self.log_widget.write_line(f"\n[▶] ESCANEO INICIADO EN {self.selected_interface}...")
                threading.Thread(target=self.run_sniffer, daemon=True).start()
        elif event.button.id == "stop":
            self.sniffer_activo = False
            self.log_widget.write_line("[■] ESCANEO DETENIDO.")
        elif event.button.id == "export":
            self.action_export_logs()

    def run_sniffer(self):
        def packet_callback(pkt):
            if not self.sniffer_activo: return True 
            if IP in pkt:
                ip_src = pkt[IP].src
                if ip_src not in self.seen_ips:
                    self.seen_ips.add(ip_src)
                    self.call_from_thread(self.add_device, ip_src)
                    threading.Thread(target=self.scan_device, args=(ip_src,), daemon=True).start()

        sniff(iface=self.selected_interface, prn=packet_callback, store=0, stop_filter=lambda x: not self.sniffer_activo)

    def add_device(self, ip: str):
        try:
            self.query_one("#device_list").append(ListItem(Label(f"📍 {ip}")))
            self.log_widget.write_line(f"[+] Nueva IP: {ip}")
        except: pass

    def scan_device(self, ip: str):
        try:
            cmd = ["nmap", "-sV", "--top-ports", "5", ip]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.stdout:
                self.call_from_thread(self.log_widget.write_line, f"--- {ip} ---\n{res.stdout}")
        except: pass

    def action_export_logs(self):
        path = os.path.join(FOLDER, f"Export_{datetime.now().strftime('%H%M%S')}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.log_widget.lines))
        self.log_widget.write_line(f"[V] Guardado en: {path}")

if __name__ == "__main__":
    SnifferTUI().run()