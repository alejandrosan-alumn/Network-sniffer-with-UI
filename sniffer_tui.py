import os
import sys
import threading
import subprocess
import socket
from datetime import datetime

# --- AUTO-INSTALACION DE DEPENDENCIAS ---
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
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS

# --- VENTANA EMERGENTE PARA DETALLES ---
class DetalleIPScreen(ModalScreen):
    def __init__(self, ip, info_nmap):
        super().__init__()
        self.ip = ip
        self.info_nmap = info_nmap

    def compose(self) -> ComposeResult:
        with Vertical(id="modal_container"):
            yield Label(f"AUDITORIA: {self.ip}", id="modal_title")
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
    CSS = """
    Screen { layout: horizontal; }
    #sidebar { width: 30%; border-right: tall $primary; background: $surface; }
    #main_content { width: 70%; }
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

    BINDINGS = [("q", "quit", "Salir"), ("e", "export", "Exportar")]

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except: return "127.0.0.1"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label(" INTERFACES ", classes="title")
                yield ListView(id="iface_list")
                yield Label(" DISPOSITIVOS (Click) ", classes="title")
                yield ListView(id="device_list")
            with Vertical(id="main_content"):
                yield Label(" IDS Y MONITOR DE ACTIVIDAD ", classes="title")
                yield RichLog(id="event_log", highlight=True, markup=True)
                with Horizontal(id="controls"):
                    yield Button("START", id="start", variant="success")
                    yield Button("STOP", id="stop", variant="error")
                    yield Button("EXPORTAR", id="export", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        self.sniffer_activo = False 
        self.seen_ips = {}
        self.active_connections = set()
        self.selected_interface = None
        self.connection_attempts = {}
        self.mi_ip = self.get_local_ip()
        self.log_widget = self.query_one("#event_log")
        
        iface_list = self.query_one("#iface_list")
        for iface in psutil.net_if_addrs().keys():
            iface_list.append(ListItem(Label(f"IFACE: {iface}"), id=iface))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "iface_list":
            self.selected_interface = event.item.id
        elif event.list_view.id == "device_list":
            target_ip = None
            for ip, data in self.seen_ips.items():
                if data["widget"] == event.item.children[0]:
                    target_ip = ip
                    break
            if target_ip:
                info = self.seen_ips[target_ip].get("nmap", "Analizando...")
                self.push_screen(DetalleIPScreen(target_ip, info))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start" and self.selected_interface:
            if not self.sniffer_activo:
                self.sniffer_activo = True
                self.log_widget.write("[bold green]INFO: MONITOR ACTIVADO[/]")
                if self.mi_ip not in self.seen_ips:
                    self.registrar_dispositivo(self.mi_ip, es_mio=True)
                threading.Thread(target=self.run_sniffer, daemon=True).start()
        elif event.button.id == "stop":
            self.sniffer_activo = False
            self.log_widget.write("[bold yellow]INFO: MONITOR DETENIDO[/]")
        elif event.button.id == "export":
            self.action_export_full_report()

    def registrar_dispositivo(self, ip, es_mio=False):
        status = "(LOCAL)" if es_mio else "(NUEVO)"
        nuevo_label = Label(f"IP: {ip} [bold yellow]{status}[/]")
        self.seen_ips[ip] = {"nmap": "Pendiente de analisis...", "widget": nuevo_label}
        
        list_view = self.query_one("#device_list")
        if threading.current_thread() is threading.main_thread():
            list_view.append(ListItem(nuevo_label))
        else:
            self.call_from_thread(list_view.append, ListItem(nuevo_label))
            
        threading.Thread(target=self.scan_ports_background, args=(ip,), daemon=True).start()

    def run_sniffer(self):
        def packet_callback(pkt):
            if not self.sniffer_activo: return True 
            if IP in pkt:
                ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
                
                if ip_src not in self.seen_ips:
                    self.registrar_dispositivo(ip_src)

                msg = None
                conn_id = tuple(sorted((ip_src, ip_dst)))

                # Conexiones TCP nuevas
                if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
                    if conn_id not in self.active_connections:
                        msg = f"[cyan]CONN:[/] {ip_src} -> {ip_dst} (Port {pkt[TCP].dport})"
                        self.active_connections.add(conn_id)

                # Consultas DNS
                elif pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                    try:
                        qname = pkt[DNS].qd.qname.decode()
                        msg = f"[magenta]DNS:[/] {ip_src} solicita {qname}"
                    except: pass

                # ICMP (Ping)
                elif pkt.haslayer(ICMP):
                    msg = f"[blue]ICMP:[/] {ip_src} -> {ip_dst}"

                # Deteccion de Escaneo (IDS)
                if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) and ip_src != self.mi_ip:
                    dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
                    if ip_src not in self.connection_attempts: self.connection_attempts[ip_src] = set()
                    self.connection_attempts[ip_src].add(dport)
                    
                    if len(self.connection_attempts[ip_src]) > 15:
                        msg = f"[bold red]ALERTA IDS: Escaneo de puertos desde {ip_src}[/]"

                if msg:
                    self.call_from_thread(self.log_widget.write, msg)

        sniff(iface=self.selected_interface, prn=packet_callback, store=0, stop_filter=lambda x: not self.sniffer_activo)

    def scan_ports_background(self, ip: str):
        try:
            puertos = "21,22,23,25,53,80,110,111,135,139,143,443,445,3389,8080"
            cmd = ["nmap", "-sV", "-O", "-p", puertos, "--open", ip]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=95)
            self.seen_ips[ip]["nmap"] = f"[bold cyan]AUDITORIA NMAP - {ip}[/]\n\n{res.stdout}"
            self.call_from_thread(self.update_ui_finished, ip)
        except Exception as e:
            self.seen_ips[ip]["nmap"] = f"Error: {e}"

    def update_ui_finished(self, ip):
        if ip in self.seen_ips:
            label = self.seen_ips[ip]["widget"]
            label.update(f"IP: {ip} [bold green](LISTO)[/]")

    def action_export_full_report(self):
        folder = "Auditorias_Red"
        if not os.path.exists(folder): os.makedirs(folder)
        filename = f"Reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path = os.path.join(folder, filename)
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"REPORTE DE AUDITORIA - {datetime.now()}\n" + "="*40 + "\n")
            for ip, data in self.seen_ips.items():
                f.write(f"\nHOST: {ip}\n{data['nmap']}\n")
        
        self.log_widget.write(f"[bold green]REPORTE GENERADO EN:[/] {path}")

if __name__ == "__main__":
    if os.name != 'nt' and os.getuid() != 0:
        print("ERROR: Ejecute con sudo.")
        sys.exit(1)
    SnifferTUI().run()