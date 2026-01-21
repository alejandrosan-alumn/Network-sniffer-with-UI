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

# --- VENTANA DE DETALLES ---
class DetalleIPScreen(ModalScreen):
    def __init__(self, ip, info_nmap, historial_eventos):
        super().__init__()
        self.ip = ip
        self.info_nmap = info_nmap
        self.historial = historial_eventos

    def compose(self) -> ComposeResult:
        with Vertical(id="modal_container"):
            yield Label(f"DETALLES DE HOST: {self.ip}", id="modal_title")
            yield RichLog(id="modal_log", markup=True, highlight=True)
            yield Button("VOLVER", variant="primary", id="close_btn")

    def on_mount(self):
        log = self.query_one("#modal_log")
        log.write("[bold cyan]--- AUDITORIA DE PUERTOS (NMAP) ---[/]")
        log.write(self.info_nmap)
        log.write("\n[bold yellow]--- LOG COMPLETO DE ACTIVIDAD ---[/]")
        if not self.historial:
            log.write("Sin actividad registrada aún.")
        for evento in self.historial:
            log.write(evento)

    def on_button_pressed(self, event: Button.Pressed) -> None:
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
        padding: 2;
    }
    #modal_title { text-style: bold; margin-bottom: 1; color: $accent; }
    ListItem { padding: 0 1; }
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
                yield Label(" DISPOSITIVOS (Click detalle) ", classes="title")
                yield ListView(id="device_list")
            with Vertical(id="main_content"):
                yield Label(" MONITOR DE RED ", classes="title")
                yield RichLog(id="event_log", highlight=True, markup=True)
                with Horizontal(id="controls"):
                    yield Button("START", id="start", variant="success")
                    yield Button("STOP", id="stop", variant="error")
                    yield Button("EXPORTAR", id="export", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        self.sniffer_activo = False 
        self.seen_ips = {} 
        self.active_logs = {} # {id_log: {contador: int, mensaje_base: str}}
        self.selected_interface = None
        self.connection_attempts = {}
        self.mi_ip = self.get_local_ip()
        self.log_widget = self.query_one("#event_log")
        
        for iface in psutil.net_if_addrs().keys():
            self.query_one("#iface_list").append(ListItem(Label(f"IFACE: {iface}"), id=iface))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "iface_list":
            self.selected_interface = event.item.id
        elif event.list_view.id == "device_list":
            target_ip = next((ip for ip, d in self.seen_ips.items() if d["widget"] == event.item.children[0]), None)
            if target_ip:
                data = self.seen_ips[target_ip]
                self.push_screen(DetalleIPScreen(target_ip, data["nmap"], data["historial"]))

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
        self.seen_ips[ip] = {"nmap": "Analizando...", "widget": nuevo_label, "historial": []}
        
        lv = self.query_one("#device_list")
        if threading.current_thread() is threading.main_thread(): lv.append(ListItem(nuevo_label))
        else: self.call_from_thread(lv.append, ListItem(nuevo_label))
            
        threading.Thread(target=self.scan_ports_background, args=(ip,), daemon=True).start()

    def update_log_colapsado(self, log_id, mensaje_base, categoria, ip_historial=None):
        """Gestiona el contador de eventos y actualiza la UI"""
        if log_id not in self.active_logs:
            self.active_logs[log_id] = 1
            full_msg = f"[{categoria}] {mensaje_base} (1 evento)"
            self.call_from_thread(self.log_widget.write, full_msg)
        else:
            self.active_logs[log_id] += 1
            count = self.active_logs[log_id]
            full_msg = f"[{categoria}] {mensaje_base} ({count} eventos registrados)"
            self.call_from_thread(self.log_widget.write, full_msg)
        
        # Guardar en el historial individual del dispositivo
        if ip_historial and ip_historial in self.seen_ips:
            hora = datetime.now().strftime("%H:%M:%S")
            self.seen_ips[ip_historial]["historial"].append(f"[{hora}] {mensaje_base}")

    def run_sniffer(self):
        def packet_callback(pkt):
            if not self.sniffer_activo or IP not in pkt: return 
            ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
            if ip_src not in self.seen_ips: self.registrar_dispositivo(ip_src)

            # --- CASO DNS ---
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                try:
                    qname = pkt[DNS].qd.qname.decode()
                    log_id = f"dns_{ip_src}_{qname}"
                    self.update_log_colapsado(log_id, f"{ip_src} consultó {qname}", "magenta", ip_src)
                except: pass

            # --- CASO CONN (TCP SYN) ---
            elif pkt.haslayer(TCP) and pkt[TCP].flags == "S":
                log_id = f"conn_{ip_src}_{ip_dst}_{pkt[TCP].dport}"
                self.update_log_colapsado(log_id, f"{ip_src} -> {ip_dst} al puerto {pkt[TCP].dport}", "cyan", ip_src)

            # --- CASO IDS (ESCANEOS) ---
            if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) and ip_src != self.mi_ip:
                dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
                if ip_src not in self.connection_attempts: self.connection_attempts[ip_src] = set()
                self.connection_attempts[ip_src].add(dport)
                
                if len(self.connection_attempts[ip_src]) > 15:
                    log_id = f"ids_{ip_src}"
                    self.update_log_colapsado(log_id, f"ALERTA IDS: Escaneo detectado desde {ip_src}", "bold red", ip_src)

        sniff(iface=self.selected_interface, prn=packet_callback, store=0, stop_filter=lambda x: not self.sniffer_activo)

    def scan_ports_background(self, ip: str):
        try:
            cmd = ["nmap", "-sV", "-p", "22,80,443,445,3389,8080", "--open", ip]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            self.seen_ips[ip]["nmap"] = res.stdout
            self.call_from_thread(self.update_ui_finished, ip)
        except: pass

    def update_ui_finished(self, ip):
        if ip in self.seen_ips:
            self.seen_ips[ip]["widget"].update(f"IP: {ip} [bold green](LISTO)[/]")

    def action_export_full_report(self):
        folder = "Auditorias_Red"
        if not os.path.exists(folder): os.makedirs(folder)
        path = os.path.join(folder, f"Auditoria_{datetime.now().strftime('%H%M%S')}.txt")
        with open(path, "w") as f:
            for ip, d in self.seen_ips.items():
                f.write(f"\nHOST: {ip}\nHistorial: {len(d['historial'])}\n{d['nmap']}\n")
        self.log_widget.write(f"REPORTE: {path}")

if __name__ == "__main__":
    if os.name != 'nt' and os.getuid() != 0:
        print("Sudo requerido."); sys.exit(1)
    SnifferTUI().run()