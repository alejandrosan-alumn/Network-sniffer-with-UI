import os
import sys
import subprocess
import platform

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def check_system_requirements():
    sistema = platform.system()
    print(f"[*] Detectado sistema: {sistema}")

    # 1. Verificar privilegios
    if sistema == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print(" [!] ERROR: Debes ejecutar la terminal como ADMINISTRADOR.")
            sys.exit(1)
    else:
        if os.getuid() != 0:
            print(" [!] ERROR: Debes ejecutar con 'sudo'.")
            sys.exit(1)

    # 2. Verificar Nmap
    try:
        subprocess.run(["nmap", "--version"], capture_output=True)
    except FileNotFoundError:
        print(f" [!] AVISO: Nmap no detectado en el PATH.")
        if sistema == "Windows":
            print("     Descárgalo en: https://nmap.org/download.html")
        else:
            print("     Instálalo con: sudo apt install nmap")

def install_dependencies():
    print("[*] Verificando librerías de Python...")
    libs = ["textual", "scapy", "psutil"]
    for lib in libs:
        try:
            __import__(lib)
        except ImportError:
            print(f" [!] Instalando {lib}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])

def launch():
    clear_screen()
    print("Iniciando Sniffer TUI...")
    try:
        from sniffer_tui import SnifferTUI
        app = SnifferTUI()
        app.run()
    except Exception as e:
        print(f" [!] Error crítico al lanzar la app: {e}")

if __name__ == "__main__":
    check_system_requirements()
    install_dependencies()
    launch()
