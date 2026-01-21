# Network Sniffer TUI

Herramienta de auditoría de red con interfaz de terminal (TUI) desarrollada en Python. Permite identificar dispositivos en la red local, capturar tráfico en tiempo real y realizar escaneos automáticos de servicios mediante Nmap.

## Características
* **Selección de Interfaz:** Listado automático de interfaces de red activas.
* **Detección de Dispositivos:** Identifica nuevas IPs en la red mediante la captura de paquetes.
* **Escaneo Automático:** Integración con Nmap para auditar los servicios de los dispositivos detectados.
* **Interfaz Moderna:** Construida con `Textual` para una navegación fluida en la terminal.
* **Exportación:** Guarda los hallazgos de la sesión en archivos de texto.

## Requisitos del Sistema
Para que la herramienta funcione correctamente, necesitas:
Aconsejable usar entorno virtual de Python3 para usarlo
1. **Nmap instalado:** 
```bash
sudo apt install nmap  # Debian/Ubuntu

