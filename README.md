# Network Sniffer TUI

Herramienta profesional de auditoria de red con interfaz de terminal (TUI). Diseñada para el monitoreo selectivo y la intercepción manual de trafico local mediante tecnicas MitM de alto rendimiento.

## Caracteristicas Avanzadas

* Intercepcion Manual Selectiva: El usuario fija el objetivo con un clic, iniciando el envenenamiento ARP de forma dirigida.
* Optimizacion Automatica: El lanzador activa el IP Forwarding del Kernel (en Linux) para garantizar una navegacion fluida en el dispositivo auditado.
* Log Inteligente: Agrupacion de eventos (DNS, TCP, ICMP) para evitar el lag visual y facilitar el analisis.
* Autodescubrimiento de Gateway: Identificacion automatica de la ruta de salida a internet para el ataque Man-in-the-Middle.
* Restauracion de Red: Al detener la auditoria o cambiar de objetivo, la herramienta envia paquetes ARP legitimos para devolver la estabilidad a los dispositivos.

---

## Instalacion y Requisitos

### Linux (Parrot, Kali, Ubuntu)
1. Requisito: Instalacion de Nmap (sudo apt install nmap).
2. Ejecucion: sudo python3 main.py (El script activara automaticamente el ip_forward).

### Windows
1. Requisito: Nmap configurado en el PATH y Npcap en modo compatibilidad WinPcap.
2. Ejecucion: Abrir terminal como Administrador y lanzar python main.py.

---

## Detalles del Analisis

* Man-in-the-Middle: Posicionamiento entre el Router y el Objetivo para visualizar dominios visitados (DNS) a pesar del cifrado HTTPS.
* Auditoria Nmap: Obtencion de puertos, servicios y versiones del sistema operativo del host seleccionado.
* Rendimiento: Uso de hilos (threading) independientes para la interfaz, el sniffer y el ataque ARP.

---

## Atajos de Teclado

| Tecla | Accion |
| :--- | :--- |
| S | Iniciar / Detener el Sniffer y la Intercepcion |
| E | Exportar el informe de auditoria actual |
| Q | Salir de la aplicacion de forma segura |
| ESC | Cerrar ventanas modales o liberar objetivos |

---

Aviso Legal: Herramienta de uso educativo y profesional. El uso de estas tecnicas en redes ajenas sin autorizacion es ilegal.