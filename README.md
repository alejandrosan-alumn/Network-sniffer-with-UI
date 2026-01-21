# Network Sniffer TUI

Una herramienta de auditoría de red con interfaz de terminal (TUI) desarrollada en Python. Diseñada para monitorear tráfico en tiempo real, detectar comportamientos anómalos y realizar escaneos automáticos de servicios sin saturar la pantalla.

## Características Avanzadas

* **Log Colapsado:** Evita el ruido visual agrupando eventos repetitivos (DNS, Conexiones TCP, ICMP) en una sola línea con contador de eventos en tiempo real.
* **Sistema de Alertas IDS:** Identificación automática de escaneos de puertos con alertas visuales resaltadas.
* **Historial por Dispositivo:** Al hacer clic en cualquier IP detectada, aparecerá una nueva ventana con información completa de su actividad y su auditoría de servicios.
* **Escaneo Automático Nmap:** Ejecución de escaneos de servicios (`-sV`) en segundo plano para cada nuevo dispositivo identificado.
* **Exportación de Informes:** Generación de reportes detallados en la carpeta `Auditorias_Red/`, incluyendo un resumen de hosts y el detalle de cada escaneo.

## Requisitos del Sistema

Para que la herramienta funcione con todas sus capacidades, necesitas:

1.  **Nmap instalado:**
    ```bash
    sudo apt install nmap  # Debian/Ubuntu/Parrot
    ```
2.  **Permisos de Superusuario:** La captura de paquetes (Scapy) requiere privilegios de `root` o `sudo`.
3.  **Python 3.10+** (Aconsejable usar entorno virtual).

## Instalación y Uso

1. **Clonar el repositorio:**
   ```bash
   git clone <tu-url-de-repo>
   cd sniffer_UI