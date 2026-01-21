# Network Sniffer TUI

Una herramienta de auditoría de red con interfaz de terminal (TUI) desarrollada en Python. Diseñada para monitorear tráfico en tiempo real, detectar comportamientos anómalos y realizar escaneos automáticos de servicios sin saturar la pantalla.

## Características Avanzadas

* **Log Colapsado Inteligente:** Evita el ruido visual agrupando eventos repetitivos (DNS, TCP, ICMP) en una sola línea con un contador dinámico que se actualiza en tiempo real.
* **Sistema de Alertas IDS:** Identificación automática de escaneos de puertos y actividades sospechosas con alertas visuales resaltadas.
* **Historial por Dispositivo:** Al hacer clic en cualquier IP detectada, se despliega una ventana modal con el historial completo de su actividad y su auditoría de servicios técnica.
* **Escaneo Automático Nmap:** Ejecución de escaneos de servicios (-sV) en segundo plano para cada nuevo dispositivo identificado en la red.
* **Exportación de Informes:** Generación de reportes detallados en la carpeta Auditorias_Red, organizados por fecha y hora.

---

## Instalación y Uso Universal

Esta herramienta utiliza un script de gestión centralizado (main.py) que verifica requisitos, instala dependencias faltantes y lanza la aplicación automáticamente.

### Preparación en Linux
1. Requisito: Tener nmap instalado (sudo apt install nmap).
2. Ejecución:
   ```bash
   sudo python3 main.py

### Preparación en Windows
1. Requisito Nmap: Instalar Nmap y asegurarse de que esté en el PATH del sistema.
2. Requisito Npcap: Instalar Npcap marcando obligatoriamente la opción "Install Npcap in WinPcap API-compatible Mode".
3. Ejecución: Abre una terminal (CMD o PowerShell) como Administrador y ejecuta:
   ```bash
   python main.py

## Atajos de Teclado (Bindings)

La interfaz incluye un footer dinámico para facilitar la navegación:

| Tecla | Acción |
| :--- | :--- |
| **S** | **Iniciar / Detener** el monitoreo de red. |
| **E** | **Exportar** el informe actual a la carpeta `Auditorias_Red/`. |
| **Q** | **Salir** de la aplicación de forma segura. |
| **ESC** | **Cerrar** ventanas modales de detalles de IP. |

---

## Requisitos Técnicos

* **Python 3.10+**
* **Librerías principales:** `textual`, `scapy`, `psutil` (Gestionadas automáticamente por los lanzadores).
* **Controlador de Red:** Npcap (Windows) o privilegios de Root (Linux).

## Estructura del Proyecto

* `main.py`: Launcher con autodetección de dependencias y permisos.
* `sniffer_tui.py`: Código principal y lógica de la interfaz.
* `requirements.txt`: Lista de dependencias de Python.
* `Auditorias_Red/`: Carpeta autogenerada para los reportes de salida.

---
> **Aviso Legal:** Esta herramienta ha sido creada con fines de auditoría ética y aprendizaje. El uso de este software en redes sin autorización previa es responsabilidad exclusiva del usuario.