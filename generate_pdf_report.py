#!/usr/bin/env python3
"""
Generador de Informe de Vulnerabilidades en PDF
"""

from fpdf import FPDF
import os
from datetime import datetime

class PDFReport(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 15)
        self.cell(0, 10, 'Informe de Analisis de Vulnerabilidades', border=False, new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Pagina {self.page_no()}', border=False, new_x="LMARGIN", new_y="NEXT")

    def chapter_title(self, title):
        self.set_font('helvetica', 'B', 14)
        self.set_fill_color(41, 128, 185)
        self.cell(0, 10, title, border=True, new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(5)

    def chapter_body(self, body):
        self.set_font('helvetica', '', 11)
        self.multi_cell(0, 5, body)
        self.ln()

def create_vulnerability_report():
    pdf = PDFReport()
    pdf.add_page()
    
    # ============================================
    # TITULO
    # ============================================
    pdf.set_font('helvetica', 'B', 24)
    pdf.set_text_color(41, 128, 185)
    pdf.cell(0, 20, 'Informe de Analisis de Vulnerabilidades', border=False, new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.ln(5)
    
    pdf.set_font('helvetica', '', 12)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, f'Fecha de generacion: {datetime.now().strftime("%d/%m/%Y")}', border=False, align='C')
    pdf.ln(15)
    
    # ============================================
    # 1. INTRODUCCION
    # ============================================
    pdf.chapter_title('1. Introduccion')
    
    intro_text = """Este informe presenta los resultados del analisis de vulnerabilidades realizado sobre la red local.
El analisis incluye un reconocimiento completo de los dispositivos conectados, identificacion de servicios
y versiones de software, y evaluacion de vulnerabilidades conocidas (CVE).

Alcance del analisis:
- Direcciones IP analizadas: 9 hosts
- Puertos escaneados: 21 servicios comunes
- Periodo de CVEs analizados: 2016-2018

Metodologia:
1. Reconocimiento de red y descubrimiento de servicios
2. Identificacion de versiones de software mediante banners
3. Analisis de vulnerabilidades CVE relacionadas
4. Evaluacion de riesgo basada en criticidad y version del software
    
El objetivo de este informe es proporcionar una vision clara del estado de seguridad de la red
y recomendaciones para mejorar la postura de seguridad."""
    
    pdf.chapter_body(intro_text)
    
    # ============================================
    # 2. RESUMEN EJECUTIVO
    # ============================================
    pdf.chapter_title('2. Resumen Ejecutivo')
    
    pdf.set_font('helvetica', 'B', 12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 8, '2.1 Hallazgos Principales', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    
    # Tabla de hallazgos
    pdf.set_font('helvetica', '', 10)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(60, 8, 'Categoria', 1, 0, 'C', True)
    pdf.cell(40, 8, 'Cantidad', 1, 0, 'C', True)
    pdf.cell(80, 8, 'Estado', 1, 1, 'C', True)
    
    pdf.cell(60, 8, 'Hosts analizados', 1, 0, 'C')
    pdf.cell(40, 8, '9', 1, 0, 'C')
    pdf.cell(80, 8, '-', 1, 1, 'C')
    
    pdf.cell(60, 8, 'Hosts con servicios', 1, 0, 'C')
    pdf.cell(40, 8, '4', 1, 0, 'C')
    pdf.cell(80, 8, 'Activos', 1, 1, 'C')
    
    pdf.cell(60, 8, 'Servicios detectados', 1, 0, 'C')
    pdf.cell(40, 8, '7', 1, 0, 'C')
    pdf.cell(80, 8, 'Identificados', 1, 1, 'C')
    
    pdf.cell(60, 8, 'Vulnerabilidades', 1, 0, 'C')
    pdf.cell(40, 8, '3', 1, 0, 'C')
    pdf.cell(80, 8, 'Bajo riesgo', 1, 1, 'C')
    
    pdf.cell(60, 8, 'CVEs potenciales', 1, 0, 'C')
    pdf.cell(40, 8, '18', 1, 0, 'C')
    pdf.cell(80, 8, 'Requiere verificacion', 1, 1, 'C')
    
    pdf.ln(10)
    
    # 2.2 Grafico de servicios
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 8, '2.2 Distribucion de Servicios', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    
    pdf.set_font('helvetica', '', 10)
    services_text = """
Servicios detectados por host:

192.168.1.1  [====================] 2 servicios (HTTP, HTTPS)
192.168.1.149 [====================] 1 servicio  (SSH)
192.168.1.191 [====================] 1 servicio  (SSH)
192.168.1.194 [====================] 4 servicios (FTP, SSH, HTTP, HTTP-Alt)

Grafico de servicios por tipo:

SSH     [######################] 3 hosts (33%)
HTTP   [######################] 2 hosts (22%)
HTTPS  [######################] 1 host  (11%)
FTP    [######################] 1 host  (11%)
"""
    pdf.chapter_body(services_text)
    
    # 2.3 Estado de seguridad
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 8, '2.3 Estado General de Seguridad', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    
    pdf.set_font('helvetica', '', 10)
    status_text = """
Nivel de Riesgo General: BAJO

El analisis revela que los dispositivos de la red cuentan con versiones de software
relativamente actualizadas. No se encontraron vulnerabilidades criticas activas.

Distribucion de riesgo:
- Riesgo Critico:    0% (0 vulnerabilidades)
- Riesgo Alto:       0% (0 vulnerabilidades)  
- Riesgo Medio:      0% (0 vulnerabilidades)
- Riesgo Bajo:     100% (versiones parcheadas)
"""
    pdf.chapter_body(status_text)
    
    # ============================================
    # 3. VULNERABILIDADES
    # ============================================
    pdf.chapter_title('3. Analisis de Vulnerabilidades')
    
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 8, '3.1 Vulnerabilidades por Host', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    
    # Tabla de vulnerabilidades por host
    pdf.set_font('helvetica', '', 9)
    pdf.cell(40, 7, 'IP', 1, 0, 'C', True)
    pdf.cell(50, 7, 'Software', 1, 0, 'C', True)
    pdf.cell(30, 7, 'Puerto', 1, 0, 'C', True)
    pdf.cell(30, 7, 'Version', 1, 0, 'C', True)
    pdf.cell(30, 7, 'Riesgo', 1, 1, 'C', True)
    
    pdf.cell(40, 7, '192.168.1.1', 1, 0, 'C')
    pdf.cell(50, 7, 'Router Web UI', 1, 0, 'C')
    pdf.cell(30, 7, '80/443', 1, 0, 'C')
    pdf.cell(30, 7, 'N/A', 1, 0, 'C')
    pdf.cell(30, 7, 'Bajo', 1, 1, 'C')
    
    pdf.cell(40, 7, '192.168.1.149', 1, 0, 'C')
    pdf.cell(50, 7, 'OpenSSH', 1, 0, 'C')
    pdf.cell(30, 7, '22', 1, 0, 'C')
    pdf.cell(30, 7, '8.4p1', 1, 0, 'C')
    pdf.cell(30, 7, 'Bajo', 1, 1, 'C')
    
    pdf.cell(40, 7, '192.168.1.191', 1, 0, 'C')
    pdf.cell(50, 7, 'OpenSSH', 1, 0, 'C')
    pdf.cell(30, 7, '22', 1, 0, 'C')
    pdf.cell(30, 7, '10.2p1', 1, 0, 'C')
    pdf.cell(30, 7, 'Muy Bajo', 1, 1, 'C')
    
    pdf.cell(40, 7, '192.168.1.194', 1, 0, 'C')
    pdf.cell(50, 7, 'Apache', 1, 0, 'C')
    pdf.cell(30, 7, '80', 1, 0, 'C')
    pdf.cell(30, 7, '2.4.66', 1, 0, 'C')
    pdf.cell(30, 7, 'Bajo', 1, 1, 'C')
    
    pdf.cell(40, 7, '192.168.1.194', 1, 0, 'C')
    pdf.cell(50, 7, 'OpenSSH', 1, 0, 'C')
    pdf.cell(30, 7, '22', 1, 0, 'C')
    pdf.cell(30, 7, '8.4p1', 1, 0, 'C')
    pdf.cell(30, 7, 'Bajo', 1, 1, 'C')
    
    pdf.cell(40, 7, '192.168.1.194', 1, 0, 'C')
    pdf.cell(50, 7, 'vsFTPd', 1, 0, 'C')
    pdf.cell(30, 7, '21', 1, 0, 'C')
    pdf.cell(30, 7, '3.0.3', 1, 0, 'C')
    pdf.cell(30, 7, 'Muy Bajo', 1, 1, 'C')
    
    pdf.ln(10)
    
    # 3.2 CVEs potenciales
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 8, '3.2 CVEs Potencialmente Relevantes', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    
    pdf.set_font('helvetica', '', 9)
    pdf.cell(35, 7, 'CVE', 1, 0, 'C', True)
    pdf.cell(50, 7, 'Software', 1, 0, 'C', True)
    pdf.cell(25, 7, 'Año', 1, 0, 'C', True)
    pdf.cell(20, 7, 'Puerto', 1, 0, 'C', True)
    pdf.cell(50, 7, 'Descripcion', 1, 1, 'C', True)
    
    cves = [
        ('CVE-2017-15906', 'OpenSSH', '2017', '22', 'Denegacion de servicio'),
        ('CVE-2018-0044', 'OpenSSH', '2018', '22', 'Denegacion de servicio'),
        ('CVE-2018-15919', 'OpenSSH', '2018', '22', 'Denegacion de servicio'),
        ('CVE-2016-0706', 'Apache', '2016', '80', 'mod_rewrite'),
        ('CVE-2016-0711', 'Apache', '2016', '80', 'mod_proxy'),
    ]
    
    for cve, sw, año, puerto, desc in cves:
        pdf.cell(35, 7, cve, 1, 0, 'C')
        pdf.cell(50, 7, sw, 1, 0, 'C')
        pdf.cell(25, 7, año, 1, 0, 'C')
        pdf.cell(20, 7, puerto, 1, 0, 'C')
        pdf.cell(50, 7, desc[:25], 1, 1, 'C')
    
    pdf.ln(10)
    
    # ============================================
    # 4. CONCLUSIONES
    # ============================================
    pdf.chapter_title('4. Conclusiones')
    
    conclusiones = """El analisis de vulnerabilidades de la red local revela las siguientes conclusiones:

1. ESTADO GENERAL: La red presenta un buen nivel de seguridad. Los dispositivos cuentan
   con versiones de software relativamente actualizadas y no se encontraron vulnerabilidades
   criticas activas.

2. SERVICIOS EXPUESTOS: Se identificaron 7 servicios activos en 4 hosts. La mayoria son
   servicios esenciales (SSH, HTTP, HTTPS, FTP) que requieren acceso controlado.

3. SOFTWARE ACTUALIZADO: Las versiones de software detectadas (OpenSSH 8.4/10.2,
   Apache 2.4.66, vsFTPd 3.0.3) son versiones recientes que incluyen parches de
   seguridad para vulnerabilidades conocidas.

4. VULNERABILIDADES: Se identificaron potenciales vulnerabilidades (CVE) pero estas
   corresponden a versiones anteriores del software. Las versiones actuales ya incluyen
   los parches correspondientes.

5. RIESGO GLOBAL: Nivel BAJO - No se requieren acciones inmediatas, pero se
   recomienda mantener el software actualizado y seguir las mejores practicas de seguridad.
"""
    pdf.chapter_body(conclusiones)
    
    # ============================================
    # 5. RECOMENDACIONES
    # ============================================
    pdf.chapter_title('5. Recomendaciones')
    
    recomendaciones = """BASADAS EN EL ANALISIS, SE RECOMIENDA IMPLEMENTAR LAS SIGUIENTES MEDIDAS:

5.1 PRIORIDAD ALTA:
    * Implementar autenticacion basada en claves SSH (deshabilitar autenticacion por password)
    * Configurar fail2ban para prevenir ataques de fuerza bruta en SSH
    * Habilitar firewall (iptables/ufw) limitando acceso a servicios esenciales

5.2 PRIORIDAD MEDIA:
    * Actualizar regularmente el software cuando haya nuevos parches de seguridad
    * Implementar certificados SSL/TLS validos para servicios HTTPS
    * Configurar logs de auditoria para todos los servicios
    * Realizar analisis de vulnerabilidades periodicos (trimestral)

5.3 PRIORIDAD BAJA:
    * Considerar cambiar FTP por SFTP para transferencias de archivos
    * Implementar IDS/IPS para deteccion de amenazas
    * Crear segmento de red separado para servicios web
    * Documentar politica de seguridad y procedimientos de respuesta incidentes

5.4 MEJORES PRACTICAS CONTINUAS:
    * Monitorear boletines de seguridad de vendors (Debian Security, Apache, OpenSSH)
    * Realizar pruebas de penetracion anuales
    * Mantener inventario actualizado de activos de red
    * Capacitar a usuarios en seguridad informatica basica
"""
    pdf.chapter_body(recomendaciones)
    
    # ============================================
    # ANEXO
    # ============================================
    pdf.chapter_title('6. Anexo: Comandos de Verificacion')
    
    comandos = """Para verificar manualmente las vulnerabilidades, utilize los siguientes comandos:

# Verificar CVE en servidor SSH
python3 /usr/src/cves/cve_checker_scripts_2017/CVE-2017-15906_check.py 192.168.1.149 -p 22
python3 /usr/src/cves/cve_checker_scripts_2018/CVE-2018-0044_check.py 192.168.1.149 -p 22

# Verificar CVE en servidor Apache
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-0706_check.py 192.168.1.194 -p 80
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-0711_check.py 192.168.1.194 -p 80

# Escaneo completo de red
python3 /usr/src/cves/network_scan.py

# Usar escaner universal
python3 /usr/src/cves/cve_scanner.py 192.168.1.194 -p 22
"""
    pdf.chapter_body(comandos)
    
    # Guardar PDF
    output_path = '/usr/src/cves/INFORME_VULNERABILIDADES.pdf'
    pdf.output(output_path)
    print(f"Informe PDF generado: {output_path}")
    return output_path

if __name__ == "__main__":
    create_vulnerability_report()
