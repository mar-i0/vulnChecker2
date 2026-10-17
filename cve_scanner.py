#!/usr/bin/env python3
"""
Escáner de vulnerabilidades CVE remoto
Verifica si un host es vulnerable a múltiples CVEs

Uso: python3 cve_scanner.py <IP_TARGET> [opciones]

Ejemplos:
    python3 cve_scanner.py 192.168.1.1
    python3 cve_scanner.py 192.168.1.1 -p 80
    python3 cve_scanner.py 192.168.1.1 --cve CVE-2016-8721
"""

import socket
import ssl
import sys
import os
import glob
import re
import argparse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

CVE_BASE = "/usr/src/cves"

def _year_dirs():
    """Todas las carpetas cve_checker_scripts_<año> existentes."""
    return sorted(glob.glob(os.path.join(CVE_BASE, "cve_checker_scripts_*")))

def _script_for(cve_id):
    """Localiza el _check.py de un CVE en la carpeta de su año (o en cualquiera)."""
    m = re.match(r"CVE-(\d{4})-", cve_id)
    if m:
        p = os.path.join(CVE_BASE, f"cve_checker_scripts_{m.group(1)}", f"{cve_id}_check.py")
        if os.path.exists(p):
            return p
    for d in _year_dirs():
        p = os.path.join(d, f"{cve_id}_check.py")
        if os.path.exists(p):
            return p
    return None

def get_http_banner(host, port, use_ssl=False, timeout=5):
    """Obtiene el banner de un servidor HTTP"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        url = f"{'https' if use_ssl else 'http'}://{host}:{port}/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            headers = dict(response.headers)
            server = headers.get('Server', '')
            powered = headers.get('X-Powered-By', '')
            return f"{server} {powered}".strip()
    except Exception as e:
        return str(e)

def get_tcp_banner(host, port, timeout=5):
    """Obtiene el banner de un servicio TCP genérico"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except:
            pass
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        lines = banner.split('\n')
        for line in lines:
            if line.lower().startswith('server:'):
                return line.split(':', 1)[1].strip()
        
        return banner[:200]
    except Exception as e:
        return str(e)

def detect_services(host, ports=None):
    """Detecta servicios comunes en el host"""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
    
    services = {}
    
    print(f"[*] Detectando servicios en {host}...")
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                if port in [80, 443, 8080, 8443]:
                    banner = get_http_banner(host, port, port == 443)
                else:
                    banner = get_tcp_banner(host, port)
                
                services[port] = banner
                print(f"    [+] Puerto {port}: {banner[:80]}")
        except:
            pass
    
    return services

def check_cve(host, cve_id, port=None):
    """Verifica un CVE específico"""
    cve_script = _script_for(cve_id)
    
    if not cve_script:
        return None
    
    try:
        # Ejecutar el script de verificación
        import subprocess
        result = subprocess.run(
            ['python3', cve_script, host, '-p', str(port or 80)],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout
    except Exception as e:
        return f"Error: {str(e)}"

def scan_host(host, options):
    """Escanea un host contra CVEs conocidos"""
    print(f"\n{'='*60}")
    print(f"ESCÁNER DE VULNERABILIDADES CVE")
    print(f"Objetivo: {host}")
    print(f"{'='*60}\n")
    
    services = detect_services(host, options.ports)
    
    if not services:
        print("[!] No se detectaron servicios activos")
        return
    
    print(f"\n[*] Analizando vulnerabilidades...\n")
    
    # Detectar software basado en banners
    detected_software = []
    for port, banner in services.items():
        banner_lower = banner.lower()
        
        if 'apache' in banner_lower:
            detected_software.append(('apache', port))
        elif 'nginx' in banner_lower:
            detected_software.append(('nginx', port))
        elif 'iis' in banner_lower or 'microsoft' in banner_lower:
            detected_software.append(('iis', port))
        elif 'openssh' in banner_lower or 'ssh' in banner_lower:
            detected_software.append(('ssh', port))
        elif 'mysql' in banner_lower or 'mariadb' in banner_lower:
            detected_software.append(('mysql', port))
        elif 'postgresql' in banner_lower:
            detected_software.append(('postgresql', port))
        elif 'ftp' in banner_lower:
            detected_software.append(('ftp', port))
        elif 'wordpress' in banner_lower:
            detected_software.append(('wordpress', port))
        elif 'jenkins' in banner_lower:
            detected_software.append(('jenkins', port))
    
    if detected_software:
        print("[*] Software detectado:")
        for sw, port in detected_software:
            print(f"    - {sw} (puerto {port})")
        print()
    
    # Escanear CVEs relevantes
    cve_files = []
    for _d in _year_dirs():
        cve_files.extend(glob.glob(os.path.join(_d, "*_check.py")))
    
    relevant_cves = []
    for cve_file in cve_files:
        cve_id = os.path.basename(cve_file).replace('_check.py', '')
        
        for sw, port in detected_software:
            if sw.upper() in cve_id.upper() or sw in open(cve_file).read().lower():
                relevant_cves.append((cve_id, port))
                break
    
    # Si se especificaron CVEs, usar esos
    if options.cve:
        relevant_cves = [(options.cve, options.port or 80)]
    
    if not relevant_cves:
        print("[*] No se encontraron CVEs específicos para el software detectado")
        print("[*] Mostrando algunos CVEs comunes...\n")
        relevant_cves = [
            ('CVE-2016-0003', 80),
            ('CVE-2016-0002', 80),
            ('CVE-2016-8721', 80),
        ][:3]
    
    # Ejecutar verificación de CVEs
    print("[*] Verificando CVEs relevantes:\n")
    
    for cve_id, port in relevant_cves[:options.limit]:
        print(f"--- {cve_id} ---")
        result = check_cve(host, cve_id, port)
        if result:
            lines = result.split('\n')
            for line in lines[-10:]:
                if line.strip():
                    print(f"  {line}")
        print()

def main():
    parser = argparse.ArgumentParser(
        description="Escáner de vulnerabilidades CVE remoto",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
    python3 cve_scanner.py 192.168.1.1
    python3 cve_scanner.py 192.168.1.1 -p 8080
    python3 cve_scanner.py 192.168.1.1 --cve CVE-2016-8721
    python3 cve_scanner.py 192.168.1.1 --limit 10
        """
    )
    
    parser.add_argument("target", help="Dirección IP o hostname objetivo")
    parser.add_argument("-p", "--port", type=int, help="Puerto específico a verificar")
    parser.add_argument("--ports", nargs="+", type=int, help="Puertos a escanear (default: comunes)")
    parser.add_argument("--cve", help="Verificar un CVE específico")
    parser.add_argument("--limit", type=int, default=5, help="Número de CVEs a verificar (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Salida verbosa")
    
    args = parser.parse_args()
    
    if not args.target:
        parser.print_help()
        return 1
    
    scan_host(args.target, args)
    return 0

if __name__ == "__main__":
    sys.exit(main())
