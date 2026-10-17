#!/usr/bin/env python3
"""
Reconocimiento de red y verificación de vulnerabilidades CVE
Ejecuta scripts de verificación en los hosts objetivo
"""

import socket
import ssl
import sys
import os
import subprocess
import urllib.request
import urllib.error
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGETS = [
    "192.168.1.1",
    "192.168.1.16", 
    "192.168.1.128",
    "192.168.1.132",
    "192.168.1.137",
    "192.168.1.149",
    "192.168.1.191",
    "192.168.1.194",
    "192.168.1.129"
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 27017]

SERVICE_BANNERS = {
    22: "SSH",
    21: "FTP", 
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

def get_banner(host, port, timeout=3):
    """Obtiene el banner de un servicio"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        
        if result != 0:
            sock.close()
            return None
        
        try:
            if port in [80, 443, 8080, 8443]:
                sock.close()
                return get_http_banner(host, port, port in [443, 8443])
        except:
            pass
        
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except:
            pass
            
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        if banner:
            return banner.strip()[:200]
        return None
        
    except Exception as e:
        return None

def get_http_banner(host, port, use_ssl=False):
    """Obtiene banner HTTP"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{host}:{port}/"
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0', 'Host': host})
        
        with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
            headers = dict(response.headers)
            server = headers.get('Server', '')
            powered = headers.get('X-Powered-By', '')
            return f"Server: {server} | X-Powered-By: {powered}".strip()
    except urllib.error.URLError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

def detect_services(host):
    """Detecta servicios activos en el host"""
    print(f"\n[*] Escaneando {host}...")
    
    services = []
    
    for port in COMMON_PORTS:
        banner = get_banner(host, port)
        if banner:
            service_name = SERVICE_BANNERS.get(port, f"Port-{port}")
            services.append({
                'port': port,
                'service': service_name,
                'banner': banner
            })
            print(f"    [+] {port}/tcp -> {service_name}: {banner[:80]}")
    
    return services

def identify_software(banner, port):
    """Identifica el software basado en el banner"""
    b = banner.lower()
    
    if 'apache' in b:
        return 'apache'
    elif 'nginx' in b:
        return 'nginx'
    elif 'iis' in b or 'microsoft' in b:
        return 'iis'
    elif 'openssh' in b or 'ssh' in b:
        return 'ssh'
    elif 'mysql' in b or 'mariadb' in b:
        return 'mysql'
    elif 'postgresql' in b:
        return 'postgresql'
    elif 'proftpd' in b:
        return 'proftpd'
    elif 'vsftpd' in b:
        return 'vsftpd'
    elif 'pure-ftpd' in b:
        return 'pure-ftpd'
    elif 'wordPress' in b:
        return 'wordpress'
    elif 'drupal' in b:
        return 'drupal'
    elif 'joomla' in b:
        return 'joomla'
    elif 'jenkins' in b:
        return 'jenkins'
    elif 'tomcat' in b:
        return 'tomcat'
    elif 'oracle' in b:
        return 'oracle'
    elif 'redis' in b:
        return 'redis'
    elif 'mongo' in b:
        return 'mongodb'
    elif port == 22:
        return 'ssh'
    elif port == 21:
        return 'ftp'
    elif port == 23:
        return 'telnet'
    elif port == 3389:
        return 'rdp'
    elif port == 5900:
        return 'vnc'
    
    return 'unknown'

def check_cve_for_service(year, software, target, port):
    """Busca y ejecuta scripts CVE relevantes"""
    cve_dir = f"/usr/src/cves/cve_checker_scripts_{year}"
    
    if not os.path.exists(cve_dir):
        return None
    
    cves_to_check = []
    
    for cve_file in os.listdir(cve_dir):
        if not cve_file.endswith('_check.py'):
            continue
        
        cve_id = cve_file.replace('_check.py', '')
        
        cve_path = os.path.join(cve_dir, cve_file)
        try:
            with open(cve_path, 'r') as f:
                content = f.read()
                if software in content.lower():
                    cves_to_check.append(cve_id)
        except:
            pass
        
        if len(cves_to_check) >= 3:
            break
    
    return cves_to_check

def main():
    print("=" * 70)
    print("RECONOCIMIENTO DE RED Y VERIFICACIÓN DE VULNERABILIDADES")
    print("=" * 70)
    print(f"\nObjetivos: {', '.join(TARGETS)}")
    print(f"Puertos escaneados: {len(COMMON_PORTS)}")
    
    results = {}
    
    for target in TARGETS:
        print(f"\n{'='*70}")
        print(f"ANALIZANDO: {target}")
        print(f"{'='*70}")
        
        services = detect_services(target)
        
        if not services:
            print(f"    [!] No se detectaron servicios activos")
            results[target] = {'services': [], 'vulnerabilities': []}
            continue
        
        print(f"\n[*] Identificando software y buscando vulnerabilidades...")
        
        vulnerabilities = []
        
        for svc in services:
            software = identify_software(svc['banner'], svc['port'])
            print(f"    -> {svc['service']} ({software})")
            
            import glob as _glob
            for _yd in sorted(_glob.glob("/usr/src/cves/cve_checker_scripts_*")):
                year = _yd.rsplit("_", 1)[-1]
                cves = check_cve_for_service(year, software, target, svc['port'])
                if cves:
                    for cve in cves:
                        vulnerabilities.append({
                            'cve': cve,
                            'service': svc['service'],
                            'software': software,
                            'port': svc['port']
                        })
        
        results[target] = {
            'services': services,
            'vulnerabilities': vulnerabilities
        }
        
        if vulnerabilities:
            print(f"\n[!] Posibles vulnerabilidades encontradas:")
            for v in vulnerabilities[:5]:
                print(f"    - {v['cve']} ({v['software']}, puerto {v['port']})")
    
    print(f"\n{'='*70}")
    print("RESUMEN FINAL")
    print(f"{'='*70}")
    
    for target, data in results.items():
        print(f"\n{target}:")
        if data['services']:
            print(f"  Servicios: {', '.join([s['service'] for s in data['services']])}")
        if data['vulnerabilities']:
            print(f"  Vulnerabilidades: {len(data['vulnerabilities'])} encontradas")
            for v in data['vulnerabilities'][:3]:
                print(f"    - {v['cve']}")
        else:
            print(f"  Sin vulnerabilidades detectadas (o servicios no identificados)")

if __name__ == "__main__":
    main()
