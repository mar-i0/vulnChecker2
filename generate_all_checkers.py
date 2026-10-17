#!/usr/bin/env python3
"""
Generador de scripts de verificación para todos los CVEs remotos (1999-2018)
"""

import json
import os
import glob
import re

CVE_DIR_BASE = "/usr/src/cves/cvelistV5-main/cves"
OUTPUT_DIR_BASE = "/usr/src/cves"

SERVICE_PATTERNS = {
    'openssh': {'port': 22, 'banner_regex': r'OpenSSH'},
    'apache': {'port': 80, 'banner_regex': r'Apache'},
    'nginx': {'port': 80, 'banner_regex': r'nginx'},
    'iis': {'port': 80, 'banner_regex': r'Microsoft-IIS'},
    'mysql': {'port': 3306, 'banner_regex': r'mysql'},
    'postgresql': {'port': 5432, 'banner_regex': r'PostgreSQL'},
    'ftp': {'port': 21, 'banner_regex': r'ftp'},
    'ssh': {'port': 22, 'banner_regex': r'ssh'},
    'telnet': {'port': 23, 'banner_regex': r'telnet'},
    'smtp': {'port': 25, 'banner_regex': r'smtp'},
    'wordpress': {'port': 80, 'banner_regex': r'WordPress'},
    'joomla': {'port': 80, 'banner_regex': r'Joomla'},
    'drupal': {'port': 80, 'banner_regex': r'Drupal'},
    'jenkins': {'port': 8080, 'banner_regex': r'Jenkins'},
    'tomcat': {'port': 8080, 'banner_regex': r'Tomcat'},
    'oracle': {'port': 1521, 'banner_regex': r'oracle'},
    'redis': {'port': 6379, 'banner_regex': r'REDIS'},
    'mongodb': {'port': 27017, 'banner_regex': r'mongo'},
}

PRODUCT_KEYWORDS = {
    'openssh': [r'OpenSSH', r'sshd'],
    'apache': [r'Apache', r'httpd'],
    'nginx': [r'nginx'],
    'iis': [r'IIS', r'Internet Information Services'],
    'mysql': [r'MySQL', r'MariaDB'],
    'postgresql': [r'PostgreSQL'],
    'ftp': [r'FTP', r'vsftpd', r'ProFTPD', r'pure-ftpd'],
    'ssh': [r'SSH', r'sshd'],
    'telnet': [r'telnet'],
    'smtp': [r'SMTP', r'Sendmail', r'Postfix'],
    'wordpress': [r'WordPress'],
    'joomla': [r'Joomla'],
    'drupal': [r'Drupal'],
    'jenkins': [r'Jenkins'],
    'tomcat': [r'Tomcat'],
    'oracle': [r'Oracle'],
    'java': [r'Java', r'JRE', r'JDK'],
    'openssl': [r'OpenSSL'],
    'php': [r'PHP'],
    'jquery': [r'jQuery'],
}

def get_cve_info(year, cve_id):
    """Obtiene información de un CVE"""
    cve_num = cve_id.replace(f'CVE-{year}-', '')
    
    if len(cve_num) <= 4:
        subdir = cve_num[0] + 'xxx'
    elif len(cve_num) == 5:
        subdir = cve_num[0:2] + 'xxx'
    elif len(cve_num) == 6:
        subdir = cve_num[0:3] + 'xxx'
    else:
        subdir = cve_num[0:4] + 'xxx'
    
    cve_path = os.path.join(CVE_DIR_BASE, year, subdir, f"{cve_id}.json")
    
    if not os.path.exists(cve_path):
        return None
    
    try:
        with open(cve_path, 'r') as f:
            data = json.load(f)
        
        containers = data.get('containers', {})
        cna = containers.get('cna', {})
        
        descriptions = cna.get('descriptions', [])
        description = ""
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        affected = cna.get('affected', [])
        versions = []
        vendor = ""
        product = ""
        for aff in affected:
            vendor = aff.get('vendor', '')
            product = aff.get('product', '')
            for v in aff.get('versions', []):
                versions.append(v.get('version', ''))
        
        return {
            'id': cve_id,
            'description': description[:300],
            'vendor': vendor,
            'product': product,
            'versions': versions[:5]
        }
    except:
        return None

def identify_service(cve_info):
    """Identifica el servicio afectado"""
    if not cve_info:
        return None
    text = f"{cve_info.get('description', '')} {cve_info.get('product', '')} {cve_info.get('vendor', '')}".lower()
    
    for service, keywords in PRODUCT_KEYWORDS.items():
        for keyword in keywords:
            if re.search(keyword, text, re.IGNORECASE):
                return service
    return None

def get_service_port(service):
    """Obtiene el puerto por defecto del servicio"""
    return SERVICE_PATTERNS.get(service.lower(), {}).get('port', 80)

def create_checker_script(year, cve_id, output_dir):
    """Crea un script de verificación"""
    cve_info = get_cve_info(year, cve_id)
    if not cve_info:
        return None
    
    service = identify_service(cve_info)
    default_port = get_service_port(service) if service else 80
    
    script = f'''#!/usr/bin/env python3
"""
CVE Checker: {cve_id}
Producto: {cve_info['product']}
Vendor: {cve_info['vendor']}
Descripción: {cve_info['description'][:150]}...
"""

import socket
import ssl
import sys
import argparse
import urllib.request

CVE_ID = "{cve_id}"
PRODUCT = "{cve_info['product']}"
VENDOR = "{cve_info['vendor']}"
DEFAULT_PORT = {default_port}
SERVICE = {service!r}

def get_banner(host, port, use_ssl=False):
    try:
        if port in [80, 443, 8080, 8443]:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            url = f"{{'https' if use_ssl else 'http'}}://{{host}}:{{port}}/"
            req = urllib.request.Request(url, headers={{'User-Agent': 'Mozilla/5.0'}})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                return r.headers.get('Server', 'Unknown')
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner[:200]
    except Exception as e:
        return f"Error: {{str(e)}}"

def check_vulnerability(target, port=None):
    port = port or DEFAULT_PORT
    banner = get_banner(target, port, port == 443)
    print(f"[+] Target: {{target}}:{{port}}")
    print(f"[+] Banner: {{banner}}")
    print(f"[INFO] Producto: {{PRODUCT}} ({{VENDOR}})")
    print(f"[INFO] Para verificar vulnerabilidad, consulte los boletines de seguridad oficiales")
    return {{"vulnerable": None, "banner": banner}}

def main():
    parser = argparse.ArgumentParser(description=f"CVE Checker: {{CVE_ID}}")
    parser.add_argument("target", help="IP o hostname")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="Puerto")
    parser.add_argument("-s", "--ssl", action="store_true", help="Usar SSL")
    args = parser.parse_args()
    print(f"=== {{CVE_ID}} Checker ===")
    check_vulnerability(args.target, args.port)

if __name__ == "__main__":
    sys.exit(main())
'''
    
    script_path = os.path.join(output_dir, f"{cve_id}_check.py")
    with open(script_path, 'w') as f:
        f.write(script)
    return script_path

def process_year(year):
    """Procesa un año específico"""
    remote_file = f"/usr/src/cves/cve_scripts_{year}/remote_cves.txt"
    if not os.path.exists(remote_file):
        print(f"  [!] No existe {remote_file}")
        return 0
    
    with open(remote_file, 'r') as f:
        cves = [line.strip() for line in f if line.strip()]
    
    output_dir = f"/usr/src/cves/cve_checker_scripts_{year}"
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"  Generando {len(cves)} scripts para {year}...")
    
    created = 0
    for cve_id in cves:
        if create_checker_script(year, cve_id, output_dir):
            created += 1
        if created % 500 == 0:
            print(f"    Progreso: {created}/{len(cves)}")
    
    print(f"  ✓ {created} scripts creados en {output_dir}")
    return created

def main():
    years = [str(y) for y in range(1999, 2019)]
    
    print("=" * 60)
    print("GENERADOR DE SCRIPTS DE VERIFICACIÓN CVE")
    print("=" * 60)
    
    total = 0
    for year in years:
        print(f"\n[{year}]")
        count = process_year(year)
        total += count
    
    print(f"\n{'='*60}")
    print(f"COMPLETADO: {total} scripts de verificación creados")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
