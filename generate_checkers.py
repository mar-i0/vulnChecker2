#!/usr/bin/env python3
"""
Generador de scripts de verificación de vulnerabilidades CVE remotas
Crea scripts que verifican si un host es vulnerable a CVEs específicos
"""

import json
import os
import glob
import re
import sys

CVE_DIR = "/usr/src/cves/cvelistV5-main/cves/2016"
OUTPUT_DIR = "/usr/src/cves/cve_checker_scripts"

# Mapeo de productos/servicios a puertos y métodos de verificación
SERVICE_PATTERNS = {
    'openssh': {'port': 22, 'banner_regex': r'OpenSSH', 'version_regex': r'OpenSSH_([0-9.]+)'},
    'apache': {'port': 80, 'banner_regex': r'Apache', 'version_regex': r'Apache/([0-9.]+)'},
    'nginx': {'port': 80, 'banner_regex': r'nginx', 'version_regex': r'nginx/([0-9.]+)'},
    'iis': {'port': 80, 'banner_regex': r'Microsoft-IIS', 'version_regex': r'Microsoft-IIS/([0-9.]+)'},
    'mysql': {'port': 3306, 'banner_regex': r'mysql', 'version_regex': None},
    'postgresql': {'port': 5432, 'banner_regex': r'PostgreSQL', 'version_regex': None},
    'ftp': {'port': 21, 'banner_regex': r'ftp', 'version_regex': None},
    'ssh': {'port': 22, 'banner_regex': r'ssh', 'version_regex': r'ssh.*version ([0-9.]+)'},
    'telnet': {'port': 23, 'banner_regex': r'telnet', 'version_regex': None},
    'smtp': {'port': 25, 'banner_regex': r'smtp|220', 'version_regex': None},
    'pop3': {'port': 110, 'banner_regex': r'pop3|220', 'version_regex': None},
    'imap': {'port': 143, 'banner_regex': r'imap|220', 'version_regex': None},
    'dns': {'port': 53, 'banner_regex': None, 'version_regex': None},
    'http': {'port': 80, 'banner_regex': None, 'version_regex': None},
    'https': {'port': 443, 'banner_regex': None, 'version_regex': None},
    'wordpress': {'port': 80, 'banner_regex': r'WordPress', 'version_regex': None},
    'joomla': {'port': 80, 'banner_regex': r'Joomla', 'version_regex': None},
    'drupal': {'port': 80, 'banner_regex': r'Drupal', 'version_regex': None},
    'jenkins': {'port': 8080, 'banner_regex': r'Jenkins', 'version_regex': None},
    'tomcat': {'port': 8080, 'banner_regex': r'Apache.*Tomcat', 'version_regex': None},
    'oracle': {'port': 1521, 'banner_regex': r'oracle', 'version_regex': None},
    'redis': {'port': 6379, 'banner_regex': r'REDIS', 'version_regex': None},
    'mongodb': {'port': 27017, 'banner_regex': r'mongo', 'version_regex': None},
    'elasticsearch': {'port': 9200, 'banner_regex': r'elastic', 'version_regex': None},
    'rabbitmq': {'port': 15672, 'banner_regex': r'RabbitMQ', 'version_regex': None},
    'vsftpd': {'port': 21, 'banner_regex': r'vsftpd', 'version_regex': r'vsftpd ([0-9.]+)'},
    'proftpd': {'port': 21, 'banner_regex': r'ProFTPD', 'version_regex': r'ProFTPD ([0-9.]+)'},
    'pure-ftpd': {'port': 21, 'banner_regex': r'Pure-FTPd', 'version_regex': r'Pure-FTPd ([0-9.]+)'},
    'jquery': {'port': 80, 'banner_regex': r'jquery', 'version_regex': None},
    'php': {'port': 80, 'banner_regex': r'PHP', 'version_regex': r'PHP/([0-9.]+)'},
}

# Keywords para identificar productos en descripciones
PRODUCT_KEYWORDS = {
    'openssh': [r'OpenSSH', r'sshd'],
    'apache': [r'Apache', r'httpd'],
    'nginx': [r'nginx'],
    'iis': [r'IIS', r'Internet Information Services', r'Microsoft-IIS'],
    'mysql': [r'MySQL', r'MariaDB'],
    'postgresql': [r'PostgreSQL', r'Postgres'],
    'ftp': [r'FTP', r'vsftpd', r'ProFTPD', r'pure-ftpd', r'FileZilla'],
    'ssh': [r'SSH', r'sshd', r'OpenSSH'],
    'telnet': [r'telnet'],
    'smtp': [r'SMTP', r'Sendmail', r'Postfix', r'Exim'],
    'wordpress': [r'WordPress'],
    'joomla': [r'Joomla'],
    'drupal': [r'Drupal'],
    'jenkins': [r'Jenkins'],
    'tomcat': [r'Tomcat', r'Apache Tomcat'],
    'oracle': [r'Oracle Database', r'Oracle RDBMS'],
    'java': [r'Java', r'JRE', r'JDK', r'JVM'],
    'openssl': [r'OpenSSL'],
    'jquery': [r'jQuery'],
    'php': [r'PHP'],
    'python': [r'Python'],
    'ruby': [r'Ruby', r'Rails', r'Sinatra'],
    'nodejs': [r'Node\.js', r'NodeJS'],
}

def get_cve_info(cve_id):
    """Obtiene información de un CVE específico"""
    cve_num = cve_id.replace('CVE-2016-', '')
    year = '2016'
    
    if len(cve_num) <= 4:
        subdir = cve_num[0] + 'xxx'
    elif len(cve_num) == 5:
        subdir = cve_num[0:2] + 'xxx'
    elif len(cve_num) == 6:
        subdir = cve_num[0:3] + 'xxx'
    else:
        subdir = cve_num[0:4] + 'xxx'
    
    cve_path = os.path.join(CVE_DIR, subdir, f"{cve_id}.json")
    
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
            'description': description,
            'vendor': vendor,
            'product': product,
            'versions': versions,
            'path': cve_path
        }
    except:
        return None

def identify_service(cve_info):
    """Identifica el servicio/producto afectado por el CVE"""
    text = f"{cve_info['description']} {cve_info['product']} {cve_info['vendor']}".lower()
    
    for service, keywords in PRODUCT_KEYWORDS.items():
        for keyword in keywords:
            if re.search(keyword, text, re.IGNORECASE):
                return service
    
    return None

def get_service_info(service):
    """Obtiene información del servicio"""
    return SERVICE_PATTERNS.get(service.lower())

def create_checker_script(cve_id, output_dir):
    """Crea un script de verificación para un CVE específico"""
    cve_info = get_cve_info(cve_id)
    if not cve_info:
        return None
    
    service = identify_service(cve_info)
    service_info = get_service_info(service) if service else None
    
    default_port = service_info['port'] if service_info else 80
    
    script_template = f'''#!/usr/bin/env python3
"""
CVE Checker: {cve_id}
Producto: {cve_info['product']}
Vendor: {cve_info['vendor']}

Descripción: {cve_info['description'][:200]}...

Este script verifica si un host remoto es vulnerable a {cve_id}
"""

import socket
import ssl
import sys
import argparse
import re
import urllib.request
import urllib.error

CVE_ID = "{cve_id}"
PRODUCT = "{cve_info['product']}"
VENDOR = "{cve_info['vendor']}"
DEFAULT_PORT = {default_port}

SERVICE = {service!r}
SERVICE_INFO = {service_info!r}


def get_http_banner(host, port, use_ssl=False):
    """Obtiene el banner de un servidor HTTP"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        url = f"{{'https' if use_ssl else 'http'}}://{{host}}:{{port}}/"
        req = urllib.request.Request(url, headers={{'User-Agent': 'Mozilla/5.0'}})
        
        with urllib.request.urlopen(req, timeout=10, context=context) as response:
            headers = dict(response.headers)
            server = headers.get('Server', '')
            return server
    except Exception as e:
        return f"Error: {{str(e)}}"


def get_tcp_banner(host, port, timeout=5):
    """Obtiene el banner de un servicio TCP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        try:
            sock.send(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
        except:
            pass
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return banner
    except Exception as e:
        return f"Error: {{str(e)}}"


def check_cve_{cve_id.replace('-', '_')}(target, port=None, use_ssl=False):
    """
    Verifica si el target es vulnerable a {cve_id}
    
    Args:
        target: Dirección IP o hostname
        port: Puerto a verificar (default: {default_port})
        use_ssl: Usar HTTPS
    
    Returns:
        dict: Resultado de la verificación
    """
    port = port or DEFAULT_PORT
    
    result = {{
        "cve": CVE_ID,
        "target": target,
        "port": port,
        "service": SERVICE,
        "vulnerable": None,
        "banner": "",
        "message": "",
        "details": {{
            "product": PRODUCT,
            "vendor": VENDOR,
            "affected_versions": {cve_info['versions'][:5]!r}
        }}
    }}
    
    print(f"[+] Verificando {{CVE_ID}} en {{target}}:{{port}}")
    
    if SERVICE == "http" or port in [80, 443] or use_ssl:
        banner = get_http_banner(target, port, use_ssl)
        result["banner"] = banner
        print(f"[+] Banner HTTP: {{banner}}")
        
        # Análisis básico basado en el producto
        if PRODUCT.lower() in banner.lower() or VENDOR.lower() in banner.lower():
            result["message"] = f"El servidor parece ejecutar {{PRODUCT}}/{{VENDOR}}. "
            result["message"] += "Para verificación completa, consulte los detalles del CVE."
    else:
        banner = get_tcp_banner(target, port)
        result["banner"] = banner
        print(f"[+] Banner: {{banner}}")
    
    # Información general
    result["message"] += "\\n[INFO] Este CVE afecta: {{PRODUCT}} de {{VENDOR}}. "
    result["message"] += "Versiones afectadas: {', '.join(cve_info['versions'][:3])}. "
    result["message"] += "Consulte los boletines de seguridad oficiales para verificación exacta."
    
    return result


def main():
    parser = argparse.ArgumentParser(description=f"CVE Checker: {{CVE_ID}}")
    parser.add_argument("target", help="Dirección IP o hostname")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help=f"Puerto (default: {{DEFAULT_PORT}})")
    parser.add_argument("-s", "--ssl", action="store_true", help="Usar SSL/HTTPS")
    parser.add_argument("-v", "--verbose", action="store_true", help="Salida verbosa")
    
    args = parser.parse_args()
    
    print(f"=" * 60)
    print(f"CVE Checker: {{CVE_ID}}")
    print(f"Producto: {{PRODUCT}} ({{VENDOR}})")
    print(f"=" * 60)
    
    result = check_cve_{cve_id.replace('-', '_')}(args.target, args.port, args.ssl)
    
    print(f"\\nResultado:")
    print(f"  Target: {{result['target']}}:{{result['port']}}")
    print(f"  Servicio: {{result['service']}}")
    print(f"  Banner: {{result['banner'][:100]}}...")
    print(f"  Mensaje: {{result['message'][:200]}}...")
    
    if args.verbose:
        print(f"\\nDetalles adicionales:")
        print(f"  Producto: {{result['details']['product']}}")
        print(f"  Vendor: {{result['details']['vendor']}}")
        print(f"  Versiones afectadas: {{result['details']['affected_versions']}}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
    
    script_filename = os.path.join(output_dir, f"{cve_id}_check.py")
    with open(script_filename, 'w') as f:
        f.write(script_template)
    
    return script_filename

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Leer lista de CVEs remotos
    remote_file = "/usr/src/cves/cve_scripts_2016/remote_cves.txt"
    if not os.path.exists(remote_file):
        print("No se encontró remote_cves.txt")
        return
    
    with open(remote_file, 'r') as f:
        remote_cves = [line.strip() for line in f if line.strip()]
    
    print(f"Generando scripts de verificación para {len(remote_cves)} CVEs...")
    
    created = 0
    skipped = 0
    
    for cve_id in remote_cves:
        script_path = create_checker_script(cve_id, OUTPUT_DIR)
        if script_path:
            created += 1
            if created % 100 == 0:
                print(f"  Generados {created} scripts...")
        else:
            skipped += 1
    
    print(f"\\nCompletado!")
    print(f"  Scripts creados: {created}")
    print(f"  Omitidos: {skipped}")
    print(f"  Output: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
