#!/usr/bin/env python3
"""
Genera JSON final completo con información de detección para agente
"""

import json
import os

def generate_agent_json():
    INPUT_FILE = "/usr/src/cves/CVE_ENRIQUECIDO_COMPLETO.json"
    OUTPUT_FILE = "/usr/src/cves/CVE_AGENTE_DETECCION.json"
    
    print("Cargando datos...")
    with open(INPUT_FILE, 'r') as f:
        data = json.load(f)
    
    # Productos con métodos de detección completos
    detection_methods = {
        "openssh": {
            "name": "OpenSSH",
            "description": "Secure Shell (SSH) server",
            "cpe": "cpe:/a:openbsd:openssh",
            "puerto_default": 22,
            "detection": {
                "banner_command": "ssh -V 2>&1",
                "banner_pattern": r"OpenSSH_(\d+\.\d+)",
                "nmap_script": "ssh-version",
                "netcat": "nc -zv host 22",
                "python": "socket.connect to port 22"
            },
            "version_vulnerable": "< 7.9",
            "version_safe": ">= 7.9",
            "severity_critical": ["CVE-2016-6210", "CVE-2017-15906"],
            "references": ["https://openssh.com/security.html"]
        },
        "apache": {
            "name": "Apache HTTP Server",
            "description": "Apache web server",
            "cpe": "cpe:/a:apache:http_server",
            "puerto_default": 80,
            "detection": {
                "http_header": "Server",
                "banner_pattern": r"Apache/(\d+\.\d+)",
                "curl": "curl -I http://host/",
                "nmap_script": "http-headers",
                "python": "requests.head(url)"
            },
            "version_vulnerable": "< 2.4.29",
            "version_safe": ">= 2.4.29",
            "severity_critical": ["CVE-2017-15710"],
            "references": ["https://httpd.apache.org/security/"]
        },
        "nginx": {
            "name": "Nginx",
            "description": "Nginx web server",
            "cpe": "cpe:/a:nginx:nginx",
            "puerto_default": 80,
            "detection": {
                "http_header": "Server",
                "banner_pattern": r"nginx/(\d+\.\d+)",
                "curl": "curl -I http://host/"
            },
            "version_vulnerable": "< 1.16.0",
            "version_safe": ">= 1.16.0"
        },
        "iis": {
            "name": "Microsoft IIS",
            "description": "Internet Information Services",
            "cpe": "cpe:/a:microsoft:internet_information_server",
            "puerto_default": 80,
            "detection": {
                "http_header": "Server",
                "banner_pattern": r"Microsoft-IIS/(\d+\.\d+)"
            },
            "version_vulnerable": "< 10.0",
            "version_safe": ">= 10.0"
        },
        "mysql": {
            "name": "MySQL",
            "description": "MySQL Database Server",
            "cpe": "cpe:/a:mysql:mysql",
            "puerto_default": 3306,
            "detection": {
                "banner_pattern": r"mysql",
                "nmap_script": "mysql-info",
                "python": "pymysql.connect()"
            },
            "version_vulnerable": "< 5.7.0",
            "version_safe": ">= 5.7.0"
        },
        "postgresql": {
            "name": "PostgreSQL",
            "description": "PostgreSQL Database Server",
            "cpe": "cpe:/a:postgresql:postgresql",
            "puerto_default": 5432,
            "detection": {
                "banner_pattern": r"PostgreSQL",
                "nmap_script": "pgsql-brute"
            },
            "version_vulnerable": "< 9.6.0",
            "version_safe": ">= 9.6.0"
        },
        "vsftpd": {
            "name": "vsFTPd",
            "description": "Very Secure FTP Daemon",
            "cpe": "cpe:/a:vsftpd:vsftpd",
            "puerto_default": 21,
            "detection": {
                "banner_pattern": r"vsFTPd",
                "nmap_script": "ftp-anon"
            },
            "version_vulnerable": "< 3.0.0",
            "version_safe": ">= 3.0.0"
        },
        "wordpress": {
            "name": "WordPress",
            "description": "WordPress CMS",
            "cpe": "cpe:/a:wordpress:wordpress",
            "puerto_default": 80,
            "detection": {
                "http_header": "X-Powered-By",
                "path": "/wp-admin/",
                "meta_generator": "<meta name=\"generator\" content=\"WordPress\""
            },
            "version_vulnerable": "< 4.9.0",
            "version_safe": ">= 4.9.0"
        },
        "joomla": {
            "name": "Joomla",
            "description": "Joomla CMS",
            "cpe": "cpe:/a:joomla:joomla",
            "puerto_default": 80,
            "detection": {
                "http_header": "X-Content-Encoded-By",
                "path": "/administrator/"
            },
            "version_vulnerable": "< 3.6.0",
            "version_safe": ">= 3.6.0"
        },
        "drupal": {
            "name": "Drupal",
            "description": "Drupal CMS",
            "cpe": "cpe:/a:drupal:drupal",
            "puerto_default": 80,
            "detection": {
                "http_header": "X-Generator",
                "path": "/CHANGELOG.txt"
            },
            "version_vulnerable": "< 8.5.0",
            "version_safe": ">= 8.5.0"
        },
        "tomcat": {
            "name": "Apache Tomcat",
            "description": "Apache Tomcat Application Server",
            "cpe": "cpe:/a:apache:tomcat",
            "puerto_default": 8080,
            "detection": {
                "http_header": "Server",
                "banner_pattern": "Apache-Coyote"
            },
            "version_vulnerable": "< 8.0.31",
            "version_safe": ">= 8.0.31"
        },
        "redis": {
            "name": "Redis",
            "description": "Redis in-memory data store",
            "cpe": "cpe:/a:redis:redis",
            "puerto_default": 6379,
            "detection": {
                "banner_pattern": r"REDIS",
                "nmap_script": "redis-info"
            },
            "version_vulnerable": "< 4.0.0",
            "version_safe": ">= 4.0.0"
        },
        "mongodb": {
            "name": "MongoDB",
            "description": "MongoDB Database",
            "cpe": "cpe:/a:mongodb:mongodb",
            "puerto_default": 27017,
            "detection": {
                "banner_pattern": r"mongo",
                "nmap_script": "mongodb-info"
            },
            "version_vulnerable": "< 3.6.0",
            "version_safe": ">= 3.6.0"
        },
        "php": {
            "name": "PHP",
            "description": "PHP scripting language",
            "cpe": "cpe:/a:php:php",
            "puerto_default": 80,
            "detection": {
                "http_header": "X-Powered-By",
                "banner_pattern": r"PHP/(\d+\.\d+)"
            },
            "version_vulnerable": "< 7.3.0",
            "version_safe": ">= 7.3.0"
        },
        "openssl": {
            "name": "OpenSSL",
            "description": "OpenSSL cryptography library",
            "cpe": "cpe:/a:openssl:openssl",
            "puerto_default": 443,
            "detection": {
                "openssl_s_client": "openssl s_client -connect host:443",
                "banner_pattern": r"OpenSSL (\d+\.\d+)"
            },
            "version_vulnerable": "< 1.1.0",
            "version_safe": ">= 1.1.0"
        }
    }
    
    # Filtrar CVEs relevantes
    software_list = list(detection_methods.keys())
    relevant_cves = []
    
    for cve in data['cves']:
        if cve.get('detected_product') in software_list:
            # Añadir info de detección
            prod = cve.get('detected_product')
            if prod in detection_methods:
                cve['detection_method'] = detection_methods[prod]
            relevant_cves.append(cve)
    
    # Crear estructura optimizada para agente
    agent_data = {
        "metadata": {
            "version": "1.0",
            "fecha_generacion": data['metadata']['fecha_generacion'],
            "total_cves": len(relevant_cves),
            "descripcion": "Base de datos de vulnerabilidades CVE con metodos de deteccion"
        },
        "resumen": {
            "cves_by_product": {},
            "severity_distribution": {}
        },
        "productos": detection_methods,
        "cves": relevant_cves
    }
    
    # Calcular estadísticas
    for cve in relevant_cves:
        prod = cve.get('detected_product', 'unknown')
        agent_data['resumen']['cves_by_product'][prod] = agent_data['resumen']['cves_by_product'].get(prod, 0) + 1
        
        severity = cve.get('cvss_severity', 'UNKNOWN')
        agent_data['resumen']['severity_distribution'][severity] = agent_data['resumen']['severity_distribution'].get(severity, 0) + 1
    
    # Guardar
    print(f"Guardando archivo para agente: {OUTPUT_FILE}")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(agent_data, f, indent=2, ensure_ascii=False)
    
    print(f"¡Completado!")
    print(f"  CVEs relevantes: {len(relevant_cves)}")
    print(f"  Archivo: {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_agent_json()
