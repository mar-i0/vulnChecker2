#!/usr/bin/env python3
"""
Script para enriquecer todos los CVEs remotos con información de detección
Genera un JSON completo con metadatos para cada CVE
"""

import json
import os
import glob
import re
from datetime import datetime

CVE_DIR_BASE = "/usr/src/cves/cvelistV5-main/cves"
OUTPUT_FILE = "/usr/src/cves/CVE_ENRIQUECIDO_COMPLETO.json"

# Mapeo de productos a versiones afectadas y comandos de detección
PRODUCT_DATA = {
    "openssh": {
        "cves": ["CVE-2016-0777", "CVE-2016-0778", "CVE-2016-1907", "CVE-2016-1908", 
                 "CVE-2016-3115", "CVE-2016-6210", "CVE-2016-6515", "CVE-2016-8858",
                 "CVE-2016-10708", "CVE-2017-15906", "CVE-2018-0044", "CVE-2018-15919"],
        "version_vulnerable": "< 7.4",
        "version_segura": ">= 7.9",
        "detection": {
            "banner_pattern": "OpenSSH_",
            "comando": "ssh -V",
            "puerto": 22,
            "cpe": "cpe:/a:openbsd:openssh"
        }
    },
    "apache": {
        "cves": ["CVE-2016-0706", "CVE-2016-0709", "CVE-2016-0710", "CVE-2016-0711",
                 "CVE-2016-0712", "CVE-2016-0760", "CVE-2016-0782", "CVE-2016-0783",
                 "CVE-2017-15710", "CVE-2018-1312"],
        "version_vulnerable": "< 2.4.18",
        "version_segura": ">= 2.4.29",
        "detection": {
            "banner_pattern": "Apache/",
            "comando": "curl -I http://host/",
            "header": "Server",
            "puerto": 80,
            "cpe": "cpe:/a:apache:http_server"
        }
    },
    "nginx": {
        "cves": [],
        "version_vulnerable": "< 1.10.0",
        "version_segura": ">= 1.16.0",
        "detection": {
            "banner_pattern": "nginx/",
            "puerto": 80,
            "cpe": "cpe:/a:nginx:nginx"
        }
    },
    "iis": {
        "cves": [],
        "version_vulnerable": "< 10.0",
        "detection": {
            "banner_pattern": "Microsoft-IIS",
            "puerto": 80,
            "cpe": "cpe:/a:microsoft:internet_information_server"
        }
    },
    "mysql": {
        "cves": [],
        "version_vulnerable": "< 5.7.0",
        "version_segura": ">= 5.7.0",
        "detection": {
            "banner_pattern": "mysql",
            "puerto": 3306,
            "cpe": "cpe:/a:mysql:mysql"
        }
    },
    "postgresql": {
        "cves": [],
        "version_vulnerable": "< 9.6.0",
        "version_segura": ">= 9.6.0",
        "detection": {
            "banner_pattern": "PostgreSQL",
            "puerto": 5432,
            "cpe": "cpe:/a:postgresql:postgresql"
        }
    },
    "vsftpd": {
        "cves": [],
        "version_vulnerable": "< 3.0.0",
        "version_segura": ">= 3.0.0",
        "detection": {
            "banner_pattern": "vsFTPd",
            "puerto": 21,
            "cpe": "cpe:/a:vsftpd:vsftpd"
        }
    },
    "wordpress": {
        "cves": [],
        "version_vulnerable": "< 4.7.0",
        "version_segura": ">= 4.9.0",
        "detection": {
            "banner_pattern": "WordPress",
            "puerto": 80,
            "cpe": "cpe:/a:wordpress:wordpress"
        }
    },
    "joomla": {
        "cves": [],
        "version_vulnerable": "< 3.6.0",
        "version_segura": ">= 3.6.0",
        "detection": {
            "banner_pattern": "Joomla",
            "puerto": 80
        }
    },
    "drupal": {
        "cves": [],
        "version_vulnerable": "< 8.0.0",
        "version_segura": ">= 8.5.0",
        "detection": {
            "banner_pattern": "Drupal",
            "puerto": 80
        }
    },
    "jenkins": {
        "cves": [],
        "version_vulnerable": "< 2.50.0",
        "version_segura": ">= 2.50.0",
        "detection": {
            "banner_pattern": "Jenkins",
            "puerto": 8080
        }
    },
    "tomcat": {
        "cves": ["CVE-2016-0706"],
        "version_vulnerable": "< 8.0.31",
        "version_segura": ">= 8.0.31",
        "detection": {
            "banner_pattern": "Apache-Coyote",
            "puerto": 8080,
            "cpe": "cpe:/a:apache:tomcat"
        }
    },
    "oracle": {
        "cves": [],
        "version_vulnerable": "< 12c",
        "detection": {
            "banner_pattern": "oracle",
            "puerto": 1521
        }
    },
    "redis": {
        "cves": [],
        "version_vulnerable": "< 4.0.0",
        "version_segura": ">= 4.0.0",
        "detection": {
            "banner_pattern": "REDIS",
            "puerto": 6379,
            "cpe": "cpe:/a:redis:redis"
        }
    },
    "mongodb": {
        "cves": [],
        "version_vulnerable": "< 3.6.0",
        "version_segura": ">= 3.6.0",
        "detection": {
            "banner_pattern": "mongo",
            "puerto": 27017,
            "cpe": "cpe:/a:mongodb:mongodb"
        }
    }
}

def get_cve_info(year, cve_id):
    """Obtiene información de un CVE desde los archivos locales"""
    cve_num = cve_id.replace(f"CVE-{year}-", "")
    
    if len(cve_num) <= 4:
        subdir = cve_num[0] + "xxx"
    elif len(cve_num) == 5:
        subdir = cve_num[0:2] + "xxx"
    elif len(cve_num) == 6:
        subdir = cve_num[0:3] + "xxx"
    else:
        subdir = cve_num[0:4] + "xxx"
    
    cve_path = os.path.join(CVE_DIR_BASE, year, subdir, f"{cve_id}.json")
    
    if not os.path.exists(cve_path):
        return None
    
    try:
        with open(cve_path, 'r') as f:
            data = json.load(f)
        
        containers = data.get('containers', {})
        cna = containers.get('cna', {})
        
        # Extraer descripción
        descriptions = cna.get('descriptions', [])
        description = ""
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        # Extraer vendor y producto
        affected = cna.get('affected', [])
        vendor = ""
        product = ""
        versions = []
        for aff in affected:
            vendor = aff.get('vendor', '')
            product = aff.get('product', '')
            for v in aff.get('versions', []):
                versions.append(v.get('version', ''))
        
        # Extraer CVSS
        metrics = cna.get('metrics', [])
        cvss_score = None
        cvss_vector = None
        severity = None
        
        for metric in metrics:
            if 'cvssV3_1' in metric:
                cvss_data = metric['cvssV3_1']
                cvss_score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity')
                cvss_vector = cvss_data.get('vectorString')
            elif 'cvssV3_0' in metric:
                cvss_data = metric['cvssV3_0']
                cvss_score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity')
                cvss_vector = cvss_data.get('vectorString')
        
        # Detectar producto
        detected_product = None
        text_search = f"{description} {product} {vendor}".lower()
        
        for prod_name, prod_data in PRODUCT_DATA.items():
            for keyword in [prod_name.replace(' ', '').lower(), prod_name]:
                if keyword in text_search:
                    detected_product = prod_name
                    break
            if detected_product:
                break
        
        return {
            'cve_id': cve_id,
            'year': year,
            'description': description[:500],
            'vendor': vendor,
            'product': product,
            'versions_affected': versions[:10],
            'cvss_score': cvss_score,
            'cvss_severity': severity,
            'cvss_vector': cvss_vector,
            'detected_product': detected_product,
            'state': data.get('cveMetadata', {}).get('state', 'UNKNOWN')
        }
        
    except Exception as e:
        return None

def identify_product_from_cve(cve_id, description=""):
    """Identifica el producto afectado por el CVE"""
    text = description.lower()
    
    product_keywords = {
        'openssh': ['openssh', 'sshd', 'ssh'],
        'apache': ['apache', 'httpd'],
        'nginx': ['nginx'],
        'iis': ['iis', 'microsoft-iis', 'internet information services'],
        'mysql': ['mysql', 'mariadb'],
        'postgresql': ['postgresql', 'postgres'],
        'vsftpd': ['vsftpd', 'vsftp'],
        'proftpd': ['proftpd'],
        'wordpress': ['wordpress'],
        'joomla': ['joomla'],
        'drupal': ['drupal'],
        'jenkins': ['jenkins'],
        'tomcat': ['tomcat', 'apache tomcat'],
        'oracle': ['oracle', 'oracle database'],
        'redis': ['redis'],
        'mongodb': ['mongodb', 'mongo'],
        'jquery': ['jquery'],
        'php': ['php'],
        'openssl': ['openssl']
    }
    
    for product, keywords in product_keywords.items():
        for keyword in keywords:
            if keyword in text:
                return product
    
    return 'unknown'

def process_all_cves():
    """Procesa todos los CVEs remotos"""
    
    all_remote_cves = []
    year_stats = {}
    
    print("Procesando CVEs remotos de todos los años...")
    
    for year in range(1999, 2019):
        remote_file = f"/usr/src/cves/cve_scripts_{year}/remote_cves.txt"
        
        if not os.path.exists(remote_file):
            continue
        
        with open(remote_file, 'r') as f:
            cves = [line.strip() for line in f if line.strip()]
        
        year_stats[year] = len(cves)
        
        print(f"  {year}: {len(cves)} CVEs...")
        
        for cve_id in cves:
            cve_info = get_cve_info(str(year), cve_id)
            
            if cve_info:
                # Identificar producto
                if not cve_info.get('detected_product'):
                    cve_info['detected_product'] = identify_product_from_cve(
                        cve_id, 
                        cve_info.get('description', '')
                    )
                
                # Añadir información de detección
                product = cve_info.get('detected_product', 'unknown')
                if product in PRODUCT_DATA:
                    cve_info['detection'] = PRODUCT_DATA[product].get('detection', {})
                    cve_info['version_vulnerable'] = PRODUCT_DATA[product].get('version_vulnerable', 'unknown')
                    cve_info['version_segura'] = PRODUCT_DATA[product].get('version_segura', 'unknown')
                
                all_remote_cves.append(cve_info)
    
    return all_remote_cves, year_stats

def main():
    print("=" * 60)
    print("ENRIQUECIMIENTO DE CVEs REMOTOS")
    print("=" * 60)
    
    # Procesar todos los CVEs
    cves_data, year_stats = process_all_cves()
    
    # Calcular estadísticas
    total_cves = len(cves_data)
    products_count = {}
    severity_count = {}
    
    for cve in cves_data:
        product = cve.get('detected_product', 'unknown')
        products_count[product] = products_count.get(product, 0) + 1
        
        severity = cve.get('cvss_severity', 'UNKNOWN')
        severity_count[severity] = severity_count.get(severity, 0) + 1
    
    # Crear estructura JSON final
    output_data = {
        "metadata": {
            "fecha_generacion": datetime.now().isoformat(),
            "total_cves": total_cves,
            "años_cubiertos": list(year_stats.keys()),
            "year_stats": year_stats
        },
        "resumen": {
            "total_cves": total_cves,
            "cves_por_producto": products_count,
            "cvs_por_severidad": severity_count
        },
        "productos_soportados": {
            prod: {
                "version_vulnerable": data.get("version_vulnerable"),
                "version_segura": data.get("version_segura"),
                "detection": data.get("detection")
            }
            for prod, data in PRODUCT_DATA.items()
        },
        "cves": cves_data
    }
    
    # Guardar JSON
    print(f"\nGuardando JSON enriquecido...")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n¡Completado!")
    print(f"  Total CVEs procesados: {total_cves}")
    print(f"  Archivo: {OUTPUT_FILE}")
    print(f"\nEstadísticas:")
    for year, count in sorted(year_stats.items()):
        print(f"  {year}: {count} CVEs")
    print(f"\nProductos encontrados:")
    for product, count in sorted(products_count.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {product}: {count}")

if __name__ == "__main__":
    main()
