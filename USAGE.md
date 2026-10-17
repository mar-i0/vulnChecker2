# Documentación de Scripts CVE - Verificación de Vulnerabilidades

## Índice

1. [Introducción](#introducción)
2. [Estructura de Directorios](#estructura-de-directorios)
3. [Uso Básico](#uso-básico)
4. [Scripts por Año](#scripts-por-año)
5. [Ejemplos por Servicio](#ejemplos-por-servicio)

---

## Introducción

Este documento describe cómo utilizar los scripts de verificación de vulnerabilidades CVE generados para los años 1999-2018.

**Nota importante:** Estos scripts realizan verificación pasiva (recopilan información del banner/version). Para una verificación completa, consulte los boletines de seguridad oficiales del vendor.

---

## Estructura de Directorios

```
/usr/src/cves/
├── cve_scripts_YYYY/           # Scripts base CVE (definición)
│   ├── CVE-2016-XXXX.py        # Script individual
│   ├── remote_cves.txt         # Lista de CVEs remotos
│   └── unknown_cves.txt        # Lista de CVEs no determinados
│
├── cve_checker_scripts_YYYY/   # Scripts de verificación
│   ├── CVE-2016-XXXX_check.py # Script verificador
│   └── ...
│
├── cve_scanner.py              # Escáner universal
└── network_scan.py             # Reconocimiento de red
```

---

## Uso Básico

### Verificar un CVE específico

```bash
python3 /usr/src/cves/cve_checker_scripts_YYYY/CVE-AAAA-NNNNN_check.py <IP> -p <PUERTO>
```

**Parámetros:**
- `YYYY` - Año del CVE (1999-2018)
- `AAAA-NNNNN` - ID del CVE (ej: 2016-8721)
- `<IP>` - Dirección IP objetivo
- `-p <PUERTO>` - Puerto a verificar (opcional, valor por defecto según servicio)

**Opciones adicionales:**
- `-s, --ssl` - Usar SSL/HTTPS
- `-v, --verbose` - Salida verbosa

### Usar el escáner universal

```bash
python3 /usr/src/cves/cve_scanner.py <IP> -p <PUERTO>
python3 /usr/src/cves/cve_scanner.py <IP> --cve CVE-2016-8721
python3 /usr/src/cves/cve_scanner.py <IP> --limit 10
```

---

## Scripts por Año

### Resumen de CVEs Remotos por Año

| Año | CVEs Remotos | Directorio |
|-----|-------------|------------|
| 1999 | 960 | `/usr/src/cves/cve_checker_scripts_1999/` |
| 2000 | 958 | `/usr/src/cves/cve_checker_scripts_2000/` |
| 2001 | 1,232 | `/usr/src/cves/cve_checker_scripts_2001/` |
| 2002 | 2,027 | `/usr/src/cves/cve_checker_scripts_2002/` |
| 2003 | 1,241 | `/usr/src/cves/cve_checker_scripts_2003/` |
| 2004 | 2,269 | `/usr/src/cves/cve_checker_scripts_2004/` |
| 2005 | 4,051 | `/usr/src/cves/cve_checker_scripts_2005/` |
| 2006 | 6,517 | `/usr/src/cves/cve_checker_scripts_2006/` |
| 2007 | 6,014 | `/usr/src/cves/cve_checker_scripts_2007/` |
| 2008 | 6,428 | `/usr/src/cves/cve_checker_scripts_2008/` |
| 2009 | 4,585 | `/usr/src/cves/cve_checker_scripts_2009/` |
| 2010 | 4,474 | `/usr/src/cves/cve_checker_scripts_2010/` |
| 2011 | 4,193 | `/usr/src/cves/cve_checker_scripts_2011/` |
| 2012 | 4,892 | `/usr/src/cves/cve_checker_scripts_2012/` |
| 2013 | 5,482 | `/usr/src/cves/cve_checker_scripts_2013/` |
| 2014 | 6,210 | `/usr/src/cves/cve_checker_scripts_2014/` |
| 2015 | 7,021 | `/usr/src/cves/cve_checker_scripts_2015/` |
| 2016 | 7,423 | `/usr/src/cves/cve_checker_scripts_2016/` |
| 2017 | 10,367 | `/usr/src/cves/cve_checker_scripts_2017/` |
| 2018 | 6,616 | `/usr/src/cves/cve_checker_scripts_2018/` |

**Total: 92,960 scripts de verificación**

---

## Ejemplos por Servicio

### HTTP / Servidor Web (Puerto 80, 443, 8080, 8443)

```bash
# Verificar CVE para Apache
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-10708_check.py 192.168.1.1 -p 80

# Verificar CVE para nginx
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-10884_check.py 192.168.1.1 -p 80

# Verificar CVE para IIS
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-1491_check.py 192.168.1.1 -p 80

# Usar HTTPS
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-8721_check.py 192.168.1.1 -p 443 -s
```

### SSH (Puerto 22)

```bash
# Verificar CVE para OpenSSH
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-1984_check.py 192.168.1.149 -p 22

# Otro ejemplo
python3 /usr/src/cves/cve_checker_scripts_2017/CVE-2017-2648_check.py 192.168.1.191 -p 22
```

### FTP (Puerto 21)

```bash
# Verificar CVE para vsFTPd
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-1984_check.py 192.168.1.194 -p 21

# Verificar CVE para ProFTPD
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-4805_check.py 192.168.1.194 -p 21
```

### MySQL (Puerto 3306)

```bash
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-1491_check.py 192.168.1.1 -p 3306
```

### PostgreSQL (Puerto 5432)

```bash
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-1491_check.py 192.168.1.1 -p 5432
```

### Redis (Puerto 6379)

```bash
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-1491_check.py 192.168.1.1 -p 6379
```

### MongoDB (Puerto 27017)

```bash
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-1491_check.py 192.168.1.1 -p 27017
```

### RDP (Puerto 3389)

```bash
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-1491_check.py 192.168.1.1 -p 3389
```

### VNC (Puerto 5900)

```bash
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-1491_check.py 192.168.1.1 -p 5900
```

---

## Puertos Comunes y Servicios

| Puerto | Servicio | Comando de ejemplo |
|--------|----------|-------------------|
| 21 | FTP | `python3 ..._check.py <IP> -p 21` |
| 22 | SSH | `python3 ..._check.py <IP> -p 22` |
| 23 | Telnet | `python3 ..._check.py <IP> -p 23` |
| 25 | SMTP | `python3 ..._check.py <IP> -p 25` |
| 53 | DNS | `python3 ..._check.py <IP> -p 53` |
| 80 | HTTP | `python3 ..._check.py <IP> -p 80` |
| 110 | POP3 | `python3 ..._check.py <IP> -p 110` |
| 143 | IMAP | `python3 ..._check.py <IP> -p 143` |
| 443 | HTTPS | `python3 ..._check.py <IP> -p 443 -s` |
| 445 | SMB | `python3 ..._check.py <IP> -p 445` |
| 993 | IMAPS | `python3 ..._check.py <IP> -p 993 -s` |
| 995 | POP3S | `python3 ..._check.py <IP> -p 995 -s` |
| 3306 | MySQL | `python3 ..._check.py <IP> -p 3306` |
| 3389 | RDP | `python3 ..._check.py <IP> -p 3389` |
| 5432 | PostgreSQL | `python3 ..._check.py <IP> -p 5432` |
| 5900 | VNC | `python3 ..._check.py <IP> -p 5900` |
| 6379 | Redis | `python3 ..._check.py <IP> -p 6379` |
| 8080 | HTTP-Alt | `python3 ..._check.py <IP> -p 8080` |
| 8443 | HTTPS-Alt | `python3 ..._check.py <IP> -p 8443 -s` |
| 27017 | MongoDB | `python3 ..._check.py <IP> -p 27017` |

---

## Ejemplo Completo de Uso

### 1. Escanear un host específico

```bash
# Verificar todos los servicios en un host
python3 /usr/src/cves/network_scan.py

# O verificar manualmente cada puerto
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-8721_check.py 192.168.1.194 -p 80
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-8721_check.py 192.168.1.194 -p 443 -s
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-8721_check.py 192.168.1.194 -p 22
```

### 2. Buscar CVEs específicos para un servicio

```bash
# Listar todos los CVEs de Apache en 2016
ls /usr/src/cves/cve_checker_scripts_2016/ | grep -i apache

# Contar CVEs disponibles
ls /usr/src/cves/cve_checker_scripts_2016/*.py | wc -l
```

### 3. Verificar versión específica

```bash
# Si conoces la versión exacta
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-1984_check.py 192.168.1.149 -p 22 -v
```

---

## Notas Importantes

1. **Verificación Pasiva:** Los scripts recopilan información del banner/version pero no confirman vulnerabilidad.

2. **Falsos Positivos:** La coincidencia de software no garantiza vulnerabilidad.

3. **Actualizaciones:** Los CVEs más antiguos pueden no ser relevantes para versiones actuales.

4. **Permisos:** Asegúrate de tener permiso antes de escanear sistemas que no controlas.

5. **Versiones:** Las versiones modernas de software generalmente parchean vulnerabilidades antiguas.

---

## Referencia Rápida

```bash
# Verificar CVE específico
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-8721_check.py 192.168.1.1 -p 80

# Usar escáner universal
python3 /usr/src/cves/cve_scanner.py 192.168.1.1

# Escanear red completa
python3 /usr/src/cves/network_scan.py

# Puerto específico
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-XXXX_check.py <IP> -p 80

# Con SSL
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-XXXX_check.py <IP> -p 443 -s
```

---

*Documento generado automáticamente - Fecha: 2026-02-19*
