# vulnChecker2 🔍

> Escáner de vulnerabilidades CVE **rápido y fiable**: detecta servicio + versión
> con nmap y los cruza contra un índice de **309.826 CVEs (1999–2026)** comparando
> rangos de versión reales. Salida estilo sqlmap.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![CVE Database](https://img.shields.io/badge/CVE-1999--2026-red.svg)](https://cve.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## ✨ Qué cambia respecto a vulnChecker v1

La v1 generaba un script por CVE (220k ficheros) y emparejaba por *substring* del
banner, sin comparar versión: lento (leía 220k ficheros por escaneo) y con muchos
falsos positivos. La **v2** sustituye ese motor por dos piezas:

| | v1 | **v2** |
|---|---|---|
| Fuente de match | 220k scripts `_check.py` | 1 índice SQLite (`cve_index.sqlite`) |
| Fingerprint | banner + substring | **nmap `-sV` + CPE** (fallback a sockets) |
| Decisión | "la palabra aparece" | **versión detectada ∈ rango afectado** (`packaging`) |
| Ranking | — | por **CVSS** (CNA + ADP/CISA) |
| Velocidad | 220k lecturas/escaneo | 1 consulta indexada (ms) |

---

## 🚀 Motor v2 — uso rápido

### 1) Construir el índice (una vez)

Necesita la base oficial de CVE descomprimida en `cvelistV5-main/cves/`
(fuente: <https://github.com/CVEProject/cvelistV5>).

```bash
python3 build_index.py --src cvelistV5-main/cves --db cve_index.sqlite
# -> 309.826 CVEs, 866.373 filas, ~430 MB
```

### 2) Escanear

```bash
# Un host
python3 vulnscan.py 192.168.1.137

# Una subred entera
python3 vulnscan.py 192.168.1.0/24

# Solo lo grave, mostrando también coincidencias sin versión
python3 vulnscan.py 10.0.0.5 --min-cvss 7 --show-potential

# Sin nmap (solo sockets) o salida JSON para integrar
python3 vulnscan.py host --no-nmap
python3 vulnscan.py host --json > salida.json
```

### Ejemplo de salida

```
        _       _        ___ _           _
 __   _| |_   _| |_ __  / __\ |__   ___ | | _____ _ __
 \ \ / / | | | | | '_ \/ /  | '_ \ / _ \| |/ / _ \ '__|
  \ V /| | |_| | | | | / /___| | | |  __/|   <  __/ |
   \_/ |_|\__,_|_|_| |_\____/|_| |_|\___|_|\_\___|_|
   v2.0  ·  motor CVE 1999-2026  ·  detección pasiva + versión

[20:00:49] [INFO] host 192.168.1.137 responde con 5 servicio(s) abierto(s)
[20:00:49] [INFO]   192.168.1.137:22 ejecuta 'OpenSSH 8.4p1 Debian 5+deb11u5'
[20:00:49] [WARNING]   3 CVE con la versión en rango (confirmados):
         4.3 MEDIUM   CVE-2025-32728 [net]  In sshd in OpenSSH before 10.0, ...
         3.6 LOW      CVE-2025-61984 [net]  ssh in OpenSSH before 10.1 ...
[20:00:49] [WARNING] 3 vulnerabilidad(es) confirmada(s) en 1 host(s) — 0 crítica(s)
```

`INFO` en verde, `WARNING` en amarillo, `CRITICAL/ERROR` en rojo; severidad de cada
CVE coloreada. El color se apaga solo si no hay TTY, con `--no-color` o `NO_COLOR`;
`--color` lo fuerza (p.ej. para `| less -R`).

### Opciones

```
--db FICHERO        Índice SQLite (def. /usr/src/cves/cve_index.sqlite)
--ports 22,80,443   Puertos a escanear (def. lista de comunes)
--min-cvss N        Filtrar por CVSS mínimo
--top N             Máx. CVEs por servicio (def. 15)
--show-potential    Mostrar coincidencias de producto sin versión detectada
--no-nmap           No usar nmap (solo sondeo TCP propio)
--color / --no-color  Forzar / desactivar color
--json              Salida JSON
```

---

## 📦 Requisitos

```bash
pip install packaging          # comparación de versiones
sudo apt install nmap          # fingerprint de versión (recomendado; hay fallback)
```

Python 3.8+. `sqlite3` va en la stdlib.

---

## 🗂️ Motor v1 (legacy, aún presente)

Se conservan los scripts por año y los escáneres originales, ya **parcheados para
recorrer todos los años 1999–2026** (antes solo miraban 2016–2018):

```bash
python3 cve_scanner.py 192.168.1.100 --cve CVE-2021-41773
python3 network_scan.py
```

Cobertura de los checkers generados (`cve_checker_scripts_<año>/`):

| Rango | Scripts `_check.py` |
|-------|---------------------|
| 1999–2018 | 92.960 |
| 2019–2026 | 127.208 |
| **TOTAL** | **220.168** |

Regenerables con `generate_all_years.py` + `generate_all_checkers.py`.

---

## ⚠️ Uso responsable

- Solo sobre sistemas propios o con **autorización explícita**. El usuario asume
  toda la responsabilidad.
- Detección **pasiva**: identifica versión y cruza con CVE; **no explota** nada.
- Puede haber falsos positivos/negativos según la calidad del banner y de los datos
  del CVE. Los resultados `CONFIRMED` exigen que la versión caiga en el rango afectado.

---

## 📝 Licencia

MIT — ver [LICENSE](LICENSE).

## 👤 Autor

**mar-i0** — <https://github.com/mar-i0>
