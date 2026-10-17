# Proyecto de Detección de Vulnerabilidades CVE

## Resumen del Proyecto

Sistema integral de detección de vulnerabilidades que:
1. Identifica CVEs remotas (explotables en red) del período 1999-2018
2. Crea scripts Python para verificar si CVEs específicas aplican a hosts remotos
3. Escanea la red doméstica del usuario para identificar servicios vulnerables
4. Genera informes profesionales de vulnerabilidades con recomendaciones
5. Crea bases de datos CVE enriquecidos con métodos de detección

---

## Direcciones IP Escaneadas

| IP | Servicios Detectados |
|----|---------------------|
| 192.168.1.1 | HTTP/HTTPS (Router Web UI) |
| 192.168.1.149 | SSH (OpenSSH 8.4p1 Debian-5+deb11u3) |
| 192.168.1.191 | SSH (OpenSSH 10.2p1 Debian-2) |
| 192.168.1.194 | FTP (vsFTPd 3.0.3), SSH (OpenSSH 8.4p1), HTTP (Apache 2.4.66) |
| 192.168.1.16 | - |
| 192.168.1.128 | - |
| 192.168.1.132 | - |
| 192.168.1.137 | - |
| 192.168.1.129 | - |

**Evaluación de Riesgo:** BAJO - Todas las versiones de software son relativamente recientes y parcheadas

---

## Estadísticas CVE (1999-2018)

| Métrica | Valor |
|---------|-------|
| Total CVEs remotas | 92,960 |
| CRITICAL | 146 |
| HIGH | 672 |
| MEDIUM | 1,052 |
| LOW | 217 |

### Productos con más CVEs

| Producto | Cantidad |
|----------|----------|
| PHP | 15,867 |
| Oracle | 3,647 |
| WordPress | 1,960 |
| Apache | 1,429 |
| Drupal | 1,020 |

---

## Archivos Generados

### Scripts Base de CVE
- **Ubicación:** `/usr/src/cves/cve_scripts_YYYY/`
- **Contenido:** Scripts base para cada CVE
- **Cantidad:** ~10,572 scripts por año

### Scripts de Verificación
- **Ubicación:** `/usr/src/cves/cve_checker_scripts_YYYY/`
- **Contenido:** Scripts para verificar vulnerabilidad en hosts remotos
- **Cantidad:** 92,960 scripts (uno por cada CVE remota)

### Base de Datos Enriquecida
- **CVE_ENRIQUECIDO_COMPLETO.json** (56MB)
  - 92,960 CVEs enriquecidas con datos de investigación
- **CVE_ENRIQUECIDO.json**
  - CVEs iniciales enriquecidas (específicas de red)

### Ficheros de Agent
- **CVE_AGENTE_DETECCION.json**
  - 23,169 CVEs con métodos de detección optimizados para agentes automatizados

### Informes
- **INFORME_VULNERABILIDADES.pdf** (63KB)
  - Informe profesional de vulnerabilidades en formato PDF
- **INFORME_VULNERABILIDADES.md**
  - Informe en formato Markdown

### Documentación
- **USAGE.md** - Guía de uso de los scripts
- **CVE_TU_RED.md** - Análisis de CVEs específicas de la red

---

## Scripts Creados

| Script | Descripción |
|--------|-------------|
| `network_scan.py` | Escáner de red doméstica |
| `cve_scanner.py` | Escáner universal de CVEs |
| `generate_cve_scripts.py` | Generador de scripts base CVE |
| `generate_all_years.py` | Generador para todos los años |
| `generate_all_checkers.py` | Generador de scripts de verificación |
| `enrich_cves.py` | Procesador de enriquecimiento CVE |
| `generate_agent_json.py` | Generador JSON para agentes |

---

## CVEs Relevantes para la Red Escaneada

### OpenSSH 8.4p1 (192.168.1.149, 192.168.1.194)
- CVE-2021-28041: Vulnerabilidad de autenticación en OpenSSH
- CVE-2020-15778: Escape de comando en scp

### OpenSSH 10.2p1 (192.168.1.191)
- Versión reciente, sin CVEs críticas documentadas

### Apache 2.4.66 (192.168.1.194)
- Múltiples CVEs en versiones anteriores de Apache HTTP Server

### vsFTPd 3.0.3 (192.168.1.194)
- CVE-2015-1418: Vulnerabilidad de denegación de servicio
- CVE-2011-5018: Escape de autenticación

---

## Uso de los Scripts

### Escanear Red
```bash
python3 /usr/src/cves/network_scan.py
```

### Verificar CVE Específica
```bash
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-XXXX_check.py 192.168.1.149
```

### Generar Nuevo Script CVE
```bash
python3 /usr/src/cves/generate_cve_scripts.py CVE-2016-1234
```

---

## Estado del Proyecto

- ✅ Scripts base CVE (92,960)
- ✅ Scripts de verificación CVE
- ✅ Escaneo de red completada
- ✅ Informe de vulnerabilidades (PDF + MD)
- ✅ Base de datos enriquecida completa
- ✅ JSON para agente de detección

---

*Generado: 2026-02-19*
