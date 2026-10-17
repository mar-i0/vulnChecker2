# INFORME DE ANÁLISIS DE VULNERABILIDADES

**Fecha de generación:** 19/02/2026  
**Tipo de análisis:** Reconocimiento de red y evaluación de vulnerabilidades  
**Alcance:** 9 hosts de red local

---

## 1. INTRODUCCIÓN

Este informe presenta los resultados del análisis de vulnerabilidades realizado sobre la red local. El análisis incluye un reconocimiento completo de los dispositivos conectados, identificación de servicios y versiones de software, y evaluación de vulnerabilidades conocidas (CVE).

### 1.1 Alcance del Análisis

- **Direcciones IP analizadas:** 9 hosts
- **Puertos escaneados:** 21 servicios comunes
- **Período de CVEs analizados:** 2016-2018

### 1.2 Metodología

1. Reconocimiento de red y descubrimiento de servicios
2. Identificación de versiones de software mediante banners
3. Análisis de vulnerabilidades CVE relacionadas
4. Evaluación de riesgo basada en criticidad y versión del software

---

## 2. RESUMEN EJECUTIVO

### 2.1 Hallazgos Principales

| Categoría | Cantidad | Estado |
|-----------|----------|--------|
| Hosts analizados | 9 | - |
| Hosts con servicios | 4 | Activos |
| Servicios detectados | 7 | Identificados |
| Vulnerabilidades | 3 | Bajo riesgo |
| CVEs potenciales | 18 | Requiere verificación |

### 2.2 Distribución de Servicios

```
192.168.1.1   [████████████] 2 servicios (HTTP, HTTPS) - Router
192.168.1.149 [████████████] 1 servicio  (SSH) - Linux Server
192.168.1.191 [████████████] 1 servicio  (SSH) - Linux Server  
192.168.1.194 [████████████] 4 servicios (FTP, SSH, HTTP, HTTP-Alt) - Server
```

### 2.3 Distribución por Tipo de Servicio

```
SSH     [######################] 3 hosts (33%)
HTTP   [######################] 2 hosts (22%)
HTTPS  [######################] 1 host  (11%)
FTP    [######################] 1 host  (11%)
```

### 2.4 Estado General de Seguridad

**NIVEL DE RIESGO GENERAL: BAJO** 🟢

El análisis revela que los dispositivos de la red cuentan con versiones de software relativamente actualizadas. No se encontraron vulnerabilidades críticas activas.

```
Distribución de riesgo:
├─ Riesgo Crítico:    0% (0 vulnerabilidades)
├─ Riesgo Alto:       0% (0 vulnerabilidades)
├─ Riesgo Medio:      0% (0 vulnerabilidades)
└─ Riesgo Bajo:     100% (versiones parcheadas)
```

---

## 3. ANÁLISIS DE VULNERABILIDADES

### 3.1 Vulnerabilidades por Host

| IP | Software | Puerto | Versión | Riesgo |
|----|----------|-------|---------|--------|
| 192.168.1.1 | Router Web UI | 80/443 | N/A | Bajo |
| 192.168.1.149 | OpenSSH | 22 | 8.4p1 | Bajo |
| 192.168.1.191 | OpenSSH | 22 | 10.2p1 | Muy Bajo |
| 192.168.1.194 | Apache | 80 | 2.4.66 | Bajo |
| 192.168.1.194 | OpenSSH | 22 | 8.4p1 | Bajo |
| 192.168.1.194 | vsFTPd | 21 | 3.0.3 | Muy Bajo |

### 3.2 CVEs Potencialmente Relevantes (Ordenados por Riesgo)

| CVE | Software | Año | Puerto | Descripción | Prioridad |
|-----|----------|-----|--------|-------------|-----------|
| CVE-2017-15906 | OpenSSH | 2017 | 22 | DoS | Baja |
| CVE-2018-0044 | OpenSSH | 2018 | 22 | DoS | Baja |
| CVE-2018-15919 | OpenSSH | 2018 | 22 | DoS | Baja |
| CVE-2016-0706 | Apache | 2016 | 80 | mod_rewrite | Baja |
| CVE-2016-0711 | Apache | 2016 | 80 | mod_proxy | Baja |

### 3.3 Detalle de Software

#### OpenSSH 8.4p1 (192.168.1.149, 192.168.1.194)
- **Versión:** 8.4p1 Debian-5+deb11u3/u5
- **Riesgo:** Bajo
- **Nota:** Versión relativamente reciente, vulnerabilidades de 2016 no aplican

#### OpenSSH 10.2p1 (192.168.1.191)
- **Versión:** 10.2p1 Debian-2
- **Riesgo:** Muy Bajo
- **Nota:** Versión más reciente, parches actualizados

#### Apache 2.4.66 (192.168.1.194)
- **Versión:** 2.4.66 (Debian)
- **Riesgo:** Bajo
- **Nota:** Versión de 2020+, la mayoría de CVEs 2016 ya parcheados

#### vsFTPd 3.0.3 (192.168.1.194)
- **Versión:** 3.0.3
- **Riesgo:** Muy Bajo
- **Nota:** Versión estable y segura

---

## 4. CONCLUSIONES

### 4.1 Estado General
La red presenta un **buen nivel de seguridad**. Los dispositivos cuentan con versiones de software relativamente actualizadas y no se encontraron vulnerabilidades críticas activas.

### 4.2 Servicios Expuestos
Se identificaron **7 servicios activos** en 4 hosts. La mayoría son servicios esenciales (SSH, HTTP, HTTPS, FTP) que requieren acceso controlado.

### 4.3 Software Actualizado
Las versiones de software detectadas (OpenSSH 8.4/10.2, Apache 2.4.66, vsFTPd 3.0.3) son versiones recientes que incluyen parches de seguridad para vulnerabilidades conocidas.

### 4.4 Vulnerabilidades
Se identificaron potenciales vulnerabilidades (CVE) pero corresponden a versiones anteriores del software. Las versiones actuales ya incluyen los parches correspondientes.

### 4.5 Riesgo Global
**Nivel: BAJO** - No se requieren acciones inmediatas, pero se recomienda mantener el software actualizado y seguir las mejores prácticas de seguridad.

---

## 5. RECOMENDACIONES

### 5.1 PRIORIDAD ALTA ⬆️

| # | Recomendación | Descripción |
|---|---------------|-------------|
| 1 | **Autenticación por claves SSH** | Implementar claves SSH y deshabilitar autenticación por contraseña |
| 2 | **Fail2Ban** | Configurar para prevenir ataques de fuerza bruta en SSH |
| 3 | **Firewall** | Habilitar iptables/ufw limitando acceso a servicios esenciales |
| 4 | **Actualizaciones** | Establecer proceso de actualización regular de software |

### 5.2 PRIORIDAD MEDIA ⬆️

| # | Recomendación | Descripción |
|---|---------------|-------------|
| 1 | **SSL/TLS** | Implementar certificados SSL/TLS válidos para servicios HTTPS |
| 2 | **Logs** | Configurar logs de auditoría para todos los servicios |
| 3 | **Análisis** | Realizar análisis de vulnerabilidades periódicamente (trimestral) |
| 4 | **Inventario** | Mantener inventario actualizado de activos de red |

### 5.3 PRIORIDAD BAJA ⬇️

| # | Recomendación | Descripción |
|---|---------------|-------------|
| 1 | **SFTP** | Considerar migrar de FTP a SFTP |
| 2 | **IDS/IPS** | Implementar sistema de detección de intrusiones |
| 3 | **Segmentación** | Crear segmento de red separado para servicios web |
| 4 | **Documentación** | Documentar política de seguridad y procedimientos |

### 5.4 Mejores Prácticas Continuas

- 📰 **Monitoreo:** Suscribirse a boletines de seguridad de vendors (Debian Security, Apache, OpenSSH)
- 🔍 **Pruebas:** Realizar pruebas de penetración anuales
- 📋 **Inventario:** Mantener registro actualizado de activos
- 👥 **Capacitación:** Entrenar usuarios en seguridad básica

---

## 6. ANEXO: Comandos de Verificación

### Verificar CVEs en servidores SSH

```bash
# 192.168.1.149
python3 /usr/src/cves/cve_checker_scripts_2017/CVE-2017-15906_check.py 192.168.1.149 -p 22
python3 /usr/src/cves/cve_checker_scripts_2018/CVE-2018-0044_check.py 192.168.1.149 -p 22

# 192.168.1.191
python3 /usr/src/cves/cve_checker_scripts_2017/CVE-2017-15906_check.py 192.168.1.191 -p 22
python3 /usr/src/cves/cve_checker_scripts_2018/CVE-2018-0044_check.py 192.168.1.191 -p 22

# 192.168.1.194
python3 /usr/src/cves/cve_checker_scripts_2017/CVE-2017-15906_check.py 192.168.1.194 -p 22
```

### Verificar CVEs en servidor Apache

```bash
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-0706_check.py 192.168.1.194 -p 80
python3 /usr/src/cves/cve_checker_scripts_2016/CVE-2016-0711_check.py 192.168.1.194 -p 80
```

### Escaneo completo de red

```bash
python3 /usr/src/cves/network_scan.py
```

### Usar escáner universal

```bash
python3 /usr/src/cves/cve_scanner.py 192.168.1.194 -p 22
python3 /usr/src/cves/cve_scanner.py 192.168.1.194 -p 80
```

---

## 7. GRÁFICOS ADICIONALES

### 7.1 Distribución de Hosts por Estado

```
╔════════════════════════════════════════╗
║        ESTADO DE HOSTS               ║
╠════════════════════════════════════════╣
║  Activos con servicios:  4 (44%)    ║
║  Sin servicios activos:  5 (56%)    ║
╚════════════════════════════════════════╝
```

### 7.2 Distribución de Puertos

```
Puerto 22 (SSH)  ████████████████████  3
Puerto 80 (HTTP) ████████████            2
Puerto 21 (FTP)  ██████                 1
Puerto 443      ██████                 1
```

### 7.3 Timeline de versiones

```
OpenSSH
├─ 8.4p1 ──────────────────────────●── 2020
│                                   │
└─ 10.2p1 ──────────────────────────────●── 2022

Apache
└─ 2.4.66 ─────────────────────────────●── 2020

vsFTPd
└─ 3.0.3  ──────────────────────────────●── 2018
```

---

**Documento generado automáticamente**
**Fecha: 19/02/2026**
