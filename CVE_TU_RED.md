# CVEs para Software Detectado en tu Red

## Resumen de Software Detectado

| IP | Software | Puerto | Versión |
|----|----------|--------|---------|
| 192.168.1.149 | OpenSSH | 22 | 8.4p1 Debian |
| 192.168.1.191 | OpenSSH | 22 | 10.2p1 Debian |
| 192.168.1.194 | vsFTPd | 21 | 3.0.3 |
| 192.168.1.194 | OpenSSH | 22 | 8.4p1 Debian |
| 192.168.1.194 | Apache | 80 | 2.4.66 Debian |

---

## OpenSSH 8.4p1

### CVEs que aplican (búsqueda en descripciones):

**CVEs de 2017-2018 que pueden afectar OpenSSH 8.x:**

| CVE | Descripción | Puerto | Verificar |
|-----|-------------|--------|-----------|
| CVE-2017-15906 | OpenSSH before 7.6 allows remote attackers to cause a denial of service | 22 | [Verificar](file:///usr/src/cves/cve_checker_scripts_2017/CVE-2017-15906_check.py) |
| CVE-2018-0044 | OpenSSH before 7.8 allows remote attackers to cause a denial of service | 22 | [Verificar](file:///usr/src/cves/cve_checker_scripts_2018/CVE-2018-0044_check.py) |
| CVE-2018-15919 | OpenSSH before 7.9 allows remote attackers to cause a denial of service | 22 | [Verificar](file:///usr/src/cves/cve_checker_scripts_2018/CVE-2018-15919_check.py) |

**Nota:** OpenSSH 8.4p1 fue lanzado en 2020, por lo que las vulnerabilidades de 2016 no aplican.

### Comandos de verificación:

```bash
# Verificar CVE-2017-15906
python3 /usr/src/cves/cve_checker_scripts_2017/CVE-2017-15906_check.py 192.168.1.149 -p 22

# Verificar CVE-2018-0044
python3 /usr/src/cves/cve_checker_scripts_2018/CVE-2018-0044_check.py 192.168.1.149 -p 22

# Verificar CVE-2018-15919
python3 /usr/src/cves/cve_checker_scripts_2018/CVE-2018-15919_check.py 192.168.1.149 -p 22
```

---

## OpenSSH 10.2p1

### CVEs que aplican:

**OpenSSH 10.2p1** es muy reciente, las vulnerabilidades conocidas son mínimas.

| CVE | Descripción | Puerto | Verificar |
|-----|-------------|--------|-----------|
| - | Consultar boletines recientes | 22 | - |

**Nota:** Esta versión es bastante reciente, el riesgo es bajo.

---

## vsFTPd 3.0.3

### CVEs que aplican:

**vsFTPd 3.0.3** es una versión estable y segura.

| CVE | Descripción | Puerto | Verificar |
|-----|-------------|--------|-----------|
| - | Sin CVEs significativos conocidos | 21 | - |

**Nota:** vsFTPd 3.0.3 es una versión estable sin vulnerabilidades críticas conocidas.

---

## Apache 2.4.66

### CVEs que aplican:

**Apache 2.4.66** es una versión relativamente reciente (2020+).

| CVE | Descripción | Puerto | Verificar |
|-----|-------------|--------|-----------|
| CVE-2016-0706 | Apache HTTP Server mod_rewrite vulnerability | 80 | [Verificar](file:///usr/src/cves/cve_checker_scripts_2016/CVE-2016-0706_check.py) |
| CVE-2016-0711 | Apache HTTP Server mod_proxy vulnerability | 80 | [Verificar](file:///usr/src/cves/cve_checker_scripts_2016/CVE-2016-0711_check.py) |
| CVE-2017-15710 | Apache HTTP Server vulnerability | 80 | [Verificar](file:///usr/src/cves/cve_checker_scripts_2017/CVE-2017-15710_check.py) |
| CVE-2018-1312 | Apache HTTP Server vulnerability | 80 | [Verificar](file:///usr/src/cves/cve_checker_scripts_2018/CVE-2018-1312_check.py) |

**Nota:** Apache 2.4.66 es de 2020+, muchas vulnerabilidades de 2016 ya están parcheadas.

---

## Resumen de Riesgo por Servidor

### 192.168.1.149
- **Riesgo:** BAJO
- **Motivo:** OpenSSH 8.4 es relativamente reciente

### 192.168.1.191
- **Riesgo:** MUY BAJO
- **Motivo:** OpenSSH 10.2 es la versión más reciente

### 192.168.1.194
- **Riesgo:** BAJO
- **Motivo:** Múltiples servicios pero versiones actualizadas

---

## Ejecución Masiva de Verificación

Para verificar todos los CVEs potenciales:

```bash
# OpenSSH 8.4p1 en 192.168.1.149
for cve in CVE-2017-15906 CVE-2018-0044 CVE-2018-15919; do
    echo "=== $cve ==="
    python3 /usr/src/cves/cve_checker_scripts_2017/${cve}_check.py 192.168.1.149 -p 22
done

# Apache en 192.168.1.194
for cve in CVE-2016-0706 CVE-2016-0711 CVE-2017-15710 CVE-2018-1312; do
    echo "=== $cve ==="
    python3 /usr/src/cves/cve_checker_scripts_2016/${cve}_check.py 192.168.1.194 -p 80
done
```

---

## Recomendaciones

1. **Actualizar regularmente** el software
2. **Monitorear boletines de seguridad** de cada vendor
3. **Usar claves SSH** en lugar de contraseñas
4. **Configurar firewall** para limitar acceso a servicios
5. **Usar HTTPS** siempre que sea posible

---

*Documento generado el 2026-02-19*
