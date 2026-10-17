#!/usr/bin/env python3
"""
vulnscan.py — Escáner de vulnerabilidades rápido y fiable.

A diferencia del motor antiguo (lee 220k scripts y hace match por substring),
este:
  1. Detecta servicio + VERSIÓN de cada puerto una sola vez (nmap -sV, con
     fallback a banner por sockets).
  2. Consulta el índice SQLite (cve_index.sqlite) y compara la versión contra
     los RANGOS afectados reales (packaging.version).
  3. Ordena por CVSS y marca confianza (CONFIRMED si la versión cae en rango).

Uso:
    python3 vulnscan.py 192.168.1.0/24
    python3 vulnscan.py 10.0.0.5 --min-cvss 7 --show-potential
    python3 vulnscan.py host --no-nmap --json
"""
import os, sys, socket, argparse, sqlite3, subprocess, ipaddress, re, json, shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

try:
    from packaging.version import parse as vparse, InvalidVersion
except Exception:
    vparse = None

VERSION = "2.0"
CVE_RANGE = "1999-2026"

# ---------- presentación estilo sqlmap ----------
class C:
    """Códigos ANSI; vacíos si el color está desactivado."""
    enabled = True
    def __getattr__(self, name):
        codes = dict(reset="0", bold="1", dim="2", red="31", green="32",
                     yellow="33", blue="34", magenta="35", cyan="36",
                     white="37", bred="91", bgreen="92", byellow="93")
        return f"\033[{codes[name]}m" if C.enabled and name in codes else ""
c = C()

def enable_color(flag):
    C.enabled = bool(flag)

def banner():
    b = rf"""{c.bred}{c.bold}
        _       _        ___ _           _
 __   _| |_   _| |_ __  / __\ |__   ___ | | _____ _ __
 \ \ / / | | | | | '_ \/ /  | '_ \ / _ \| |/ / _ \ '__|
  \ V /| | |_| | | | | / /___| | | |  __/|   <  __/ |
   \_/ |_|\__,_|_|_| |_\____/|_| |_|\___|_|\_\___|_|{c.reset}
   {c.dim}v{VERSION}  ·  motor CVE {CVE_RANGE}  ·  detección pasiva + versión{c.reset}
"""
    print(b)
    print(f"{c.dim} [!] uso exclusivo para pruebas autorizadas sobre sistemas propios "
          f"o con permiso explícito. El usuario asume toda la responsabilidad.{c.reset}\n")

def ts():
    import datetime
    return datetime.datetime.now().strftime("%H:%M:%S")

_LEVELCLR = {"INFO": "green", "WARNING": "byellow", "ERROR": "bred",
             "CRITICAL": "bred", "SUCCESS": "bgreen", "DEBUG": "dim"}
def log(level, msg):
    clr = getattr(c, _LEVELCLR.get(level, "white"))
    print(f"{c.dim}[{ts()}]{c.reset} [{clr}{c.bold}{level}{c.reset}] {msg}",
          flush=True)

def sev_color(sev):
    return {"CRITICAL": c.bred + c.bold, "HIGH": c.red, "MEDIUM": c.byellow,
            "LOW": c.cyan}.get(sev, c.dim)

def render_host(ip, host_out, idx, total, show_potential):
    """Imprime los servicios y CVEs de UN host (en cuanto termina). Devuelve (nvulns, ncrit)."""
    log("INFO", f"[{idx}/{total}] {c.bold}{ip}{c.reset}: {len(host_out)} servicio(s) abierto(s)")
    nv = nc = 0
    for entry in host_out:
        s = entry["service"]
        ver = f" {s['version']}" if s["version"] else ""
        prod = s["product"] or s["name"] or "desconocido"
        log("INFO", f"  {ip}:{c.bold}{s['port']}{c.reset} ejecuta {c.cyan}'{prod}{ver}'{c.reset}")
        conf = entry["confirmed"]
        if conf:
            nv += len(conf)
            ncrit = sum(1 for r in conf if (r["severity"] or "") == "CRITICAL")
            nc += ncrit
            log("CRITICAL" if ncrit else "WARNING",
                f"  {c.bold}{len(conf)}{c.reset} CVE con la versión en rango (confirmados):")
            for r in conf:
                sc = f"{r['cvss']:.1f}" if r["cvss"] is not None else " ?  "
                sv = r["severity"] or "N/A"
                clr = sev_color(r["severity"])
                av = (r["attack_vector"] or "")[:3].lower()
                avm = f" {c.dim}[{av}]{c.reset}" if av else ""
                print(f"        {clr}{sc:>4} {sv:<8}{c.reset} "
                      f"{c.bold}{r['cve']}{c.reset}{avm}  {c.dim}{r['descr'][:66]}{c.reset}")
        else:
            log("INFO", f"      {c.dim}sin CVE confirmado por versión{c.reset}")
        if show_potential and entry["potential"]:
            log("DEBUG", f"      {len(entry['potential'])} potenciales "
                         f"(producto coincide, versión no detectada)")
    return nv, nc

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
# stoplist mínima: solo ruido corporativo, NO palabras de producto (http, server...)
STOP = {"the", "and", "for", "inc", "ltd", "llc", "co", "gmbh", "corp",
        "software", "foundation", "project", "team", "oss"}

# ---------- versión ----------
def clean_ver(s):
    """Extrae la versión más específica de un campo sucio.
    'Apache HTTP Server 2.4 2.4.49' -> '2.4.49'."""
    if not s:
        return None
    s = str(s).strip()
    if s in ("*", "-", ""):
        return None
    cands = re.findall(r"\d+(?:\.\d+)+", s)      # x.y[.z...]
    if cands:
        return max(cands, key=lambda c: (c.count("."), len(c)))
    m = re.fullmatch(r"v?(\d+)", s)              # entero suelto
    return m.group(1) if m else None

def vkey(s):
    c = clean_ver(s)
    if c is None:
        return None
    if vparse:
        try:
            return vparse(c)
        except InvalidVersion:
            pass
    return tuple(int(x) for x in re.findall(r"\d+", c))

def in_range(ver, intro, lt, lte, exact):
    v = vkey(ver)
    if v is None:
        return False
    try:
        if exact is not None:
            e = vkey(exact)
            return e is not None and v == e
        lo = vkey(intro) if intro and intro != "*" else None
        if lt is not None:
            hi = vkey(lt)
            return hi is not None and (lo is None or v >= lo) and v < hi
        if lte is not None:
            hi = vkey(lte)
            return hi is not None and (lo is None or v >= lo) and v <= hi
        if lo is not None and intro not in ("*",):
            return v == lo   # solo 'version' sin rango: tratar como exacta
    except TypeError:
        return False
    return False

# ---------- tokens de producto ----------
def toks(*parts):
    t = set()
    for p in parts:
        for w in re.split(r"[^a-z0-9+]+", (p or "").lower().replace("_", " ")):
            if len(w) >= 2 and w not in STOP:
                t.add(w)
    return t

def parse_cpe(cpe):
    """cpe:/a:apache:http_server:2.4.49  o  cpe:2.3:a:vendor:product:ver:...
    -> (vendor, product, version)."""
    if not cpe:
        return "", "", ""
    c = cpe.replace("cpe:/", "").replace("cpe:2.3:", "cpe:/").replace("cpe:/", "")
    parts = c.split(":")
    # formato /a:vendor:product:version
    if parts and parts[0] in ("a", "o", "h"):
        parts = parts[1:]
    vendor = parts[0] if len(parts) > 0 else ""
    product = parts[1].replace("_", " ") if len(parts) > 1 else ""
    version = parts[2] if len(parts) > 2 and parts[2] not in ("*", "-") else ""
    return vendor, product, version

# ---------- detección de servicios ----------
def tcp_open(host, port, timeout=1.0):
    try:
        s = socket.socket(); s.settimeout(timeout)
        r = s.connect_ex((host, port)); s.close()
        return r == 0
    except Exception:
        return False

def grab_banner(host, port, timeout=2.0):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((host, port))
        if port in (80, 8080, 443, 8443):
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = s.recv(1024).decode("utf-8", "ignore"); s.close()
        for line in data.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()
        return data.strip()[:120]
    except Exception:
        return ""

def parse_banner(b):
    """De un banner saca (producto, versión) de forma best-effort."""
    if not b:
        return None, None
    m = re.search(r"([A-Za-z][A-Za-z0-9 _+\-/]*?)[/ ]v?(\d+(?:\.\d+)+)", b)
    if m:
        return m.group(1).strip(), m.group(2)
    return b.split()[0] if b.split() else None, None

def scan_python(host, ports, timeout):
    found = []
    with ThreadPoolExecutor(max_workers=min(64, len(ports))) as ex:
        openp = [p for p, ok in zip(ports, ex.map(lambda p: tcp_open(host, p, timeout), ports)) if ok]
    for p in openp:
        prod, ver = parse_banner(grab_banner(host, p))
        found.append({"port": p, "name": "", "product": prod or "", "version": ver or ""})
    return found

def _nmap_progress(line):
    """Traduce una línea de nmap -v a un log legible (o None para ignorarla)."""
    if "Discovered open port" in line:
        return "INFO", "  " + line.split("Discovered ", 1)[1]        # open port 22/tcp on x
    if line.startswith("Nmap scan report for"):
        if "[host down]" in line:          # no ensuciar con hosts caídos
            return None
        return "INFO", f"explorando {line.replace('Nmap scan report for', '').strip()}"
    if line.startswith("Scanning ") and ("port" in line or "host" in line):
        return "INFO", "  " + line
    if "% done" in line:                                            # progreso + ETC
        frag = line.split("About", 1)[-1].strip() if "About" in line else line
        return "INFO", "  progreso: " + frag
    if line.startswith("Initiating") and "Service scan" in line:
        return "INFO", "  identificando versiones de servicio..."
    return None

def discover_hosts(targets, progress=True):
    """FASE 1: descubrimiento rápido (nmap -sn). Devuelve lista de IPs vivas, o None si falla."""
    import tempfile
    xml = tempfile.NamedTemporaryFile(prefix="vulnscan_disc_", suffix=".xml", delete=False)
    xml.close()
    cmd = ["nmap", "-sn", "-T4", "-v", "--stats-every", "5s", "-oX", xml.name] + targets
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except Exception as e:
        log("WARNING", f"no se pudo ejecutar nmap (descubrimiento): {e}")
        try: os.unlink(xml.name)
        except OSError: pass
        return None
    for line in proc.stdout:
        line = line.strip()
        if progress and line.startswith("Nmap scan report for") and "[host down]" not in line:
            log("INFO", f"  vivo: {line.replace('Nmap scan report for', '').strip()}")
        elif progress and "% done" in line:
            frag = line.split("About", 1)[-1].strip() if "About" in line else line
            log("INFO", "  descubrimiento: " + frag)
    proc.wait()
    try:
        root = ET.parse(xml.name).getroot()
    except (ET.ParseError, FileNotFoundError) as e:
        log("WARNING", f"no se pudo leer el descubrimiento de nmap: {e}")
        return None
    finally:
        try: os.unlink(xml.name)
        except OSError: pass
    live = []
    for h in root.findall("host"):
        st = h.find("status")
        addr = h.find("address")
        if st is not None and st.get("state") == "up" and addr is not None and addr.get("addr"):
            live.append(addr.get("addr"))
    return live

def scan_nmap(targets, ports, pn=True, progress=True):
    """nmap -sV sobre los objetivos, mostrando progreso en vivo.
    Devuelve {ip: [servicios]}; None si nmap falla. pn=False -> nmap descubre hosts."""
    import tempfile
    pl = ",".join(str(p) for p in ports)
    xml = tempfile.NamedTemporaryFile(prefix="vulnscan_", suffix=".xml", delete=False)
    xml.close()
    cmd = ["nmap", "-sT", "-sV", "--version-light", "-T4", "-v", "--stats-every", "6s"]
    if pn:
        cmd.append("-Pn")
    cmd += ["-p", pl, "-oX", xml.name] + targets
    try:
        # stderr->stdout: la salida de progreso viene por stdout; el XML va al fichero
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except Exception as e:
        log("WARNING", f"no se pudo ejecutar nmap: {e}")
        os.unlink(xml.name)
        return None
    last = ""
    for line in proc.stdout:
        line = line.strip()
        if progress and line:
            p = _nmap_progress(line)
            if p and line != last:          # evita repetir la misma línea de stats
                log(p[0], p[1])
                last = line
    rc = proc.wait()
    res = {}
    try:
        root = ET.parse(xml.name).getroot()
    except (ET.ParseError, FileNotFoundError) as e:
        log("WARNING", f"nmap terminó (código {rc}) pero no se pudo leer su XML: {e}")
        return None
    finally:
        try: os.unlink(xml.name)
        except OSError: pass
    for h in root.findall("host"):
        addr = h.find("address")
        ip = addr.get("addr") if addr is not None else None
        if not ip:
            continue
        svcs = []
        for port in h.findall("./ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = port.find("service")
            cpes = [c.text for c in port.findall("./service/cpe") if c.text]
            svcs.append({
                "port": int(port.get("portid")),
                "name": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
                "cpe": cpes,
            })
        if svcs:
            res[ip] = svcs
    return res

# ---------- matching contra el índice ----------
def match_service(con, svc, min_cvss):
    cvendor = cproduct = cver = ""
    for cpe in svc.get("cpe", []):
        cvendor, cproduct, cver = parse_cpe(cpe)
        if cproduct:
            break
    ver = svc.get("version") or cver
    pset = toks(svc.get("product"), cproduct)      # tokens de PRODUCTO
    vset = toks(cvendor)                            # tokens de VENDOR (solo)
    allset = pset | vset
    if not pset and not vset:
        return [], []

    # candidatos: por vendor si lo tenemos (indexado), si no por producto
    fetch = [t for t in (toks(cvendor) or pset) if len(t) >= 3] or list(allset)
    by_vendor = bool(toks(cvendor))
    col = "vendor_l" if by_vendor else "product_l"
    cand = {}
    for t in fetch:
        for row in con.execute(
                f"SELECT cve_id,vendor,product,v_intro,v_lt,v_lte,v_exact,"
                f"cvss,severity,attack_vector,descr FROM vuln "
                f"WHERE {col} LIKE ? LIMIT 40000", ("%" + t + "%",)):
            cand[(row[0], row[2], row[3], row[4], row[5], row[6])] = row

    confirmed, potential = [], []
    for row in cand.values():
        (cve, vendor, product, v_intro, v_lt, v_lte, v_exact,
         cvss, sev, av, descr) = row
        cprod = toks(product)
        # regla de relevancia (precisa):
        #  - todos los tokens de producto del CVE están en lo detectado
        #  - comparten al menos una palabra de PRODUCTO (no solo vendor)
        #  - el producto del CVE no es solo el nombre del vendor
        if not cprod or not (cprod <= allset):
            continue
        if not (cprod & pset):          # debe compartir una palabra de producto
            continue
        if vset and cprod <= vset:      # el producto del CVE es solo el vendor
            continue
        if cvss is not None and min_cvss and cvss < min_cvss:
            continue
        rec = {"cve": cve, "product": product, "cvss": cvss, "severity": sev,
               "attack_vector": av, "descr": descr, "service_ver": ver}
        if ver and in_range(ver, v_intro, v_lt, v_lte, v_exact):
            confirmed.append(rec)
        elif not ver:
            potential.append(rec)
    # dedup por CVE quedándose con el de mayor cvss
    def dedup(lst):
        best = {}
        for r in lst:
            k = r["cve"]
            if k not in best or (r["cvss"] or 0) > (best[k]["cvss"] or 0):
                best[k] = r
        return sorted(best.values(), key=lambda r: (r["cvss"] or 0), reverse=True)
    return dedup(confirmed), dedup(potential)

# ---------- main ----------
def expand(target):
    try:
        if "/" in target:
            return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
    except ValueError:
        pass
    return [target]

def main():
    ap = argparse.ArgumentParser(description="Escáner CVE rápido y fiable")
    ap.add_argument("targets", nargs="+", help="IP, hostname o CIDR (p.ej. 192.168.1.0/24)")
    ap.add_argument("--db", default="/usr/src/cves/cve_index.sqlite")
    ap.add_argument("--ports", type=lambda s: [int(x) for x in s.split(",")], default=DEFAULT_PORTS)
    ap.add_argument("--min-cvss", type=float, default=0.0)
    ap.add_argument("--top", type=int, default=15, help="máx. CVEs por servicio")
    ap.add_argument("--show-potential", action="store_true", help="mostrar coincidencias sin versión")
    ap.add_argument("--no-nmap", action="store_true")
    ap.add_argument("--pn", action="store_true",
                    help="saltar descubrimiento y tratar todos los hosts como vivos (nmap -Pn)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--color", action="store_true", help="forzar color aunque no haya TTY")
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    enable_color(args.color or (sys.stdout.isatty() and not args.no_color
                 and os.environ.get("NO_COLOR") is None))
    if not args.json:
        banner()

    if not os.path.exists(args.db):
        sys.exit(f"[!] No existe el índice {args.db}. Ejecuta build_index.py primero.")
    con = sqlite3.connect(args.db)
    nsig = con.execute("SELECT COUNT(*) FROM vuln").fetchone()[0]

    hosts = []
    for t in args.targets:
        hosts += expand(t)

    if not args.json:
        log("INFO", f"iniciando en {ts()}")
        log("INFO", f"índice CVE cargado ({nsig:,} firmas, {CVE_RANGE})")
        log("INFO", f"objetivo: {', '.join(args.targets)} ({len(hosts)} host(s))")

    use_nmap = (not args.no_nmap) and shutil.which("nmap")
    # ---- decidir objetivos a escanear (FASE 1) y la función de escaneo ----
    scan_fn = None
    targets_list = []
    if use_nmap:
        if args.pn:
            live = hosts
            if not args.json:
                log("INFO", "descubrimiento omitido (--pn): trato todos como vivos")
        else:
            if not args.json:
                log("INFO", f"fase 1: descubriendo hosts vivos en {len(hosts)} dirección(es)...")
            live = discover_hosts(args.targets, progress=not args.json)
        if live is None:                    # el descubrimiento falló de verdad
            if not args.json:
                log("WARNING", "nmap (descubrimiento) falló; usando sondeo TCP propio")
            targets_list = hosts
            scan_fn = lambda h: scan_python(h, args.ports, args.timeout)
        else:
            if not args.json:
                log("INFO", f"fase 1 completa: {c.bold}{len(live)}{c.reset} host(s) vivo(s)")
            targets_list = live
            # escaneo de versión por host (así podemos pintar hallazgos en cuanto acaba cada uno)
            scan_fn = lambda h: next(iter((scan_nmap([h], args.ports, pn=True,
                                                     progress=False) or {}).values()), [])
    else:
        if not args.json:
            reason = "nmap desactivado (--no-nmap)" if args.no_nmap else "nmap no está instalado"
            log("WARNING", f"{reason}; usando sondeo TCP propio")
        targets_list = hosts
        scan_fn = lambda h: scan_python(h, args.ports, args.timeout)

    if not args.json and targets_list:
        log("INFO", f"fase 2: escaneando servicios y versiones en {len(targets_list)} host(s)...")

    # ---- FASE 2: escaneo concurrente; se pintan los CVEs de cada host al terminar ----
    report = {}
    total_vulns = total_crit = 0
    done = 0
    if targets_list:
        with ThreadPoolExecutor(max_workers=min(12, len(targets_list))) as ex:
            futs = {ex.submit(scan_fn, h): h for h in targets_list}
            for fut in as_completed(futs):
                h = futs[fut]
                done += 1
                try:
                    svcs = fut.result() or []
                except Exception:
                    svcs = []
                if not svcs:
                    continue
                host_out = []
                for svc in svcs:
                    conf, pot = match_service(con, svc, args.min_cvss)
                    host_out.append({"service": svc, "confirmed": conf[:args.top],
                                     "potential": pot[:args.top]})
                report[h] = host_out
                if not args.json:
                    nv, nc = render_host(h, host_out, done, len(targets_list), args.show_potential)
                    total_vulns += nv
                    total_crit += nc

    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return

    print()
    if total_vulns:
        log("CRITICAL" if total_crit else "WARNING",
            f"{c.bold}{total_vulns}{c.reset} vulnerabilidad(es) confirmada(s) "
            f"en {len(report)} host(s) — {c.bred}{total_crit} crítica(s){c.reset}")
    else:
        log("INFO", f"{c.bgreen}sin vulnerabilidades confirmadas por versión{c.reset}")
    log("INFO", f"finalizado en {ts()}")
    con.close()

if __name__ == "__main__":
    main()
