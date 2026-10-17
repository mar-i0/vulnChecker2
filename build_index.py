#!/usr/bin/env python3
"""
build_index.py — Construye un índice SQLite consultable de todos los CVE.

Recorre cvelistV5-main/cves/**/CVE-*.json y vuelca una fila por cada
rango de versión afectado: producto, rango, CVSS, vector y descripción.
Reemplaza el leer 220k scripts en cada escaneo por una sola consulta SQL.

Uso:
    python3 build_index.py [--src DIR] [--db FICHERO]
"""
import os, sys, json, glob, sqlite3, argparse, time

def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None

def best_cvss(containers):
    """(score, severity, attackVector) de la mejor métrica en cna o en cualquier adp.
    El CVSS a menudo lo añade ADP (CISA), no el CNA."""
    cna = containers.get("cna", {}) if isinstance(containers, dict) else {}
    score = sev = av = None
    metric_lists = [cna.get("metrics", [])]
    for a in (containers.get("adp", []) if isinstance(containers, dict) else []):
        if isinstance(a, dict) and a.get("metrics"):
            metric_lists.append(a.get("metrics"))
    for metrics in metric_lists:
        if not isinstance(metrics, list):
            continue
        for m in metrics:
            if not isinstance(m, dict):
                continue
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                c = m.get(key)
                if isinstance(c, dict):
                    score = score if score is not None else _num(c.get("baseScore"))
                    sev = sev or c.get("baseSeverity")
                    av = av or c.get("attackVector")
                    vec = c.get("vectorString", "") or ""
                    if av is None:
                        if "AV:N" in vec: av = "NETWORK"
                        elif "AV:L" in vec: av = "LOCAL"
    # legacy (impact / cvss pueden ser dict o list según el registro)
    if score is None:
        rec = cna.get("x_legacyV4Record")
        impact = rec.get("impact") if isinstance(rec, dict) else None
        leg = impact.get("cvss") if isinstance(impact, dict) else None
        if isinstance(leg, list):
            leg = leg[0] if leg else None
        if isinstance(leg, dict):
            score = _num(leg.get("baseScore"))
            vec = leg.get("vectorString", "") or ""
            if "AV:N" in vec and not av: av = "NETWORK"
    if sev is None and score is not None:
        s = float(score)
        sev = ("CRITICAL" if s >= 9 else "HIGH" if s >= 7 else
               "MEDIUM" if s >= 4 else "LOW" if s > 0 else "NONE")
    return score, sev, av

def en_desc(cna):
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            return d.get("value", "")[:400].replace("\n", " ").strip()
    return ""

def iter_affected(cna):
    """Genera (vendor, product, version_intro, lt, lte, exact, vtype) por rango."""
    for a in cna.get("affected", []):
        if not isinstance(a, dict):
            continue
        vendor = (a.get("vendor") or "").strip()
        product = (a.get("product") or "").strip()
        if not product or product.lower() == "n/a":
            # a veces el producto real está en packageName
            product = (a.get("packageName") or product).strip()
        vers = a.get("versions") or []
        if not vers:
            # sin detalle de versión: fila "producto afectado, versión desconocida"
            yield vendor, product, None, None, None, None, None
            continue
        for v in vers:
            if not isinstance(v, dict):
                continue
            if v.get("status") and v.get("status") != "affected":
                continue
            yield (vendor, product,
                   (v.get("version") or None),
                   (v.get("lessThan") or None),
                   (v.get("lessThanOrEqual") or None),
                   # exacto si hay version y no hay rango abierto
                   (v.get("version") if not (v.get("lessThan") or v.get("lessThanOrEqual")) else None),
                   (v.get("versionType") or None))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="/usr/src/cves/cvelistV5-main/cves")
    ap.add_argument("--db", default="/usr/src/cves/cve_index.sqlite")
    args = ap.parse_args()

    files = glob.glob(os.path.join(args.src, "*", "*", "CVE-*.json"))
    print(f"[*] {len(files):,} ficheros CVE en {args.src}", flush=True)

    if os.path.exists(args.db):
        os.remove(args.db)
    con = sqlite3.connect(args.db)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    con.execute("""CREATE TABLE vuln(
        cve_id TEXT, vendor TEXT, vendor_l TEXT, product TEXT, product_l TEXT,
        v_intro TEXT, v_lt TEXT, v_lte TEXT, v_exact TEXT, v_type TEXT,
        cvss REAL, severity TEXT, attack_vector TEXT, year INTEGER, descr TEXT)""")

    rows = []
    t0 = time.time(); n_cve = n_rows = 0
    for i, f in enumerate(files, 1):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        meta = d.get("cveMetadata", {})
        if meta.get("state") == "REJECTED":
            continue
        cve_id = meta.get("cveId") or os.path.basename(f)[:-5]
        try: year = int(cve_id.split("-")[1])
        except Exception: year = None
        containers = d.get("containers", {})
        cna = containers.get("cna", {})
        score, sev, av = best_cvss(containers)
        descr = en_desc(cna)
        n_cve += 1
        for vendor, product, intro, lt, lte, exact, vtype in iter_affected(cna):
            if not product:
                continue
            rows.append((cve_id, vendor, vendor.lower(), product, product.lower(),
                         intro, lt, lte, exact, vtype,
                         score, sev, av, year, descr))
            n_rows += 1
        if len(rows) >= 50000:
            con.executemany("INSERT INTO vuln VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            rows.clear()
        if i % 40000 == 0:
            print(f"    {i:,}/{len(files):,} ficheros...", flush=True)
    if rows:
        con.executemany("INSERT INTO vuln VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    print("[*] Creando índices...", flush=True)
    con.execute("CREATE INDEX idx_prod ON vuln(product_l)")
    con.execute("CREATE INDEX idx_vendor ON vuln(vendor_l)")
    con.execute("CREATE INDEX idx_cve ON vuln(cve_id)")
    con.commit()
    total = con.execute("SELECT COUNT(*) FROM vuln").fetchone()[0]
    prods = con.execute("SELECT COUNT(DISTINCT product_l) FROM vuln").fetchone()[0]
    con.close()
    sz = os.path.getsize(args.db) / 1e6
    print(f"[✓] {n_cve:,} CVEs -> {total:,} filas, {prods:,} productos distintos")
    print(f"[✓] {args.db}  ({sz:.0f} MB)  en {time.time()-t0:.0f}s")

if __name__ == "__main__":
    main()
