#!/usr/bin/env python3
import json
import os
import glob
import re
import sys

CVE_DIR_BASE = "/usr/src/cves/cvelistV5-main/cves"
OUTPUT_DIR_BASE = "/usr/src/cves"

REMOTE_KEYWORDS = [
    r'\bremote\b',
    r'\bnetwork\b',
    r'\bhttp\b',
    r'\bhttps\b',
    r'\bweb\b',
    r'\bserver\b',
    r'\binternet\b',
    r'\battacker can (exploit|send|use)\b',
    r'\bvia (unspecified|a remote|network)\b',
    r'\b(exploit|attack) remotely\b',
    r'\bremote (attacker|code execution|injection)\b',
    r'\bauthentication\b',
    r'\b(session|hijack)\b',
    r'\b(sql|xss|cross[- ]site)\b',
    r'\b(file|path|directory) inclusion\b',
    r'\b(buffer|heap|stack) overflow\b',
    r'\binteger overflow\b',
    r'\buse[- ]after[- ]free\b',
    r'\bformat string\b',
    r'\bdenial of service\b',
    r'\bcsrf\b',
    r'\bopen.?redirect\b',
    r'\bxxe\b',
    r'\bxml external entity\b',
]

def find_attack_vector(cve_path):
    try:
        with open(cve_path, 'r') as f:
            data = json.load(f)
        
        containers = data.get('containers', {})
        cna = containers.get('cna', {})
        metrics = cna.get('metrics', [])
        
        for metric in metrics:
            if 'cvssV3_1' in metric:
                return metric['cvssV3_1'].get('attackVector')
            if 'cvssV3_0' in metric:
                return metric['cvssV3_0'].get('attackVector')
            if 'cvssV2_0' in metric:
                av = metric['cvssV2_0'].get('accessVector')
                if av == 'NETWORK':
                    return 'NETWORK'
                elif av == 'LOCAL':
                    return 'LOCAL'
        
        for metric in metrics:
            for key in metric:
                if 'cvss' in key.lower():
                    cvss_data = metric[key]
                    if isinstance(cvss_data, dict):
                        if 'attackVector' in cvss_data:
                            return cvss_data['attackVector']
                        if 'accessVector' in cvss_data:
                            av = cvss_data['accessVector']
                            if av == 'NETWORK':
                                return 'NETWORK'
                            elif av == 'LOCAL':
                                return 'LOCAL'
        
        legacy = cna.get('x_legacyV4Record', {})
        if legacy:
            impact = legacy.get('impact', {})
            if impact:
                vector = impact.get('cvss', {}).get('vectorString', '')
                if 'AV:N' in vector:
                    return 'NETWORK'
                elif 'AV:L' in vector:
                    return 'LOCAL'
        
        return None
        
    except Exception:
        return None

def is_rejected(cve_path):
    try:
        with open(cve_path, 'r') as f:
            data = json.load(f)
        metadata = data.get('cveMetadata', {})
        state = metadata.get('state', '')
        return state == 'REJECTED'
    except:
        return False

def get_cve_description(cve_path):
    try:
        with open(cve_path, 'r') as f:
            data = json.load(f)
        containers = data.get('containers', {})
        cna = containers.get('cna', {})
        descriptions = cna.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')[:500].replace('"', "'").replace('\n', ' ')
        return ''
    except:
        return ''

def analyze_description(description):
    desc_lower = description.lower()
    for keyword in REMOTE_KEYWORDS:
        if re.search(keyword, desc_lower):
            return True
    return False

def create_check_script(cve_id, cve_path, output_dir, attack_vector=None, description='', is_remote=None):
    if is_remote is True:
        status = "REMOTE (NETWORK)"
    elif is_remote is False and attack_vector:
        status = attack_vector
    elif is_remote is False:
        status = "REJECTED"
    else:
        status = "UNKNOWN"
    
    script_content = f'''#!/usr/bin/env python3
"""
CVE Check Script: {cve_id}
Status: {status}
Description: {description}
"""

CVE_ID = "{cve_id}"
CVE_PATH = "{cve_path}"

def check_remote():
    return {is_remote}

def get_details():
    return {{
        "cve_id": "{cve_id}",
        "is_remote": {is_remote},
        "attack_vector": "{attack_vector if attack_vector else 'UNKNOWN'}",
        "status": "{status}",
        "description": """{description}"""
    }}

if __name__ == "__main__":
    details = get_details()
    print(f"CVE: {{details['cve_id']}}")
    print(f"Remote: {{details['is_remote']}}")
    print(f"Attack Vector: {{details['attack_vector']}}")
    print(f"Status: {{details['status']}}")
    print(f"Description: {{details['description']}}")
'''
    
    script_filename = os.path.join(output_dir, f"{cve_id}.py")
    with open(script_filename, 'w') as f:
        f.write(script_content)

def process_year(year):
    CVE_DIR = os.path.join(CVE_DIR_BASE, year)
    OUTPUT_DIR = os.path.join(OUTPUT_DIR_BASE, f"cve_scripts_{year}")
    
    if not os.path.exists(CVE_DIR):
        print(f"Year {year} not found, skipping...")
        return
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    all_cves = []
    for pattern in ['[0-9]xxx', '[1-9]xxx', '[1-9][0-9]xxx', '[1-9][0-9][0-9]xxx', '[1-9][0-9][0-9][0-9]xxx']:
        search_pattern = os.path.join(CVE_DIR, pattern, f"CVE-{year}-*.json")
        all_cves.extend(glob.glob(search_pattern))
    
    if not all_cves:
        print(f"No CVEs found for year {year}")
        return
    
    print(f"\n=== Processing {year} ({len(all_cves)} CVEs) ===")
    
    remote_cves = set()
    local_cves = set()
    unknown_cves = set()
    rejected_cves = set()
    
    for i, cve_path in enumerate(sorted(all_cves)):
        cve_id = os.path.basename(cve_path).replace('.json', '')
        
        if is_rejected(cve_path):
            rejected_cves.add(cve_id)
            create_check_script(cve_id, cve_path, OUTPUT_DIR, attack_vector='REJECTED', description='REJECTED', is_remote=False)
            continue
        
        attack_vector = find_attack_vector(cve_path)
        description = get_cve_description(cve_path)
        
        if attack_vector == 'NETWORK':
            remote_cves.add(cve_id)
            create_check_script(cve_id, cve_path, OUTPUT_DIR, attack_vector='NETWORK', description=description, is_remote=True)
        elif attack_vector == 'LOCAL':
            local_cves.add(cve_id)
            create_check_script(cve_id, cve_path, OUTPUT_DIR, attack_vector='LOCAL', description=description, is_remote=False)
        elif analyze_description(description):
            remote_cves.add(cve_id)
            create_check_script(cve_id, cve_path, OUTPUT_DIR, attack_vector='REMOTE_LIKELY', description=description, is_remote=True)
        else:
            unknown_cves.add(cve_id)
            create_check_script(cve_id, cve_path, OUTPUT_DIR, attack_vector='UNKNOWN', description=description, is_remote=None)
        
        if (i + 1) % 1000 == 0:
            print(f"  Processed {i + 1}/{len(all_cves)} CVEs...")
    
    print(f"  Remote: {len(remote_cves)}, Local: {len(local_cves)}, Unknown: {len(unknown_cves)}, Rejected: {len(rejected_cves)}")
    
    with open(os.path.join(OUTPUT_DIR, "remote_cves.txt"), 'w') as f:
        for cve in sorted(remote_cves):
            f.write(f"{cve}\n")
    
    with open(os.path.join(OUTPUT_DIR, "unknown_cves.txt"), 'w') as f:
        for cve in sorted(unknown_cves):
            f.write(f"{cve}\n")
    
    with open(os.path.join(OUTPUT_DIR, "README.md"), 'w') as f:
        f.write(f"# CVE {year} Remote Check Scripts\n\n")
        f.write(f"Total CVEs: {len(all_cves)}\n")
        f.write(f"Remote: {len(remote_cves)}\n")
        f.write(f"Local: {len(local_cves)}\n")
        f.write(f"Unknown: {len(unknown_cves)}\n")
        f.write(f"Rejected: {len(rejected_cves)}\n")
    
    print(f"  Done! Output: {OUTPUT_DIR}")

def main():
    years = [str(y) for y in range(1999, 2019)]
    years.remove('2016')
    
    print(f"Processing {len(years)} years: {', '.join(years)}")
    
    for year in years:
        process_year(year)
    
    print("\n=== ALL YEARS COMPLETED ===")

if __name__ == "__main__":
    main()
