#!/usr/bin/env python3
import json
import os
import glob
import re

CVE_DIR = "/usr/src/cves/cvelistV5-main/cves/2016"
OUTPUT_DIR = "/usr/src/cves/cve_scripts_2016"

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

LOCAL_KEYWORDS = [
    r'\blocal\b',
    r'\blocally\b',
    r'\bprivilege escalation\b',
    r'\blocal privilege\b',
    r'\bexecute code locally\b',
    r'\brequire local\b',
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
                elif av == 'ADJACENT_NETWORK':
                    return 'ADJACENT_NETWORK'
        
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
                            elif av == 'ADJACENT_NETWORK':
                                return 'ADJACENT_NETWORK'
        
        legacy = cna.get('x_legacyV4Record', {})
        if legacy:
            impact = legacy.get('impact', {})
            if impact:
                vector = impact.get('cvss', {}).get('vectorString', '')
                if 'AV:N' in vector:
                    return 'NETWORK'
                elif 'AV:L' in vector:
                    return 'LOCAL'
                elif 'AV:A' in vector:
                    return 'ADJACENT_NETWORK'
                elif 'AV:P' in vector:
                    return 'PHYSICAL'
        
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

def analyze_description_remote(description):
    desc_lower = description.lower()
    
    for keyword in LOCAL_KEYWORDS:
        if re.search(keyword, desc_lower):
            if 'local' in keyword and 'not local' not in desc_lower:
                return 'LOCAL'
    
    for keyword in REMOTE_KEYWORDS:
        if re.search(keyword, desc_lower):
            return 'REMOTE_LIKELY'
    
    return 'UNKNOWN'

def create_check_script(cve_id, cve_path, output_dir, attack_vector=None, description='', analysis=''):
    is_rej = is_rejected(cve_path)
    
    if is_rej:
        status = "REJECTED"
        is_remote = False
    elif attack_vector == 'NETWORK':
        status = "REMOTE (NETWORK)"
        is_remote = True
    elif attack_vector == 'LOCAL':
        status = "LOCAL"
        is_remote = False
    elif attack_vector == 'ADJACENT_NETWORK':
        status = "ADJACENT_NETWORK"
        is_remote = False
    elif attack_vector == 'PHYSICAL':
        status = "PHYSICAL"
        is_remote = False
    elif attack_vector == 'REMOTE_LIKELY':
        status = "REMOTE (by description analysis)"
        is_remote = True
    else:
        status = "UNKNOWN - No attackVector found"
        is_remote = None
    
    script_content = f'''#!/usr/bin/env python3
"""
CVE Check Script: {cve_id}
Status: {status}
Description: {description}
Analysis: {analysis}
"""

CVE_ID = "{cve_id}"
CVE_PATH = "{cve_path}"

def check_remote():
    """
    Check if this CVE is remotely exploitable.
    Returns True if the CVE is remote (NETWORK attack vector), False otherwise.
    """
    return {is_remote}

def get_details():
    return {{
        "cve_id": "{cve_id}",
        "is_remote": {is_remote},
        "attack_vector": "{attack_vector if attack_vector else 'UNKNOWN'}",
        "status": "{status}",
        "description": """{description}""",
        "analysis": "{analysis}"
    }}

if __name__ == "__main__":
    details = get_details()
    print(f"CVE: {{details['cve_id']}}")
    print(f"Remote: {{details['is_remote']}}")
    print(f"Attack Vector: {{details['attack_vector']}}")
    print(f"Status: {{details['status']}}")
    print(f"Description: {{details['description']}}")
    if details['analysis']:
        print(f"Analysis: {{details['analysis']}}")
'''
    
    script_filename = os.path.join(output_dir, f"{cve_id}.py")
    with open(script_filename, 'w') as f:
        f.write(script_content)
    
    return is_remote, attack_vector, is_rej

def main():
    unknown_file = os.path.join(OUTPUT_DIR, "unknown_cves.txt")
    with open(unknown_file, 'r') as f:
        unknown_cves = [line.strip() for line in f if line.strip()]
    
    new_remote = []
    
    print(f"Analyzing {len(unknown_cves)} unknown CVEs for remote indicators...")
    
    for cve_id in unknown_cves:
        cve_num = cve_id.replace('CVE-2016-', '')
        
        if len(cve_num) <= 4:
            subdir = cve_num[0] + 'xxx'
        elif len(cve_num) == 5:
            subdir = cve_num[0:2] + 'xxx'
        elif len(cve_num) == 6:
            subdir = cve_num[0:3] + 'xxx'
        else:
            subdir = cve_num[0:4] + 'xxx'
        
        cve_path = os.path.join(CVE_DIR, subdir, f"{cve_id}.json")
        
        if not os.path.exists(cve_path):
            continue
        
        attack_vector = find_attack_vector(cve_path)
        description = get_cve_description(cve_path)
        
        if attack_vector is None and description:
            analysis_result = analyze_description_remote(description)
            
            if analysis_result == 'REMOTE_LIKELY':
                create_check_script(cve_id, cve_path, OUTPUT_DIR, 
                                   attack_vector='REMOTE_LIKELY', 
                                   description=description[:200],
                                   analysis='Determined remote based on description keywords')
                new_remote.append(cve_id)
                print(f"  [NEW REMOTE] {cve_id}: {description[:80]}...")
    
    print(f"\n=== New Remote CVEs Found by Description Analysis ===")
    print(f"Total new remote CVEs: {len(new_remote)}")
    
    if new_remote:
        with open(os.path.join(OUTPUT_DIR, "new_remote_cves.txt"), 'w') as f:
            for cve in sorted(new_remote):
                f.write(f"{cve}\n")
        
        with open(os.path.join(OUTPUT_DIR, "remote_cves.txt"), 'a') as f:
            for cve in sorted(new_remote):
                f.write(f"{cve}\n")
        
        print(f"Updated remote_cves.txt with {len(new_remote)} new entries")
        print(f"List saved to: {OUTPUT_DIR}/new_remote_cves.txt")

if __name__ == "__main__":
    main()
