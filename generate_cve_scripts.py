#!/usr/bin/env python3
import json
import os
import glob

CVE_DIR = "/usr/src/cves/cvelistV5-main/cves/2016"
OUTPUT_DIR = "/usr/src/cves/cve_scripts_2016"

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
                return desc.get('value', '')[:200].replace('"', "'").replace('\n', ' ')
        return ''
    except:
        return ''

def create_check_script(cve_id, cve_path, output_dir):
    attack_vector = find_attack_vector(cve_path)
    is_rej = is_rejected(cve_path)
    description = get_cve_description(cve_path)
    
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
    else:
        status = "UNKNOWN - No attackVector found"
        is_remote = None
    
    script_content = f'''#!/usr/bin/env python3
"""
CVE Check Script: {cve_id}
Status: {status}
Description: {description}
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
    
    return is_remote, attack_vector, is_rej

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    all_cves = []
    for pattern in ['[0-9]xxx', '[1-9]xxx', '[1-9][0-9]xxx', '[1-9][0-9][0-9]xxx', '[1-9][0-9][0-9][0-9]xxx']:
        search_pattern = os.path.join(CVE_DIR, pattern, "CVE-2016-*.json")
        all_cves.extend(glob.glob(search_pattern))
    
    remote_cves = set()
    local_cves = set()
    unknown_cves = set()
    rejected_cves = set()
    
    print(f"Processing {len(all_cves)} CVEs from 2016...")
    
    for cve_path in sorted(all_cves):
        cve_id = os.path.basename(cve_path).replace('.json', '')
        is_remote, attack_vector, is_rej = create_check_script(cve_id, cve_path, OUTPUT_DIR)
        
        if is_rej:
            rejected_cves.add(cve_id)
        elif is_remote is True:
            remote_cves.add(cve_id)
        elif is_remote is False:
            local_cves.add(cve_id)
        else:
            unknown_cves.add(cve_id)
    
    remote_cves_list = sorted(list(remote_cves))
    local_cves_list = sorted(list(local_cves))
    unknown_cves_list = sorted(list(unknown_cves))
    rejected_cves_list = sorted(list(rejected_cves))
    
    print(f"\n=== Summary ===")
    print(f"Total CVEs: {len(all_cves)}")
    print(f"Remote (NETWORK): {len(remote_cves_list)}")
    print(f"Local: {len(local_cves_list)}")
    print(f"Unknown (no attackVector): {len(unknown_cves_list)}")
    print(f"Rejected: {len(rejected_cves_list)}")
    
    with open(os.path.join(OUTPUT_DIR, "README.md"), 'w') as f:
        f.write("# CVE 2016 Remote Check Scripts\n\n")
        f.write("This directory contains Python scripts to check if each CVE-2016 is remotely exploitable.\n\n")
        f.write("## Summary\n")
        f.write(f"- Total CVEs: {len(all_cves)}\n")
        f.write(f"- Remote (NETWORK): {len(remote_cves_list)}\n")
        f.write(f"- Local: {len(local_cves_list)}\n")
        f.write(f"- Unknown: {len(unknown_cves_list)}\n")
        f.write(f"- Rejected: {len(rejected_cves_list)}\n\n")
        f.write("## Remote CVEs (attackVector = NETWORK)\n")
        for cve in remote_cves_list:
            f.write(f"- {cve}\n")
        f.write("\n## Local CVEs (attackVector = LOCAL)\n")
        for cve in local_cves_list:
            f.write(f"- {cve}\n")
        f.write("\n## Unknown CVEs (no attackVector found)\n")
        for cve in unknown_cves_list:
            f.write(f"- {cve}\n")
        f.write("\n## Rejected CVEs\n")
        for cve in rejected_cves_list:
            f.write(f"- {cve}\n")
    
    with open(os.path.join(OUTPUT_DIR, "remote_cves.txt"), 'w') as f:
        for cve in remote_cves_list:
            f.write(f"{cve}\n")
    
    with open(os.path.join(OUTPUT_DIR, "unknown_cves.txt"), 'w') as f:
        for cve in unknown_cves_list:
            f.write(f"{cve}\n")
    
    print(f"\nScripts created in: {OUTPUT_DIR}")
    print(f"Remote CVEs list: {OUTPUT_DIR}/remote_cves.txt")
    print(f"Unknown CVEs list: {OUTPUT_DIR}/unknown_cves.txt")

if __name__ == "__main__":
    main()
