#!/usr/bin/env python3
import json
import os
import glob

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
                return desc.get('value', '').lower()
        return ''
    except:
        return ''

def analyze_description(description):
    for keyword in REMOTE_KEYWORDS:
        import re
        if re.search(keyword, description):
            return True
    return False

def main():
    all_cves = []
    for pattern in ['[0-9]xxx', '[1-9]xxx', '[1-9][0-9]xxx', '[1-9][0-9][0-9]xxx', '[1-9][0-9][0-9][0-9]xxx']:
        search_pattern = os.path.join(CVE_DIR, pattern, "CVE-2016-*.json")
        all_cves.extend(glob.glob(search_pattern))
    
    unknown_cves = []
    remote_cves = set()
    local_cves = set()
    rejected_cves = set()
    
    for cve_path in all_cves:
        cve_id = os.path.basename(cve_path).replace('.json', '')
        
        if is_rejected(cve_path):
            rejected_cves.add(cve_id)
            continue
        
        attack_vector = find_attack_vector(cve_path)
        
        if attack_vector == 'NETWORK':
            remote_cves.add(cve_id)
        elif attack_vector == 'LOCAL':
            local_cves.add(cve_id)
        else:
            description = get_cve_description(cve_path)
            if analyze_description(description):
                remote_cves.add(cve_id)
            else:
                unknown_cves.append(cve_id)
    
    print(f"Total CVEs: {len(all_cves)}")
    print(f"Remote: {len(remote_cves)}")
    print(f"Local: {len(local_cves)}")
    print(f"Unknown: {len(unknown_cves)}")
    print(f"Rejected: {len(rejected_cves)}")
    
    with open(os.path.join(OUTPUT_DIR, "remote_cves.txt"), 'w') as f:
        for cve in sorted(remote_cves):
            f.write(f"{cve}\n")
    
    with open(os.path.join(OUTPUT_DIR, "unknown_cves.txt"), 'w') as f:
        for cve in sorted(unknown_cves):
            f.write(f"{cve}\n")
    
    print(f"\nUpdated files in {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
