#!/usr/bin/env python3
import argparse
import subprocess
import xml.etree.ElementTree as ET
import time
import shutil
import re
import ipaddress
import os
import sys
from pathlib import Path
from datetime import datetime

class Colors:
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    BLUE = '\033[34m'
    CYAN = '\033[36m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

class Config:
    SPINNER_CHARS = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    PROJECT_DIRS = ['images', 'nmap', 'files']
    BANNER = f"""{Colors.CYAN}{Colors.BOLD}
██████╗ ██╗    ██╗███╗   ██╗██╗███╗   ██╗██╗████████╗
██╔══██╗██║    ██║████╗  ██║██║████╗  ██║██║╚══██╔══╝
██████╔╝██║ █╗ ██║██╔██╗ ██║██║██╔██╗ ██║██║   ██║   
██╔═══╝ ██║███╗██║██║╚██╗██║██║██║╚██╗██║██║   ██║   
██║     ╚███╔███╔╝██║ ╚████║██║██║ ╚████║██║   ██║   
╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝   
{Colors.RESET}{Colors.DIM}        A CTF Challenge Template Generator{Colors.RESET}
"""

def validate_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        if ip_obj.is_loopback or ip_obj.is_multicast:
            raise ValueError("Invalid IP address")
        return str(ip_obj)
    except ipaddress.AddressValueError:
        raise ValueError(f"Invalid IP format: {ip_str}")

def sanitize_name(name):
    if not name or not name.strip():
        raise ValueError("Name cannot be empty")
    name = name.strip()
    if len(name) > 100:
        raise ValueError("Name too long")
    clean_name = re.sub(r'[^\w\s\-]', '', name)
    clean_name = re.sub(r'\s+', '_', clean_name)
    clean_name = re.sub(r'_+', '_', clean_name).strip('_')
    if not clean_name or '..' in clean_name:
        raise ValueError("Invalid name")
    return clean_name

def log(level, message, quiet=False):
    if quiet and level != 'error':
        return
    colors = {'info': Colors.BLUE, 'success': Colors.GREEN, 'error': Colors.RED, 'warning': Colors.YELLOW}
    symbols = {'info': '[*]', 'success': '[+]', 'error': '[-]', 'warning': '[!]'}
    color = colors.get(level, '')
    symbol = symbols.get(level, '[*]')
    print(f"{color}{symbol}{Colors.RESET} {message}")

def overwrite_line(text):
    sys.stdout.write('\r' + ' ' * (shutil.get_terminal_size().columns - 1) + '\r')
    sys.stdout.write(text)
    sys.stdout.flush()

def create_directories(project_path):
    project_path.mkdir(parents=True, exist_ok=True)
    for dir_name in Config.PROJECT_DIRS:
        (project_path / dir_name).mkdir(exist_ok=True)

def run_nmap_scan(target_ip, output_path, quiet=False):
    if not shutil.which('nmap'):
        log('error', "nmap not found - install with: sudo apt install nmap")
        return None
    output_base = output_path.with_suffix('')
    cmd = ['nmap', '-sC', '-sV', '-T4', target_ip, '-oA', str(output_base)]
    process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    start_time = datetime.now()
    spinner_idx = 0
    try:
        while process.poll() is None:
            if not quiet:
                spinner = Config.SPINNER_CHARS[spinner_idx % len(Config.SPINNER_CHARS)]
                elapsed = (datetime.now() - start_time).seconds
                overwrite_line(f"{Colors.CYAN}[{spinner}]{Colors.RESET} Scanning {target_ip} ({elapsed}s)")
                spinner_idx += 1
            time.sleep(0.1)
        if not quiet:
            overwrite_line('')
        if process.returncode == 0:
            duration = (datetime.now() - start_time).seconds
            log('success', f"Scan completed ({duration}s)", quiet)
            xml_path = output_path.with_suffix('.xml')
            return xml_path if xml_path.exists() else None
        else:
            log('error', "Scan failed", quiet)
            return None
    except KeyboardInterrupt:
        if not quiet:
            overwrite_line('')
        log('warning', "Scan interrupted")
        process.terminate()
        return None

def parse_nmap_results(xml_file):
    if not xml_file or not xml_file.exists():
        return []
    results = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall('host'):
            addr_elem = host.find('address')
            if addr_elem is None:
                continue
            host_ip = addr_elem.get('addr', '')
            for port in host.findall('ports/port'):
                state_elem = port.find('state')
                if state_elem is None or state_elem.get('state') != 'open':
                    continue
                port_num = port.get('portid', '')
                service_elem = port.find('service')
                if service_elem is not None:
                    service_name = service_elem.get('name', '')
                    product = service_elem.get('product', '')
                    version = service_elem.get('version', '')
                    version_info = ' '.join(filter(None, [product, version]))
                else:
                    service_name = ''
                    version_info = ''
                results.append({
                    'ip': host_ip,
                    'port': port_num,
                    'service': service_name,
                    'version': version_info
                })
        return results
    except ET.ParseError:
        return []

def generate_template(name, ip, platform, difficulty, os_type, scan_results):
    output_base = f"nmap/{name}"
    template = f"""# {name}

**IP:** {ip}  
**Platform:** {platform}  
**Difficulty:** {difficulty}  
**OS:** {os_type}  
**Date:** {datetime.now().strftime('%d/%m/%Y')}

## Summary



## Reconnaissance

```bash
nmap -sC -sV -T4 {ip} -oA {output_base}
```

"""

    if scan_results:
        template += "| Port | Service | Version |\n|------|---------|---------|"
        for result in scan_results:
            port = result.get('port', '')
            service = result.get('service', 'unknown')
            version = result.get('version', 'N/A')
            template += f"\n| {port} | {service} | {version} |"
        template += "\n\n"
    else:
        template += "*No open ports discovered.*\n\n"

    template += """## Enumeration



## Exploitation



## Privilege Escalation



## Flags

**User:** `user.txt`  
**Root:** `root.txt`

## Notes



"""
    return template

def create_parser():
    parser = argparse.ArgumentParser(
        prog='pwninit',
        description='A CTF Challenge Template Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-n', '--name', required=True, help='Challenge name')
    parser.add_argument('-ip', '--target-ip', required=True, help='Target IP address')
    parser.add_argument('-d', '--difficulty', required=True, choices=['Easy', 'Medium', 'Hard'], help='Difficulty level')
    parser.add_argument('-os', '--operating-system', required=True, choices=['Linux', 'Windows'], help='Target OS')
    parser.add_argument('-p', '--platform', required=True, choices=['HTB', 'THM'], help='CTF platform')
    parser.add_argument('--no-scan', action='store_true', help='Skip nmap scan')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    try:
        target_ip = validate_ip(args.target_ip)
        project_name = sanitize_name(args.name)
        if not args.quiet:
            print(Config.BANNER)
        project_path = Path.home() / 'CTF' / args.platform / project_name
        if not args.quiet:
            spinner_idx = 0
            start_time = time.time()
            overwrite_line(f"{Colors.CYAN}[{Config.SPINNER_CHARS[spinner_idx]}]{Colors.RESET} Setting up {project_name} ({target_ip})")
        create_directories(project_path)
        if not args.quiet:
            while time.time() - start_time < 1.5:
                spinner_idx = (spinner_idx + 1) % len(Config.SPINNER_CHARS)
                overwrite_line(f"{Colors.CYAN}[{Config.SPINNER_CHARS[spinner_idx]}]{Colors.RESET} Setting up {project_name} ({target_ip})")
                time.sleep(0.1)
            overwrite_line(f"{Colors.GREEN}[+]{Colors.RESET} Initialized: {project_name}")
            print()
        scan_results = []
        if not args.no_scan:
            nmap_output = project_path / 'nmap' / project_name
            xml_path = run_nmap_scan(target_ip, nmap_output, args.quiet)
            if xml_path:
                scan_results = parse_nmap_results(xml_path)
        else:
            log('info', "Skipping network scan", args.quiet)
        template = generate_template(project_name, target_ip, args.platform,
                                     args.difficulty, args.operating_system, scan_results)
        readme_path = project_path / 'README.md'
        readme_path.write_text(template, encoding='utf-8')
        log('success', "Writeup template ready: README.md", args.quiet)
        if args.quiet:
            print(str(project_path))
        else:
            print(f"\n{Colors.GREEN}{Colors.BOLD}Ready to hack {project_name}!{Colors.RESET}")
            print(f"{Colors.CYAN}{project_path}{Colors.RESET}")
    except ValueError as e:
        log('error', str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        log('warning', "Operation cancelled")
        sys.exit(1)
    except Exception as e:
        log('error', f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
