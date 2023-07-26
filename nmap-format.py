import xml.etree.ElementTree as ET
import sys
from tabulate import tabulate
from colorama import init, Fore, Style
import os

init(autoreset=True)  # Initialize colorama to automatically reset color codes

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts = []

    for host in root.findall('host'):
        ip_elem = host.find('address')
        hostname_elem = host.find('hostnames/hostname')
        if ip_elem is None or hostname_elem is None:
            print("Error: Could not find IP address or hostname for a host in the Nmap XML.", file=sys.stderr)
            continue

        ip = ip_elem.attrib.get('addr', '')
        hostname = hostname_elem.attrib.get('name', '')

        services = []

        for port in host.findall('ports/port'):
            port_id = port.attrib.get('portid', '')
            protocol = port.attrib.get('protocol', '')

            state_elem = port.find('state')
            service_elem = port.find('service')

            if state_elem is None or service_elem is None:
                print("Error: Could not find state or service information for a port in the Nmap XML.", file=sys.stderr)
                continue

            state = state_elem.attrib.get('state', 'Unknown')
            service = service_elem.attrib.get('name', 'Unknown')

            services.append(f"{port_id}/{protocol} - {service} ({state})")

        hosts.append([ip, hostname, "\n".join(services)])

    return hosts

def display_tree(hosts):
    for host in hosts:
        ip = Fore.GREEN + host[0] + Style.RESET_ALL
        hostname = Fore.CYAN + host[1] + Style.RESET_ALL
        services = host[2].split('\n')

        print(ip)
        if hostname:
            print(f"└── {hostname}")
        for service in services:
            port_state = service.split('(')[-1][:-1].lower()  # Get the port state (open/closed/filtered) from the service string
            if port_state == "closed":
                service = Fore.RED + service + Style.RESET_ALL  # Apply red color to closed ports
            elif port_state == "filtered":
                service = Fore.YELLOW + service + Style.RESET_ALL  # Apply yellow color to filtered ports
            print(f"    └── {service}")

#def display_tree(hosts):
#    for host in hosts:
#        ip = Fore.GREEN + host[0] + Style.RESET_ALL
#        hostname = Fore.CYAN + host[1] + Style.RESET_ALL
#        services = host[2].split('\n')
#
#        print(ip)
#        if hostname:
#            print(f"└── {hostname}")
#        for service in services:
#            port_state = service.split('(')[-1][:-1].lower()  # Get the port state (open/closed) from the service string
#            if port_state == "closed":
#                service = Fore.RED + service + Style.RESET_ALL  # Apply red color to closed ports
#            print(f"    └── {service}")
            
#def display_tree(hosts):
#    for host in hosts:
#        ip = Fore.GREEN + host[0] + Style.RESET_ALL
#        hostname = Fore.CYAN + host[1] + Style.RESET_ALL
#        services = host[2].split('\n')
#
#        print(ip)
#        if hostname:
#            print(f"└── {hostname}")
#        for service in services:
#            print(f"    └── {service}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <nmap_output_file> [--tree]")
        sys.exit(1)

    xml_file = sys.argv[1]
    try:
        with open(os.devnull, "w") as null_file:
            sys.stderr = null_file  # Redirect stderr to /dev/null
            hosts = parse_nmap_xml(xml_file)
            sys.stderr = sys.__stderr__  # Restore stderr

        if len(sys.argv) >= 3 and sys.argv[2] == "--tree":
            display_tree(hosts)
        else:
            display_table(hosts)

    except Exception as e:
        print("Error parsing XML:", e, file=sys.stderr)
        sys.exit(1)
