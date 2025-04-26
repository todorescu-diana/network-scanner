from datetime import datetime
import ipaddress
from pathlib import Path
import logging
import re
import socket
import psutil
from helpers.gen_const import most_common_20_tcp_ports

def init_logging(ip):
    ip = ip.replace("/", "_")
    now = datetime.now()
    current_datetime = now.strftime("%d-%m-%Y_%H-%M-%S")
    logfile_name = f"./logs/{ip}_{current_datetime}.log"

    folder = Path("./logs")
    folder.mkdir(parents=True, exist_ok=True) 

    logging.basicConfig(filename=logfile_name, level=logging.INFO, format="%(message)s")

def check_ip_address_validity(ip):
    pattern = re.compile(r'''
        ^
        (
            (25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\. # 250 - 255 | 200 - 249 | 100 - 199 | 0 - 99
            (25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.
            (25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.
            (25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)     
        )             
        $
    ''', re.VERBOSE)

    return bool(pattern.match(ip))

def check_ip_range_cidr_validity(ip):
    pattern = re.compile(r'''
        ^
        (
            (25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\. # 250 - 255 | 200 - 249 | 100 - 199 | 0 - 99
            (25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.
            (25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.
            (25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)        
        )
        /
        (
            [0-9]|[1-2][0-9]|3[0-2]              # 0 - 32 
        )                
        $
    ''', re.VERBOSE)

    return bool(pattern.match(ip))

def check_hostname_validity(hostname):
    pattern = re.compile(r'''
        ^
        (?=.{1,253}$)                  # total length 1 to 253 characters
        (                             
            ([a-zA-Z0-9]               # start with alphanumeric
            ([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])? # middle part: alphanumeric or hyphens, but cannot start/end with hyphen
            \.)+                       # dot separator
            [a-zA-Z]{2,63}             # TLD (like com, org, etc.)
        )
        $
    ''', re.VERBOSE)

    return bool(pattern.match(hostname))

def check_hostname_range_validity(hostname):
    pattern = re.compile(r'''
        ^
        (?=.{1,253}$)                        # total length 1 to 253 characters
        (                                   
            ([a-zA-Z0-9]                     # start with alphanumeric
            ([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])? # middle part: alphanumeric or hyphens, but not starting/ending with hyphen
            \.)+                             # dot separator
            [a-zA-Z]{2,63}                   # TLD (like com, org, etc.)
        )
        (                                     # optional CIDR part
            /
            ([0-9]|[1-2][0-9]|3[0-2])      # /0 to /32
        )
        $
    ''', re.VERBOSE)

    return bool(pattern.match(hostname))

def check_ip_octet_range_address_validity(ip):
    # check format
    pattern = re.compile(r'''
        ^
        (
            (?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)
            (?:-(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))?
            \.
            (?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)
            (?:-(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))?
            \.
            (?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)
            (?:-(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))?
            \.
            (?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)
            (?:-(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))?
        )
        $
    ''', re.VERBOSE)

    if not pattern.match(ip):
        return False

    # check logic
    octets = ip.split('.')
    for octet in octets:
        if '-' in octet:
            start, end = octet.split('-')
            if int(start) > int(end):
                return False

    return True

def check_ports_format(ports):
    if ports == "":
        return True
    pattern = r'(\d+(-\d+)?)(,\d+(-\d+)?)*$'
    return bool(re.match(pattern, ports))

def get_tcp_extra_configs(proto, ports):
    extra_configs = {}
    extra_configs["type"] = proto.split("-")[1]
    if ports == "":  # no config given
        extra_configs["ports"] = most_common_20_tcp_ports
    elif "," in ports and "-" not in ports:    # <port_no1>,<port_no2>,...,<port_non>
        extra_configs["ports"] = [int(p) for p in ports.split(",")]
    elif "-" in ports and "," not in ports:  # <port_no1>-<port_no2>
        start, end = map(int, ports.split("-"))
        extra_configs["ports"] = list(range(start, end+1))
    elif "-" in ports and "," in ports:     # <port_no1>-<port_no2>,<port_no3>,<port_no4>-<port_no5>
        p_nos = []
        parts = ports.split(",")

        for part in parts:
            if "-" in part:
                start, end = map(int, part.split("-"))
                if start > end:
                    raise ValueError(f"Invalid range: {part}")
                p_nos.extend(range(start, end+1))
            else:
                p_nos.append(int(part))

        extra_configs["ports"] = p_nos
    else:
        extra_configs["ports"] = [int(ports)]   # <port_no>

    return extra_configs

def get_local_networks():
    local_networks = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.netmask:
                network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                local_networks.append(network)

    return local_networks

def check_if_ip_in_LAN(ip):
    l_n = get_local_networks()
    if "-" not in ip:
        if "/" not in ip:
            obj = ipaddress.ip_address(ip)
            return any(obj in net for net in l_n)
        else:
            obj = ipaddress.IPv4Network(ip, strict=False)
            return obj in l_n
    else:
        ip_addr_list = get_ip_addr_list_from_octet_ranges(ip)
        first_addr = ip_addr_list[0]
        return any(first_addr in net for net in l_n)

def get_ip_addr_list_from_octet_ranges(target):
    octets = target.split(".")
    ip_addr_list = []
    ranges = []

    for octet in octets:
        if "-" in octet:
            start, end = map(int, octet.split("-"))
            if start == 0:
                start = 1
            ranges.append(range(start, end+1))
        else:
            value = int(octet)
            ranges.append([value])

    for o1 in ranges[0]:
        for o2 in ranges[1]:
            for o3 in ranges[2]:
                for o4 in ranges[3]:
                    ip_addr_list.append(ipaddress.ip_address(f"{o1}.{o2}.{o3}.{o4}"))

    return ip_addr_list

def resolve_target(target):
    if "/" not in target:
        try:
            ip_obj = ipaddress.ip_address(target)
            return str(ip_obj)
        except ValueError:
            resolved_ip = socket.gethostbyname(target)
            return resolved_ip
        except socket.gaierror:
            print(f"[!] Could not resolve hostname: {target}")
            return None
    else:
        try:
            hostname, cidr = target.split("/")
            resolved_ip = socket.gethostbyname(hostname)
            return f"{resolved_ip}/{cidr}"
        except (ValueError, socket.gaierror):
            print(f"[!] Could not resolve hostname or invalid format: {target}")
            return None