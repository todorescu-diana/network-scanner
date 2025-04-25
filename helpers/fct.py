import datetime
import ipaddress
from pathlib import Path
import logging
import re
import socket
import psutil
from helpers.gen_const import most_common_20_tcp_ports

def init_logging(ip):
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
    if "/" not in ip:
        obj = ipaddress.ip_address(ip)
        return any(obj in net for net in l_n)
    else:
        obj = ipaddress.IPv4Network(ip, strict=False)
        return obj in l_n
