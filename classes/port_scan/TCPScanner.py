from ipaddress import ip_network
import logging
import signal
import socket
import sys

from prettytable import PrettyTable
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import click
import scapy.all as scapy
from classes.base.Scanner import Scanner

logger = logging.getLogger(__name__)

class TCPScanner(Scanner):
    def handle_interrupt(self, signum, frame):
        print("\n[*] Ctrl+C detected. Stopping scan.")
        self.stop = True

    def scan(self, ip):
        signal.signal(signal.SIGINT, self.handle_interrupt)
        
        if "type" in self.extra_configs.keys():
            if self.extra_configs["type"] == "syn":
                if "/" not in ip:
                    o, c, f = self.do_syn_scan(ip)

                    categories = {
                        "open": o,
                        "closed": c,
                        "filtered": f
                    }
                    self.print_table(ip, categories)
                else:
                    for ip in ip_network(ip).hosts():
                        if self.stop:
                            break
                        ip_str = str(ip)
                        o, c, f = self.do_syn_scan(ip_str)

                        categories = {
                        "open": o,
                        "closed": c,
                        "filtered": f
                        }
                        self.print_table(ip, categories)
            elif self.extra_configs["type"] == "connect":
                if "/" not in ip:
                    o, c, f = self.do_connect_scan(ip)

                    categories = {
                        "open": o,
                        "closed": c,
                        "filtered": f
                    }
                    self.print_table(ip, categories)
                else:
                    for ip in ip_network(ip).hosts():
                        if self.stop:
                            break
                        ip_str = str(ip)
                        o, c, f = self.do_connect_scan(ip_str)

                        categories = {
                        "open": o,
                        "closed": c,
                        "filtered": f
                        }
                        self.print_table(ip, categories)
            elif self.extra_configs["type"] == "fin" or self.extra_configs["type"] == "null" or self.extra_configs["type"] == "xmas":
                if "/" not in ip:
                    o_f, c = self.do_fin_null_xmas_scan(ip, type=self.extra_configs["type"])

                    categories = {
                        "open|filtered": o_f,
                        "closed": c,
                    }
                    self.print_table(ip, categories)
                else:
                    for ip in ip_network(ip).hosts():
                        if self.stop:
                            break
                        ip_str = str(ip)
                        o_f, c = self.do_fin_null_xmas_scan(ip, type=self.extra_configs["type"])

                        categories = {
                        "open|filtered": o_f,
                        "closed": c,
                        }
                        self.print_table(ip, categories)

    def do_syn_scan(self, ip_addr):
        self.print_info_scanning(ip_addr)
        
        open_p = []
        closed_p = []
        filtered_p = []

        try:
            if "ports" in self.extra_configs.keys():
                for p in self.extra_configs['ports']:
                    if self.stop:
                        break
                    if self.verbose:
                        self.print_info_checking(ip_addr, t="SYN", p=p)

                    packet = scapy.IP(dst=ip_addr) / scapy.TCP(dport=p, flags="S")
                    response = scapy.sr1(packet, timeout=1, verbose=0)

                    if response and response.haslayer(scapy.TCP):
                        flags = response.getlayer(scapy.TCP).flags
                        if flags == 0x12:  # SYN-ACK
                            if self.reason is True:
                                self.print_info_open_syn(p)
                            open_p.append(p)

                            try:
                                rst = scapy.IP(dst=ip_addr)/scapy.TCP(dport=p, flags='R')
                                scapy.sr1(rst, timeout=1, verbose=0)
                            except KeyboardInterrupt:
                                sys.exit(0)
                        elif flags == 0x14:  # RST-ACK
                            if self.reason is True and self.show_only_up is False:
                                self.print_info_closed_syn(p)
                            closed_p.append(p)
                        '''
                        else:
                            if self.verbose is True and self.show_only_up is False:
                                self.print_info_filtered(p)
                            filtered_p.append(p)
                        '''
                    else:
                        if self.reason is True and self.verbose is True and self.show_only_up is False:
                            self.print_info_filtered(p)
                        filtered_p.append(p)

        except KeyboardInterrupt:
            sys.exit(0)

        return open_p, closed_p, filtered_p

    def do_connect_scan(self, ip_addr):
        self.print_info_scanning(ip_addr)
        
        open_p = []
        closed_p = []
        filtered_p = []

        try:
            if "ports" in self.extra_configs.keys():
                for p in self.extra_configs['ports']:
                    if self.stop:
                        break
                    if self.verbose:
                        self.print_info_checking(ip_addr, t="Connect", p=p)

                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        sock.connect((ip_addr, p))
                        if self.reason is True:
                            self.print_info_open_connect(p)
                        open_p.append(p)
                    except Exception as e:
                        if "did not properly respond after a period of time" in str(e):
                            if self.reason is True and self.verbose is True and self.show_only_up is False:
                                self.print_info_filtered(p)
                            filtered_p.append(p)
                        elif "actively refused" in str(e):
                            if self.reason is True:
                                self.print_info_closed_connect(p)
                            closed_p.append(p)
                    finally:
                        sock.close()

        except KeyboardInterrupt:
            sys.exit(0)

        return open_p, closed_p, filtered_p

    def do_fin_null_xmas_scan(self, ip_addr, type):
        self.print_info_scanning(ip_addr)

        flags = ""
        if type == "fin":
            flags = "F"
        elif type == "null":
            flags = 0
        elif type == "xmas":
            flags = 0x29

        open_or_filtered_p = []
        closed_p = []

        try:
            if "ports" in self.extra_configs.keys():
                for p in self.extra_configs['ports']:
                    if self.stop:
                        break
                    if self.verbose:
                        self.print_info_checking(ip_addr, t="FIN", p=p)

                    try:
                        packet = scapy.IP(dst=ip_addr) / scapy.TCP(dport=p, flags=flags)
                        response = scapy.sr1(packet, timeout=1, verbose=0)
                    except KeyboardInterrupt:
                        sys.exit(0)

                    if response and response.haslayer(scapy.TCP):
                        flags = response.getlayer(scapy.TCP).flags
                        if flags == "R" or flags == "RA":
                            if self.reason is True:
                                self.print_info_closed_fnx(ip_addr, p)
                            closed_p.append(p)
                            try:
                                rst = scapy.IP(dst=ip_addr)/scapy.TCP(dport=p, flags='R')
                                scapy.sr1(rst, timeout=1, verbose=0)
                            except KeyboardInterrupt:
                                sys.exit(0)
                        else:
                            if self.reason is True and self.verbose is True and self.show_only_up is False:
                                self.print_info_unexpected_fnx(ip_addr, p)
                    else:
                        if self.reason is True:
                            self.print_info_no_response_fnx(ip_addr, p)
                        open_or_filtered_p.append(p)

        except KeyboardInterrupt:
            sys.exit(0)

        return open_or_filtered_p, closed_p

    def print_info_scanning(self, ip_addr):
        if self.live and self.verbose:
            click.echo(f"Port scanning host {ip_addr}...")
        if self.log and self.verbose:
            logger.info(f"Port scanning host {ip_addr}...")

    def print_info_checking(self, ip_addr, t, p):
        if self.live:
            click.echo(f"\tTrying TCP {t} Scan on host {ip_addr} on port {p}...")
        if self.log:
            logger.info(f"\tTrying TCP {t} Scan on host {ip_addr} on port {p}...")

    def print_info_open_syn(self, p):
        if self.live:
            click.echo(f"\t\t[!] Port {p} is open (SYN-ACK received).")
        if self.log:
            logger.info(f"\t\t[!] Port {p} is open (SYN-ACK received).")

    def print_info_closed_syn(self, p):
        if self.live:
            click.echo(f"\t\tPort {p} is closed (RST-ACK received).")
        if self.log:
            logger.linfoog(f"\t\tPort {p} is closed (RST-ACK received).")

    def print_info_filtered(self, p):
        if self.live:
            click.echo(f"\t\tPort {p} is filtered (did not respond).")
        if self.log:
            logger.info(f"\t\tPort {p} is filtered (did not respond).")

    def print_info_open_connect(self, p):
        if self.live:
            click.echo(f"\t\t[!] Port {p} is open (succesful TCP 3-way Hansdshake).")
        if self.log:
            logger.info(f"\t\t[!] Port {p} is open (succesful TCP 3-way Hansdshake).")

    def print_info_closed_connect(self, p):
        if self.live:
            click.echo(f"\t\t[!] Port {p} is open.")
        if self.log:
            logger.info(f"\t\t[!] Port {p} is open.")

    def print_info_closed_fnx(self, p):
        if self.live:
            click.echo(f"\t\tPort {p} is closed (RST received).")
        if self.log:
            logger.info(f"\t\tPort {p} is closed (RST received).")
    
    def print_info_unexpected_fnx(self, p):
        if self.live:
            click.echo(f"\t\tUnexpected response - can't determine state of port {p}.")
        if self.log:
            logger.info(f"\t\tUnexpected response - can't determine state of port {p}.")

    def print_info_no_response_fnx(self, p):
        if self.live:
            click.echo(f"\t\tNo response. Port {p} is open or filtered.")
        if self.log:
            logger.info(f"\t\tNo response. Port {p} is open or filtered.")

    def print_table(self, ip, categories):
        t = PrettyTable(["Port", "State"])
        
        for key, category in zip(categories.keys(), categories.values()):
            for port in category:
                t.add_row([str(port), key])
        if self.live:
            click.echo(f"\n[>] {ip}")
            click.echo(t)
        if self.log:
            logger.info(f"\n[>] {ip}")
            logger.info(t)
