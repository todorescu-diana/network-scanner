import logging
import signal
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from ipaddress import ip_network
import click
import scapy.all as scapy
from classes.base.HostScanner import HostScanner

logger = logging.getLogger(__name__)

class ICMPScanner(HostScanner):     
    def scan(self, ip):
        signal.signal(signal.SIGINT, self.handle_interrupt)
        
        if "/" not in ip:
            if self.verbose:
                self.print_info_checking(ip)
            self.do_icmp_echo_req_scan(ip)
        else:
            for ip_addr in ip_network(ip).hosts():
                if self.stop:
                    break
                ip_addr_str = str(ip_addr)
                if self.verbose:
                    self.print_info_checking(ip_addr_str)
                self.do_icmp_echo_req_scan(ip_addr_str)

        
    def do_icmp_echo_req_scan(self, ip_addr):
        ip_pkt = scapy.IP(dst=ip_addr)
        icmp_pkt = scapy.ICMP(type=8)  # echo request

        try:
            packet = ip_pkt / icmp_pkt
            for _ in range(self.h_retry):
                response = scapy.sr1(packet, timeout=self.h_timeout, verbose=0)
                if response: 
                    break
        except KeyboardInterrupt:
            sys.exit(0)

        if response and response.type == 0: # echo reply
            self.print_info_up(ip_addr)
            self.up_hosts.append(ip_addr)
        else:
            if self.show_only_up is False:
                self.print_info_down(ip_addr)

    def do_icmp_timestamp_req_scan(self, ip_addr):
        ip_pkt = scapy.IP(dst=ip_addr)
        icmp_pkt = scapy.ICMP(type=13)  # timestamp request

        packet = ip_pkt / icmp_pkt
        for _ in range(self.h_retry):
            response = scapy.sr1(packet, timeout=self.h_timeout, verbose=0)
            if response:
                break

        if response and response.type == 14: # timestamp reply
            self.print_info_up(ip_addr)

        else:
            if self.verbose is True and self.show_only_up is False:
                self.print_info_down(ip_addr)

    def print_info_checking(self, ip_addr):
        if self.live:
            click.echo(f"-> Checking {ip_addr}...")
        if self.log:
            logger.info(f"-> Checking {ip_addr}...")
    
    def print_info_up(self, ip_addr):
        if self.live:
            click.echo(f"[!] \t{ip_addr} is up.")
        if self.log:
            logger.info(f"[!] \t{ip_addr} is up.")

    def print_info_down(self, ip_addr):
        if self.live:
            click.echo(f"[!] \t{ip_addr} is down or not responding.")
        if self.log:
            logger.info(f"[!] \t{ip_addr} is down or not responding.")

    def get_up_hosts(self):
        return self.up_hosts