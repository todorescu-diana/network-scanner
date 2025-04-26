from ipaddress import ip_network
import signal
import sys
from venv import logger
import click
import scapy.all as scapy
from classes.base.HostScanner import HostScanner

class ARPScanner(HostScanner):
    def scan(self, ip):
        signal.signal(signal.SIGINT, self.handle_interrupt)
        
        if "/" not in ip:
            if self.verbose:
                self.print_info_checking(ip)
            self.do_arp_scan(ip)
        else:
            for ip_addr in ip_network(ip).hosts():
                if self.stop:
                    break
                ip_addr_str = str(ip_addr)
                if self.verbose:
                    self.print_info_checking(ip_addr_str)
                self.do_arp_scan(ip_addr_str)

    def do_arp_scan(self, ip_addr):
        arp_req = scapy.ARP(pdst=ip_addr)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        
        try:
            packet = ether/arp_req
            for i in range(self.h_retry):
                if self.v_verbose:
                    if self.live:
                        click.echo(f"\tTry number {i+1}...")
                    if self.log:
                        logger.info(f"\tTry number {i+1}...")
                response = scapy.srp(packet, timeout=self.h_timeout, verbose=False)[0]
                if response: 
                    break
        except KeyboardInterrupt:
            sys.exit(0)

        if response:
            if self.live:
                click.echo(f"[!] Host {ip_addr} is up.")
            if self.log:
                logger.info(f"[!] Host {ip_addr} is up.")

            self.up_hosts.append(ip_addr)

        else:
            if self.show_only_up is False:
                if self.live:
                    click.echo(f"Host {ip_addr} is down or not responding.")
                if self.log:
                    logger.info(f"Host {ip_addr} is down or not responding.")

    def print_info_checking(self, ip_addr):
        if self.live:
            click.echo(f"-> Checking {ip_addr}...")
        if self.log:
            logger.info(f"-> Checking {ip_addr}...")

    def get_up_hosts(self):
        return self.up_hosts
