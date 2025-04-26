import logging
import multiprocessing
import signal
import socket
import sys
import time
import click
from prettytable import PrettyTable
import scapy.all as scapy
from classes.base.Scanner import Scanner


logger = logging.getLogger(__name__)

class HostScanner(Scanner):
    def __init__(self, h_retry=1, h_timeout=1, verbose=False, v_verbose=False, live=True, log=False, extra_configs={}, show_only_up=False, reason=False):
        self.h_retry = h_retry 
        self.h_timeout = h_timeout
        self.verbose = verbose
        self.v_verbose = v_verbose
        self.live = live
        self.log = log
        self.extra_configs = extra_configs
        self.show_only_up = show_only_up
        self.reason = reason
        self.stop = False
        self.up_hosts = []

    def scan(self, iprange):
        raise NotImplementedError("This method should be overridden by subclasses.")
    
    def do_traceroute(self, target, max_hops=30, timeout=1):
        signal.signal(signal.SIGINT, self.handle_interrupt)
        
        ttl = 1
        traceroute_data = []

        while ttl < max_hops:
            if self.stop:
                break
            packet = scapy.IP(dst=target, ttl=ttl) / scapy.ICMP()

            start_time = time.time()
            try:
                reply = scapy.sr1(packet, timeout=timeout, verbose=False)
            except KeyboardInterrupt:
                sys.exit(0)
            end_time = time.time()

            if reply is None:
                traceroute_data.append({"hop": ttl, "rtt": "* * *", "address": "* * *"})
            else:
                hop_ip = reply.src
                rtt = (end_time - start_time) * 1000 # ms

                hop_name = self.get_host_name_async(hop_ip)

                addr_str = str(hop_ip) + f" ({hop_name})" if hop_name != str(hop_ip) else str(hop_ip)

                if reply.haslayer(scapy.ICMP):
                    icmp_type = reply.getlayer(scapy.ICMP).type
                    if icmp_type == 0:  # ICMP Echo Reply (destination reached)
                        traceroute_data.append({"hop": ttl, "rtt": str(round(rtt, 2)) + " ms", "address": addr_str})
                        break
                    elif icmp_type == 11:  # ICMP Time Exceeded (router hop)
                        traceroute_data.append({"hop": ttl, "rtt": str(round(rtt, 2)) + " ms", "address": addr_str})
                    elif icmp_type == 3:  # ICMP Destination Unreachable
                        pass
            
            ttl += 1

        return traceroute_data
    
    def get_host_by_addr(self,hop_ip):
        try:
            hop_name = socket.gethostbyaddr(hop_ip)[0]
            return hop_name
        except (socket.herror, socket.gaierror):
            return hop_ip
    
    def get_host_name_async(self, ip_address):
        with multiprocessing.Pool(processes=1) as pool:
            try:
                result = pool.apply_async(self.get_host_by_addr, (ip_address, ))
                return result.get(timeout=2)
            except multiprocessing.context.TimeoutError:
                return ip_address

    def print_traceroute_table(self, ip, traceroute_data):
        try:
            t = PrettyTable(["Hop", "Rtt", "Address"])

            for entry in traceroute_data:
                    if self.stop:
                        break
                    t.add_row([str(entry["hop"]), str(entry["rtt"]), str(entry["address"])])
            if not self.stop:
                if self.live:
                    click.echo(f"\n[>] Traceroute to {ip}")
                    click.echo(t)
                if self.log:
                    logger.info(f"\n[>] Traceroute to {ip}")
                    logger.info(t)
        except KeyboardInterrupt:
            sys.exit(0)