from classes.host_discovery.ARPScanner import ARPScanner
from classes.host_discovery.ICMPScanner import ICMPScanner
from classes.port_scan.TCPScanner import TCPScanner
from helpers.gen_const import protocol_map

class ScannerFactory:
    @staticmethod
    def create_scanner(proto, h_retry=1, h_timeout=1, verbose=False, v_verbose=False, live=True, log=False, extra_configs={}, show_only_up=False, reason=False):
        if protocol_map[proto] == "ARP":
            return ARPScanner(h_retry=h_retry, h_timeout=h_timeout, verbose=verbose, v_verbose=v_verbose, live=True, log=log, show_only_up=show_only_up, reason=reason)
        if protocol_map[proto] == "ICMP":
            return ICMPScanner(h_retry=h_retry, h_timeout=h_timeout, verbose=verbose, v_verbose=v_verbose, live=True, log=log, show_only_up=show_only_up, reason=reason)
        if protocol_map[proto] == "TCP":
            return TCPScanner(verbose=verbose, live=True, log=log, extra_configs=extra_configs, show_only_up=show_only_up, reason=reason)
        else:
            raise ValueError(f"Unknown protocol: {proto}")