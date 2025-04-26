from ipaddress import ip_network
import logging
import signal
import click
from scapy.all import *
from classes.base.ScannerFactory import ScannerFactory
from helpers.fct import check_if_ip_in_LAN, check_ip_address_validity, check_ip_range_cidr_validity, check_ports_format, get_tcp_extra_configs, init_logging
from helpers.gen_const import valid_modes, valid_protocols

logger = logging.getLogger(__name__)

valid_modes_str = " / ".join(valid_modes)
valid_protocols_str = " / ".join(valid_protocols)

@click.command()
@click.option("--ip", default="", help="IP address or IP range to scan; Valid formats: <IP address> OR <IP address>/<prefix length>")
@click.option("--h_retry", default=1, help="Number of times to retry to send host discovery probe. DEFAULT: 1")
@click.option("--h_timeout", default=1, help="Time in seconds to wait for response to host discovery probe being sent. DEFAULT: 1")
@click.option("--h_skip/--no-h_skip", default=False, help="Skip host discovery. Treat all hosts as online and do port scan. DEFAULT: --no-h_skip")
@click.option("--traceroute/--no-traceroute", default=False, help="Perform traceroute to show hop path to target host(s). DEFAULT: --no-traceroute")
@click.option("--proto", default=f"{valid_protocols[0]}", help=f"Protocol to use for port scanning; Options: {valid_protocols_str}; DEFAULT: {valid_protocols[0]}")
@click.option("--ports", default="", help="Port(s) or range of ports to scan. Valid formats: <port_no> OR <port_no1>,<port_no2>,...,<port_non> OR <port_no1>-<port_no2> OR <port_no1>-<port_no2>,<port_no3>,<port_no4>-<port_no5>; DEFAULT: 20 most common TCP ports")
@click.option("--mode", default=f"{valid_modes[2]}", help=f"Mode of operation; Options: {valid_modes_str}; DEFAULT: {valid_modes[2]}")
@click.option("--show_only_up/--no_show_only_up", default=True, help="Only show hosts that are up; DEFAULT: --show_only_up")
@click.option("--verbose/--no-verbose", default=False, help="Increase verbosity; DEFAULT: --no-verbose")
@click.option("--v_verbose/--no-v_verbose", default=False, help="Increase verbosity even more; DEFAULT: --no-v_verbose")
@click.option("--reason/--no-reason", default=False, help="Show reason for result; DEFAULT: --no-reason")
def main(ip, h_retry, h_timeout, h_skip, traceroute, proto, ports, mode, show_only_up, verbose, v_verbose, reason):
    try:
        if check_ip_address_validity(ip) is False and check_ip_range_cidr_validity(ip) is False:
            click.echo(f"[!] Invalid IP address or range '{ip}'; Valid formats: <IP address> OR <IP address>/<prefix length>")
            exit(0)
        if check_ports_format(ports) is False:
            click.echo(f"[!] Invalid ports format; Valid formats: <port_no> OR <port_no1>,<port_no2>,...,<port_non> OR <port_no1>-<port_no2> OR <port_no1>-<port_no2>,<port_no3>,<port_no4>-<port_no5>")
            exit(0)
        if mode not in valid_modes:
            click.echo(f"[!] Invalid mode '{mode}'; Valid modes: {valid_modes_str}")
            exit(0)
        if proto not in valid_protocols:
            click.echo(f"[!] Invalid protocol '{proto}'; Valid protocols: {valid_protocols_str}")
            exit(0)

        if v_verbose and not verbose:
            verbose = True

        do_log = mode == valid_modes[0] or mode == valid_modes[1]
        do_live = mode == valid_modes[1] or mode == valid_modes[2]

        if not h_skip:
            is_in_LAN = check_if_ip_in_LAN(ip)
            
            # host discovery
            if is_in_LAN:
                scanner = ScannerFactory.create_scanner("arp", h_retry, h_timeout, verbose=verbose, v_verbose=v_verbose, live=do_live, log=do_log, show_only_up=show_only_up, reason=reason)
            else:
                scanner = ScannerFactory.create_scanner("icmp", h_retry, h_timeout, verbose=verbose, v_verbose=v_verbose, live=do_live, log=do_log, show_only_up=show_only_up, reason=reason)

            if do_log:
                init_logging(ip)

                if verbose:
                    logger.info("[-] Started log\n")

            else:
                if verbose:
                    click.echo("[-] Started log\n")

            scanner.scan(ip)

            up_hosts = scanner.get_up_hosts()
        
            if scanner.stop:
                exit(0)

        else:
            if "/" not in ip:
                up_hosts = [ip]
            else:
                up_hosts = [str(ip_addr) for ip_addr in ip_network(ip).hosts()]

        if traceroute:
            for ip_addr in up_hosts:
                if scanner.stop:
                    exit(0)
                if verbose:
                    if do_live:
                        click.echo(f"\n-> Tracing route to {ip_addr}...")
                    if do_log:
                        logger.info(f"\n-> Tracing route to {ip_addr}...")
                traceroute_data = scanner.do_traceroute(ip_addr)
                scanner.print_traceroute_table(ip_addr, traceroute_data)


        # port scanning
        extra_configs = {}
        if proto.split("-")[0] == "tcp":
            extra_configs = get_tcp_extra_configs(proto, ports)
            scanner = ScannerFactory.create_scanner("tcp", verbose=verbose, live=do_live, log=do_log, extra_configs=extra_configs, show_only_up=show_only_up)
            for ip in up_hosts:
                if scanner.stop:
                    exit(0)
                scanner.scan(ip)

        # end
        if verbose:
            if do_log:
                logger.info("\n[-] Succesfully stopped log")
            else:
                click.echo("\n[-] Succesfully stopped log")
        
    except Exception as e:
        click.echo(f"[!] Exited with error: {e}")
    except KeyboardInterrupt:
        exit(0)
    finally:
        click.echo("[:)] Goodbye.")

if __name__ == "__main__":
    main()