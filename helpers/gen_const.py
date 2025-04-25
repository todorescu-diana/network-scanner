valid_modes = ["only-log", "log-live", "live"]
valid_protocols = ["tcp-syn", "tcp-connect", "tcp-fin", "tcp-null", "tcp-xmas",]

protocol_map = {
    "arp": "ARP",
    "icmp": "ICMP",
    "tcp": "TCP",
    "tcp-syn": "TCP",
    "tcp-connect": "TCP",
    "tcp-fin": "TCP",
    "tcp-null": "TCP", 
    "tcp-xmas": "TCP"
}

# according to nmap website

most_common_20_tcp_ports = [
    80, # http
    23, # telnet
    443, # https,
    21, # ftp
    22, # ssh
    25, # smtp
    3389, # ms-term-server
    110, # pop3
    445, # microsoft-ds
    139, # netbios-ssn
    143, # imap
    53, # domain
    135, # msrpc
    3306, # mysql
    8080, # http proxy
    1723, # pptp
    111, # rpcbind
    995, # pop3s
    993, # imaps
    5900 # vnc
]