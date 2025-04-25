from classes.base.Scanner import Scanner


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