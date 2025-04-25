class Scanner:
    def __init__(self, verbose=False, live=True, log=False, extra_configs={}, show_only_up=False, reason=False):
        self.verbose = verbose
        self.live = live
        self.log = log
        self.extra_configs = extra_configs
        self.show_only_up = show_only_up
        self.reason = reason
        self.stop = False

    def scan(self, iprange):
        raise NotImplementedError("This method should be overridden by subclasses.")