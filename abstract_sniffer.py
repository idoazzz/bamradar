from utils import interface_exists


class AbstractSniffer:
    """Abstract wifi sniffer.

    Attributes:
        timeout (int): Sniffer timeout.
        interface (str): Network interface.
        debug (bool): Printing in debug mode.
        logger (Logger): Logger object for logging messages.
    """
    def __init__(self, interface, debug=False, timeout=None):
        self.timeout = timeout
        self.set_interface(interface)
        self.logger = logging.getLogger("wifi_signal_monitor")
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def set_interface(self, interface):
        """Set and validate new network interface.

        Args:
            interface (str): Network interface.

        Raises:
            ValueError. Interface is not exist.
        """
        if not interface_exists(interface):
            raise ValueError(f"Interface {interface} is invalid.")
        self.interface = interface

    @abstractmethod
    def process(self, frame):
        """Processing method.

        Args:
            frame (RadioTap): Sniffed radio tap frame.
        """
        pass

    def start(self):
        """Starting the sniffer."""
        self.logger.info("Starting sniffing on %s", self.interface)
        sniff(iface=self.interface, prn=self.process, store=False,
              monitor=True, timeout=self.timeout)