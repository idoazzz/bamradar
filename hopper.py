"""Channels hopper thread."""
import os
import logging
from time import sleep
from itertools import cycle
from threading import Thread

from utils import interface_exists


class ChannelsHopper(Thread):
    """Hopping different wifi channels on specific interface.

    Attributes:
        running (bool): Thread state.
        interface (str): Network interface.
        hop_interval (int): Hop interval in seconds.
        logger (Logger): Logger object for logging messages.
    """
    CHANNELS = 13
    DEFAULT_HOP_INTERVAL = 1  # Seconds

    def __init__(self, interface, hop_interval=DEFAULT_HOP_INTERVAL,
                 debug=False):
        super().__init__()
        self.daemon = True
        self.running = False
        self.set_interface(interface)
        self.hop_interval = hop_interval
        self.logger = logging.getLogger("channels_hopper")
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

    def hop_channel(self, channel):
        """Hop to given wifi channel using iwconfig tool."""
        self.logger.info("Hopping to channel %s", channel)
        os.system(f"iwconfig {self.interface} channel {channel}")

    def __iter__(self):
        return cycle(range(1, self.CHANNELS))

    def run(self):
        """Hopping channels in a cyclic way."""
        self.running = True
        for channel in self:
            if self.running is False:
                return
            sleep(self.hop_interval)
            self.hop_channel(channel)

    def stop(self):
        """Return to 'auto' channel and stop the thread."""
        self.hop_channel("auto")
        self.running = False
