import os
import logging
from time import sleep
from itertools import cycle
from threading import Thread


class ChannelsHopper(Thread):
    CHANNELS = 13
    DEFAULT_HOP_INTERVAL = 1  # Seconds

    def __init__(self, interface, hop_interval=DEFAULT_HOP_INTERVAL,
                 debug=False):
        super().__init__()
        self.running = True
        self.interface = interface
        self.hop_interval = hop_interval

        self.logger = logging.getLogger("channels_hopper")

        if debug:
            self.logger.setLevel(logging.DEBUG)

    def hop_channel(self, channel):
        # TODO: LOGGER
        self.logger.info(f"Hopping to channel %s", channel)
        os.system(f"iwconfig {self.interface} channel {channel}")

    def __iter__(self):
        return cycle(range(1, self.CHANNELS))

    def run(self):
        for channel in self:
            if self.running is False:
                return
            self.hop_channel(channel)
            sleep(self.hop_interval)

    def stop(self):
        self.hop_channel("auto")
        self.running = False
