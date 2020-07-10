""" Detect smartphones in classified rooms.

Bamradar is a sniffer that monitors and detects
wifi devices. The tool generates a specific RSSI threshold,
every sniffed packet that has bigger RSSI value
will be alerted.
"""
import os
import signal
import logging
from argparse import ArgumentParser

from scapy.all import sniff
from scapy.layers.dot11 import RadioTap

from hopper import ChannelsHopper

# Change root logging config.
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def enable_monitor_mode(interface):
    """Enable monitor mode using iwconfig tool.

    Args:
        interface (str): Interface name.
    """
    if not interface_exists(interface):
        raise ValueError(f"Interface {interface} is invalid.")
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")


def disable_monitor_mode(interface):
    """Disable monitor mode using iwconfig tool.

    Args:
        interface (str): Interface name.
    """
    if not interface_exists(interface):
        raise ValueError(f"Interface {interface} is invalid.")
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode managed")
    os.system(f"ifconfig {interface} up")


def valid_threshold(threshold):
    return 0 > threshold > -120


def interface_exists(interface):
    return os.path.exists(f"/sys/class/net/{interface}")


class WifiSignalMonitor:
    DEFAULT_THRESHOLD = -30  # dbm

    # TODO: CHECK EVERY INPUT FROM USER !!!!! RAISE
    # TODO: FIX ARPRARSE AND CHECK SIDE EFFECTS
    def __init__(self, interface, threshold=DEFAULT_THRESHOLD,
                 ignored_macs=None, target_macs=None, debug=False):
        self.set_interface(interface)
        self.set_threshold(threshold)
        self.target_macs = target_macs if target_macs is not None else []
        self.ignored_macs = ignored_macs if ignored_macs is not None else []

        self.logger = logging.getLogger("wifi_signal_monitor")
        if debug:
            self.logger.setLevel(logging.DEBUG)

    @property
    def targeting_macs(self):
        return False if self.target_macs == [] else True

    def set_threshold(self, threshold):
        if not valid_threshold(threshold):
            raise ValueError(f"Threshold value {threshold} is invalid.")
        self.threshold = threshold

    def set_interface(self, interface):
        if not interface_exists(interface):
            raise ValueError(f"Interface {interface} is invalid.")
        self.interface = interface

    def process(self, frame):
        source_address = frame.addr2
        channel = frame[RadioTap].Channel
        signal_strength = frame.dBm_AntSignal
        frame_info = (signal_strength, channel, source_address)

        if signal_strength < self.threshold or source_address is None:
            self.logger.debug("%s not in range", frame_info)
            return

        if source_address in self.ignored_macs:
            self.logger.debug("%s ignored", frame_info)
            return

        if source_address is not None:
            if self.targeting_macs:
                if source_address in self.target_macs:
                    self.logger.info(frame_info)
            else:
                self.logger.info(frame_info)

    def start(self):
        sniff(iface=self.interface, prn=self.process, store=False,
              monitor=True)


def setup_argparser():
    # TODO: Open README FILE
    arguments_parser = ArgumentParser(description=__doc__)
    arguments_parser.add_argument(
        "--interface", "-i", type=str, help="Target WIFI interface.",
        required=True)
    arguments_parser.add_argument(
        "--threshold", "-t", type=int, help="RSSI threshold.")
    arguments_parser.add_argument(
        "--channel", "-c", type=int, help="Wifi channel.")
    arguments_parser.add_argument(
        "--ignore", help="Ignore specific MAC.", action="append")
    arguments_parser.add_argument(
        "--target", help="Target specific MAC.", action="append")
    arguments_parser.add_argument('--verbose', '-v', action='count', default=0)
    arguments_parser.add_argument('--calibrate', action='count', default=0)
    arguments_parser.add_argument('--disable_hopping', action='count',
                                  default=0)
    return arguments_parser.parse_args()


if __name__ == '__main__':
    arguments = setup_argparser()
    print(arguments)
    enable_monitor_mode(interface=arguments.interface)
    hopper = ChannelsHopper(interface=arguments.interface,
                            hop_interval=3,
                            debug=bool(arguments.verbose))
    monitor = WifiSignalMonitor(interface=arguments.interface,
                                debug=bool(arguments.verbose),
                                target_macs=arguments.target,
                                ignored_macs=arguments.ignore)

    # TODO: Add disable hopping and channel option.
    # TODO: DOCS

    if bool(arguments.calibrate):
        pass
        # TODO: Calibrate!

    if arguments.threshold is not None:
        monitor.set_threshold(arguments.threshold)


    # TODO: More elegant
    def exit_handler(*args, **kwargs):
        hopper.stop()
        exit(1)


    signal.signal(signal.SIGINT, exit_handler)

    hopper.start()
    monitor.start()
