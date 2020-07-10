""" Detect smartphones in classified rooms.

Bamradar is a sniffer that monitors and detects
wifi devices. The tool generates a specific RSSI threshold,
every sniffed packet that has bigger RSSI value
will be alerted.
"""
import os
import logging
from abc import abstractmethod
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


class AbstractSniffer:
    def __init__(self, interface, debug=False, timeout=None):
        self.set_interface(interface)
        self.timeout = timeout
        self.logger = logging.getLogger("wifi_signal_monitor")
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def set_interface(self, interface):
        if not interface_exists(interface):
            raise ValueError(f"Interface {interface} is invalid.")
        self.interface = interface

    @abstractmethod
    def process(self, frame):
        pass

    def start(self):
        self.logger.info("Starting sniffing on %s", self.interface)
        sniff(iface=self.interface, prn=self.process, store=False,
              monitor=True, timeout=self.timeout)


class WifiSignalSniffer(AbstractSniffer):
    DEFAULT_THRESHOLD = -30  # dbm

    def __init__(self, interface, debug=False, timeout=None, target_macs=None,
                 ignored_macs=None, threshold=DEFAULT_THRESHOLD):
        super().__init__(interface, debug, timeout)
        self.set_threshold(threshold)
        self.target_macs = target_macs if target_macs is not None else []
        self.ignored_macs = ignored_macs if ignored_macs is not None else []

    def set_threshold(self, threshold):
        if not valid_threshold(threshold):
            raise ValueError(f"Threshold value {threshold} is invalid.")
        self.threshold = threshold

    def process(self, frame):
        source_address = frame.addr2
        channel = frame[RadioTap].Channel
        signal_strength = frame.dBm_AntSignal
        frame_info = (signal_strength, channel, source_address)

        if source_address is None:
            return

        if signal_strength < self.threshold:
            self.logger.debug("%s not in range", frame_info)
            return

        if source_address in self.ignored_macs:
            self.logger.debug("%s ignored", frame_info)
            return

        if not self.target_macs == []:
            if source_address in self.target_macs:
                self.logger.info(frame_info)
        else:
            self.logger.info(frame_info)


class CalibrationMonitor(AbstractSniffer):

    def __init__(self, interface, debug=False, timeout=None, target_macs=None):
        super().__init__(interface, debug, timeout)
        self.target_macs = target_macs if target_macs is not None else []
        self.captured_signals = []

    @property
    def rssi_threshold(self):
        return min(self.captured_signals) * 0.7

    def process(self, frame):
        source_address = frame.addr2
        signal_strength = frame.dBm_AntSignal

        if source_address is None:
            return

        if not self.target_macs == []:
            if source_address in self.target_macs:
                self.logger.debug((source_address, signal_strength))
                self.captured_signals.append(signal_strength)
        else:
            self.logger.debug((source_address, signal_strength))
            self.captured_signals.append(signal_strength)


def setup_argparser():
    arguments_parser = ArgumentParser(description=__doc__)
    arguments_parser.add_argument(
        "--interface", "-i", type=str, help="Target WIFI interface.",
        required=True)
    arguments_parser.add_argument(
        "--threshold", "-t", type=int, help="RSSI threshold.")
    arguments_parser.add_argument(
        "--channel", "-c", type=int, help="Wifi channel.")
    arguments_parser.add_argument(
        "--timeout", type=int, help="Monitor timeout.", default=None)
    arguments_parser.add_argument(
        "--hop_interval", type=int, help="Channel hopping interval in "
                                         "seconds.", default=3)
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
    enable_monitor_mode(interface=arguments.interface)
    hopper = ChannelsHopper(interface=arguments.interface,
                            hop_interval=arguments.hop_interval,
                            debug=bool(arguments.verbose))
    if arguments.channel is not None:
        hopper.hop_channel(arguments.channel)

    elif not bool(arguments.disable_hopping):
        hopper.start()

    # TODO: DOCS

    if bool(arguments.calibrate):
        calibration_monitor = CalibrationMonitor(interface=arguments.interface,
                                                 debug=bool(arguments.verbose),
                                                 target_macs=arguments.target,
                                                 timeout=arguments.timeout)
        calibration_monitor.start()
        print(f"Generated threshold: {calibration_monitor.rssi_threshold}")

    else:
        monitor = WifiSignalSniffer(interface=arguments.interface,
                                    debug=bool(arguments.verbose),
                                    target_macs=arguments.target,
                                    ignored_macs=arguments.ignore,
                                    timeout=arguments.timeout)

        if arguments.threshold is not None:
            monitor.set_threshold(arguments.threshold)

        # Setup stage
        monitor.start()

    # Teardown stage
    if hopper.running:
        hopper.stop()
