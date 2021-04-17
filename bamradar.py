"""Detect smartphones in classified rooms.

Bamradar is a sniffer that monitors and detects
wifi devices. The tool generates a specific RSSI threshold,
every sniffed packet that has bigger RSSI value
will be alerted. Quick start and guide: https://github.com/idoazzz/bamradar
"""
import logging
from subprocess import Popen
from abc import abstractmethod
from argparse import ArgumentParser

from scapy.all import sniff
from scapy.layers.dot11 import RadioTap

from abstract_sniffer import AbstractSniffer
from hopper import ChannelsHopper

# Change root logging config.
from sniffers import WifiSignalSniffer, ThresholdGenerator
from utils import enable_monitor_mode, valid_rssi_value, interface_exists, \
    disable_monitor_mode

# Change logging format.
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def setup_arguments_parser():
    """Setup arguments parser."""
    arguments_parser = ArgumentParser(description=__doc__)
    arguments_parser.add_argument(
        "--interface", "-i", type=str, help="Target WIFI interface.",
        required=True)
    arguments_parser.add_argument(
        "--hook", type=str, help="Alert hook - command to execute.")
    arguments_parser.add_argument(
        "--threshold", "-t", type=float, help="RSSI threshold.")
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
    arguments = setup_arguments_parser()
    enable_monitor_mode(interface=arguments.interface)
    hopper = ChannelsHopper(interface=arguments.interface,
                            hop_interval=arguments.hop_interval,
                            debug=bool(arguments.verbose))

    # Hop to specific channel.
    if arguments.channel is not None:
        hopper.hop_channel(arguments.channel)

    elif not bool(arguments.disable_hopping):
        # Start the channel hopper.
        hopper.start()

    if bool(arguments.calibrate):
        # Start calibration stage.
        calibration_monitor = \
            ThresholdGenerator(timeout=arguments.timeout,
                               target_macs=arguments.target,
                               debug=bool(arguments.verbose),
                               interface=arguments.interface)
        calibration_monitor.start()
        print(f"Generated threshold: {calibration_monitor.rssi_threshold}")

    else:
        # Start monitor stage.
        monitor = WifiSignalSniffer(timeout=arguments.timeout,
                                    target_macs=arguments.target,
                                    debug=bool(arguments.verbose),
                                    ignored_macs=arguments.ignore,
                                    interface=arguments.interface)

        if arguments.threshold is not None:
            monitor.set_threshold(arguments.threshold)
        if arguments.hook is not None:
            monitor.set_hook(arguments.hook)
        monitor.start()

    # Teardown stage
    if hopper.running:
        hopper.stop()
        hopper.join()
    disable_monitor_mode(interface=arguments.interface)
