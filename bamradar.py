"""Detect smartphones in classified rooms.

Bamradar is a sniffer that monitors and detects
wifi devices. The tool generates a specific RSSI threshold,
every sniffed packet that has bigger RSSI value
will be alerted. Quick start and guide: https://github.com/idoazzz/bamradar
"""
import logging
from abc import abstractmethod
from argparse import ArgumentParser
from subprocess import Popen

from scapy.all import sniff
from scapy.layers.dot11 import RadioTap

from hopper import ChannelsHopper

# Change root logging config.
from utils import enable_monitor_mode, valid_rssi_value, interface_exists, \
    disable_monitor_mode

# Change logging format.
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


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


class WifiSignalSniffer(AbstractSniffer):
    """Wifi RSSI (signals strength) sniffer.

    Attributes:
        threshold (int): Alerting threshold.
        ignored_macs (list): Ignoring those macs.
        target_macs (list): Filtering only those macs.
    """
    DEFAULT_THRESHOLD = -30  # dbm

    def __init__(self, interface, debug=False, timeout=None, target_macs=None,
                 ignored_macs=None, threshold=DEFAULT_THRESHOLD):
        super().__init__(interface, debug, timeout)
        self.set_threshold(threshold)
        self.target_macs = target_macs if target_macs is not None else []
        self.ignored_macs = ignored_macs if ignored_macs is not None else []

    def set_threshold(self, threshold):
        """Set and validate new RSSI threshold.

        Args:
            threshold (int): RSSI value.

        Raises:
            ValueError. Illegal rssi value.
        """
        if not valid_rssi_value(threshold):
            raise ValueError(f"Threshold value {threshold} is invalid.")
        self.threshold = threshold

    def set_hook(self, command):
        """Set a command that will be executed in alert.

        Args:
            command (str): Shell command.
        """
        self.command_hook = command

    def process(self, frame):
        """Check if the signal strength passed the threshold.

        Check if the frame signal strength is stronger than the threshold.
        If it is stronger, alert.
        Also, ignore or check targeting MAC's list.
        """
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
                if self.command_hook is not None:
                    Popen(self.command_hook, shell=True)
                self.logger.info(frame_info)
        else:
            if self.command_hook is not None:
                Popen(self.command_hook, shell=True)
            self.logger.info(frame_info)


class ThresholdCalibrationSniffer(AbstractSniffer):
    """Calibration stage, search for compatible threshold from captured frames.

    Attributes:
        target_macs (list): Filtering only those macs.
        captured_rssi_values (list): Captured RSSI values.
    """
    SAFETY_FACTOR = 0.8

    def __init__(self, interface, debug=False, timeout=None, target_macs=None):
        super().__init__(interface, debug, timeout)
        self.target_macs = target_macs if target_macs is not None else []
        self.captured_rssi_values = []

    @property
    def rssi_threshold(self):
        """Generate a threshold based on captured frames.

        The threshold is the lowest RSSI value that captured in the room with
        a extra factor (be sure that we captured a device in the room and not
        from another room).
        """
        if self.captured_rssi_values == []:
            raise ValueError("There is no captured frames, try to extend the "
                             "capturing time.")
        return min(self.captured_rssi_values) * self.SAFETY_FACTOR

    def process(self, frame):
        """Append the signal strength to the captured RSSI values list."""
        source_address = frame.addr2
        signal_strength = frame.dBm_AntSignal

        if source_address is None:
            return

        if not self.target_macs == []:
            if source_address in self.target_macs:
                self.logger.debug((source_address, signal_strength))
                self.captured_rssi_values.append(signal_strength)
        else:
            self.logger.debug((source_address, signal_strength))
            self.captured_rssi_values.append(signal_strength)


def setup_arguments_parser():
    """Setup arguments parser."""
    arguments_parser = ArgumentParser(description=__doc__)
    arguments_parser.add_argument(
        "--interface", "-i", type=str, help="Target WIFI interface.",
        required=True)
    arguments_parser.add_argument(
        "--hook", type=str, help="Alert hook - command to execute.")
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
            ThresholdCalibrationSniffer(timeout=arguments.timeout,
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
    disable_monitor_mode(interface=arguments.interface)
