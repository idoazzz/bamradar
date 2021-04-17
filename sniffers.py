from utils import valid_rssi_value
from abstract_sniffer import AbstractSniffer


class WifiSignalSniffer(AbstractSniffer):
    """Wifi RSSI (signals strength) sniffer.

    Attributes:
        threshold (int): Alerting threshold.
        ignored_macs (list): Ignoring those macs.
        target_macs (list): Filtering only those macs.
    """
    DEFAULT_THRESHOLD = -120  # dbm

    def __init__(self, interface, debug=False, timeout=None, target_macs=None,
                 ignored_macs=None, threshold=DEFAULT_THRESHOLD):
        super().__init__(interface, debug, timeout)
        self.command_hook = None
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


class ThresholdGenerator(AbstractSniffer):
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
        if not self.captured_rssi_values:
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