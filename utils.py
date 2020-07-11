"""Bamradar network utils functions."""
import os


def enable_monitor_mode(interface):
    """Enable monitor mode using iwconfig tool.

    Args:
        interface (str): Network interface.
    """
    if not interface_exists(interface):
        raise ValueError(f"Interface {interface} is invalid.")
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")


def disable_monitor_mode(interface):
    """Disable monitor mode using iwconfig tool.

    Args:
        interface (str): Network interface.
    """
    if not interface_exists(interface):
        raise ValueError(f"Interface {interface} is invalid.")
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode managed")
    os.system(f"ifconfig {interface} up")


def valid_rssi_value(rssi_value):
    """Validate given RSSI sample value.

    Args:
        rssi_value (int): RSSI value.

    Returns:
        bool. Threshold validity.
    """
    return 0 >= rssi_value >= -127


def interface_exists(interface):
    """Validate interface existence.

        Args:
            interface (str): Network interface.

        Returns:
            bool. Interface validity.
    """
    return os.path.exists(f"/sys/class/net/{interface}")
