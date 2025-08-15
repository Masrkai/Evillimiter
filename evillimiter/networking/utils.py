import re
import netifaces
from scapy.all import ARP, sr1 # pylint: disable=no-name-in-module

import console.shell as shell
from   common.globals import BIN_TC, BIN_NFTABLES, BIN_SYSCTL, IP_FORWARD_LOC


def get_default_interface():
    """
    Returns the default IPv4 interface
    """
    gateways = netifaces.gateways()
    if "default" in gateways and netifaces.AF_INET in gateways["default"]:
        return gateways["default"][netifaces.AF_INET][1]


def get_default_gateway():
    """
    Returns the default IPv4 gateway address
    """
    gateways = netifaces.gateways()
    if "default" in gateways and netifaces.AF_INET in gateways["default"]:
        return gateways["default"][netifaces.AF_INET][0]


def get_default_netmask(interface):
    """
    Returns the default IPv4 netmask associated to an interface
    """
    ifaddrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in ifaddrs:
        return ifaddrs[netifaces.AF_INET][0].get("netmask")


def get_mac_by_ip(interface, address):
    """
    Resolves hardware address from IP by sending ARP request
    and receiving ARP response
    """
    # ARP packet with operation 1 (who-is)
    packet = ARP(op=1, pdst=address)
    response = sr1(packet, timeout=3, verbose=0)

    if response is not None:
        return response.hwsrc


def exists_interface(interface):
    """
    Determines whether or not a given interface exists
    """
    return interface in netifaces.interfaces()


def flush_network_settings(interface):
    """
    Flushes all nftables rules and traffic control entries
    related to the given interface
    """
    # Delete all nftables tables and their contents
    # This is more comprehensive than the old iptables approach
    shell.execute_suppressed("{} flush ruleset".format(BIN_NFTABLES))
    
    # Alternatively, if you want to be more selective and only flush specific tables:
    # shell.execute_suppressed("{} delete table inet limiter 2>/dev/null || true".format(BIN_NFTABLES))
    # shell.execute_suppressed("{} delete table ip nat 2>/dev/null || true".format(BIN_NFTABLES))
    # shell.execute_suppressed("{} delete table ip mangle 2>/dev/null || true".format(BIN_NFTABLES))
    # shell.execute_suppressed("{} delete table ip filter 2>/dev/null || true".format(BIN_NFTABLES))

    # delete root qdisc for given interface
    shell.execute_suppressed("{} qdisc del dev {} root".format(BIN_TC, interface))


def flush_network_settings_selective(interface, table_names=None):
    """
    Alternative flush function that only removes specific nftables tables
    instead of flushing the entire ruleset. This is safer if other applications
    are also using nftables.
    
    Args:
        interface: Network interface name
        table_names: List of table names to delete (e.g., ['inet limiter', 'ip nat'])
                    If None, deletes commonly used tables for traffic limiting
    """
    if table_names is None:
        table_names = ['inet limiter', 'ip nat', 'ip mangle', 'ip filter']
    
    for table in table_names:
        shell.execute_suppressed("{} delete table {} 2>/dev/null || true".format(BIN_NFTABLES, table))
    
    # delete root qdisc for given interface
    shell.execute_suppressed("{} qdisc del dev {} root".format(BIN_TC, interface))


def validate_ip_address(ip):
    return re.match(r"^(\d{1,3}\.){3}(\d{1,3})$", ip) is not None


def validate_mac_address(mac):
    return re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac) is not None


def create_qdisc_root(interface):
    """
    Creates a root htb qdisc in traffic control for a given interface
    """
    return shell.execute_suppressed("{} qdisc add dev {} root handle 1:0 htb".format(BIN_TC, interface)) == 0


def delete_qdisc_root(interface):
    return shell.execute_suppressed("{} qdisc del dev {} root handle 1:0 htb".format(BIN_TC, interface))


def enable_ip_forwarding():
    return shell.execute_suppressed("{} -w {}=1".format(BIN_SYSCTL, IP_FORWARD_LOC)) == 0


def disable_ip_forwarding():
    return shell.execute_suppressed("{} -w {}=0".format(BIN_SYSCTL, IP_FORWARD_LOC)) == 0


def setup_basic_nftables_structure():
    """
    Sets up basic nftables structure that applications can use.
    This replaces the need for setting default policies since nftables
    uses a different approach (default is to accept unless explicitly dropped).
    """
    # Create basic inet table for general use
    shell.execute_suppressed("{} add table inet filter 2>/dev/null || true".format(BIN_NFTABLES))
    
    # Create basic chains (optional - nftables doesn't require default policies)
    shell.execute_suppressed("{} add chain inet filter input {{ type filter hook input priority filter; }} 2>/dev/null || true".format(BIN_NFTABLES))
    shell.execute_suppressed("{} add chain inet filter forward {{ type filter hook forward priority filter; }} 2>/dev/null || true".format(BIN_NFTABLES))
    shell.execute_suppressed("{} add chain inet filter output {{ type filter hook output priority filter; }} 2>/dev/null || true".format(BIN_NFTABLES))


def reset_nftables_to_permissive():
    """
    Ensures nftables is in a permissive state (equivalent to the old iptables default policies).
    Since nftables default behavior is to accept unless explicitly blocked,
    this mainly involves clearing any restrictive rules.
    """
    shell.execute_suppressed("{} flush ruleset".format(BIN_NFTABLES))