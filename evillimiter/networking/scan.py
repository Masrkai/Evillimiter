# import sys
# import socket
# import logging
# from tqdm import tqdm
# from netaddr import IPAddress

# from scapy.all import ARP, sr1  #! pylint: disable=no-name-in-module
# from concurrent.futures import ThreadPoolExecutor

# #! Just to suppress the warnings
# import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# from .host import Host
# from evillimiter.console.io import IO


# class HostScanner(object):
#     def __init__(self, interface, iprange):
#         self.interface = interface
#         self.iprange = iprange

#         self.max_workers = 75   # max. amount of threads
#         self.retries = 0        # ARP retry
#         self.timeout = 2.5      # time in s to wait for an answer

#     def scan(self, iprange=None):
#         self._resolve_names = True

#         with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
#             hosts = []
#             iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]
#             iterator = tqdm(
#                 iterable=executor.map(self._sweep, iprange),
#                 total=len(iprange),
#                 ncols=45,
#                 bar_format="{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}",
#             )

#             try:
#                 for host in iterator:
#                     if host is not None:
#                         try:
#                             host_info = socket.gethostbyaddr(host.ip)
#                             name = "" if host_info is None else host_info[0]
#                             host.name = name
#                         except socket.herror:
#                             pass

#                         hosts.append(host)
#             except KeyboardInterrupt:
#                 iterator.close()
#                 IO.ok("aborted. waiting for shutdown...")

#             return hosts

#     def scan_for_reconnects(self, hosts, iprange=None):
#         with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
#             scanned_hosts = []
#             iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]
#             for host in executor.map(self._sweep, iprange):
#                 if host is not None:
#                     scanned_hosts.append(host)

#             reconnected_hosts = {}
#             for host in hosts:
#                 for s_host in scanned_hosts:
#                     if host.mac == s_host.mac and host.ip != s_host.ip:
#                         s_host.name = host.name
#                         reconnected_hosts[host] = s_host

#             return reconnected_hosts

#     def _sweep(self, ip):
#         """
#         Sends ARP packet and listens for answer,
#         if present the host is online
#         """
#         packet = ARP(op=1, pdst=ip)
#         answer = sr1(packet, retry=self.retries, timeout=self.timeout, verbose=0)

#         if answer is not None:
#             return Host(ip, answer.hwsrc, "")


import sys
import socket
import logging
from tqdm import tqdm
from netaddr import IPAddress
import time
from functools import partial

from scapy.all import ARP, Ether, srp  # Using srp instead of sr1 for batch processing
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from .host import Host
from evillimiter.console.io import IO


class HostScanner(object):
    def __init__(self, interface, iprange):
        self.interface = interface
        self.iprange = iprange

        self.max_workers = 100      # Increased max threads
        self.retries = 1            # Small retry value to improve speed
        self.timeout = 1.5          # Reduced timeout
        self.batch_size = 50        # Batch size for ARP requests
        self.resolve_timeout = 1.0  # Timeout for hostname resolution

    def scan(self, iprange=None):
        iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]

        # Split IP addresses into batches
        ip_batches = [iprange[i:i + self.batch_size] for i in range(0, len(iprange), self.batch_size)]
        hosts = []

        with tqdm(total=len(iprange), ncols=45, bar_format="{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}") as pbar:
            try:
                for batch in ip_batches:
                    batch_hosts = self._sweep_batch(batch)

                    # Resolve hostnames in parallel
                    if batch_hosts:
                        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                            # Map the hostname resolution function to each host
                            resolution_func = partial(self._resolve_hostname, timeout=self.resolve_timeout)
                            list(executor.map(resolution_func, batch_hosts))

                        hosts.extend(batch_hosts)

                    pbar.update(len(batch))

            except KeyboardInterrupt:
                pbar.close()
                IO.ok("aborted. waiting for shutdown...")

        return hosts

    def scan_for_reconnects(self, hosts, iprange=None):
        iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]

        # Split IP addresses into batches
        ip_batches = [iprange[i:i + self.batch_size] for i in range(0, len(iprange), self.batch_size)]
        scanned_hosts = []

        for batch in ip_batches:
            batch_hosts = self._sweep_batch(batch)
            if batch_hosts:
                scanned_hosts.extend(batch_hosts)

        # Create lookup dictionary by MAC for faster comparison
        mac_to_scanned_host = {host.mac: host for host in scanned_hosts}

        reconnected_hosts = {}
        for host in hosts:
            if host.mac in mac_to_scanned_host:
                s_host = mac_to_scanned_host[host.mac]
                if host.ip != s_host.ip:
                    s_host.name = host.name
                    reconnected_hosts[host] = s_host

        return reconnected_hosts

    def _sweep_batch(self, ips):
        """
        Sends ARP packets in batch and processes responses
        """
        if not ips:
            return []

        # Create Ethernet frame with ARP request for each IP
        arp_requests = [Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) for ip in ips]

        # Send all requests at once and collect responses
        responses, _ = srp(arp_requests, timeout=self.timeout, retry=self.retries,
                           verbose=0, iface=self.interface)

        # Process responses
        hosts = []
        for sent, received in responses:
            hosts.append(Host(received.psrc, received.hwsrc, ""))

        return hosts

    def _resolve_hostname(self, host, timeout=1.0):
        """
        Resolves hostname with timeout
        """
        try:
            socket.setdefaulttimeout(timeout)
            host_info = socket.gethostbyaddr(host.ip)
            name = "" if host_info is None else host_info[0]
            host.name = name
        except (socket.herror, socket.timeout):
            pass
        return host

    # Keep the original _sweep method for backward compatibility
    def _sweep(self, ip):
        """
        Sends ARP packet and listens for answer,
        if present the host is online
        """
        packet = ARP(op=1, pdst=ip)
        answer = sr1(packet, retry=self.retries, timeout=self.timeout, verbose=0, iface=self.interface)

        if answer is not None:
            return Host(ip, answer.hwsrc, "")