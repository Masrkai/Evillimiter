# import sys
# import socket
# import logging
# from tqdm import tqdm
# from netaddr import IPAddress
# import time
# from functools import partial

# from concurrent.futures import ThreadPoolExecutor

# from scapy.all import ARP, Ether, srp  # Using srp instead of sr1 for batch processing

# #! Just to suppress the warnings
# import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# from .host import Host
# from evillimiter.console.io import IO


# class HostScanner(object):
#     def __init__(self, interface, iprange):
#         self.interface = interface
#         self.iprange = iprange

#         self.max_workers = 100      # Increased max threads
#         self.retries = 1            # Small retry value to improve speed
#         self.timeout = 1.5          # Reduced timeout
#         self.batch_size = 50        # Batch size for ARP requests
#         self.resolve_timeout = 1.0  # Timeout for hostname resolution

#     def scan(self, iprange=None):
#         iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]

#         # Split IP addresses into batches
#         ip_batches = [iprange[i:i + self.batch_size] for i in range(0, len(iprange), self.batch_size)]
#         hosts = []

#         with tqdm(total=len(iprange), ncols=45, bar_format="{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}") as pbar:
#             try:
#                 for batch in ip_batches:
#                     batch_hosts = self._sweep_batch(batch)

#                     # Resolve hostnames in parallel
#                     if batch_hosts:
#                         with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
#                             # Map the hostname resolution function to each host
#                             resolution_func = partial(self._resolve_hostname, timeout=self.resolve_timeout)
#                             list(executor.map(resolution_func, batch_hosts))

#                         hosts.extend(batch_hosts)

#                     pbar.update(len(batch))

#             except KeyboardInterrupt:
#                 pbar.close()
#                 IO.ok("aborted. waiting for shutdown...")

#         return hosts

#     def scan_for_reconnects(self, hosts, iprange=None):
#         iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]

#         # Split IP addresses into batches
#         ip_batches = [iprange[i:i + self.batch_size] for i in range(0, len(iprange), self.batch_size)]
#         scanned_hosts = []

#         for batch in ip_batches:
#             batch_hosts = self._sweep_batch(batch)
#             if batch_hosts:
#                 scanned_hosts.extend(batch_hosts)

#         # Create lookup dictionary by MAC for faster comparison
#         mac_to_scanned_host = {host.mac: host for host in scanned_hosts}

#         reconnected_hosts = {}
#         for host in hosts:
#             if host.mac in mac_to_scanned_host:
#                 s_host = mac_to_scanned_host[host.mac]
#                 if host.ip != s_host.ip:
#                     s_host.name = host.name
#                     reconnected_hosts[host] = s_host

#         return reconnected_hosts

#     def _sweep_batch(self, ips):
#         """
#         Sends ARP packets in batch and processes responses
#         """
#         if not ips:
#             return []

#         # Create Ethernet frame with ARP request for each IP
#         arp_requests = [Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) for ip in ips]

#         # Send all requests at once and collect responses
#         responses, _ = srp(arp_requests, timeout=self.timeout, retry=self.retries,
#                            verbose=0, iface=self.interface)

#         # Process responses
#         hosts = []
#         for sent, received in responses:
#             hosts.append(Host(received.psrc, received.hwsrc, ""))

#         return hosts

#     def _resolve_hostname(self, host, timeout=1.0):
#         """
#         Resolves hostname with timeout
#         """
#         try:
#             socket.setdefaulttimeout(timeout)
#             host_info = socket.gethostbyaddr(host.ip)
#             name = "" if host_info is None else host_info[0]
#             host.name = name
#         except (socket.herror, socket.timeout):
#             pass
#         return host

#     # Keep the original _sweep method for backward compatibility
#     def _sweep(self, ip):
#         """
#         Sends ARP packet and listens for answer,
#         if present the host is online
#         """
#         packet = ARP(op=1, pdst=ip)
#         answer = sr1(packet, retry=self.retries, timeout=self.timeout, verbose=0, iface=self.interface)

#         if answer is not None:
#             return Host(ip, answer.hwsrc, "")



import sys
import socket
import logging
import time
import asyncio
import threading
from tqdm import tqdm
from netaddr import IPNetwork, IPAddress
from functools import partial
from concurrent.futures import ThreadPoolExecutor
import queue

from scapy.all import ARP, Ether, srp, conf
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from .host import Host
from evillimiter.console.io import IO


class HostScanner(object):
    def __init__(self, interface, iprange):
        self.interface = interface
        self.iprange = iprange

        # Optimized scanning parameters
        self.max_workers = 150           # Increased worker threads
        self.resolve_workers = 50        # Separate pool for hostname resolution
        self.retries = 1                 # Keep retries minimal
        self.timeout = 1.0               # Reduced timeout for faster scanning
        self.batch_size = 128            # Larger batch size for network efficiency
        self.resolve_timeout = 0.8       # Faster hostname resolution
        self.max_queue_size = 1000       # Queue size for processing results
        self.adaptive_timing = True      # Dynamically adjust timeout based on network conditions

        # Cache for previously resolved hostnames
        self.hostname_cache = {}
        
        # Configure Scapy for performance
        conf.verb = 0                    # Disable verbose output
        conf.use_pcap = True             # Use libpcap for better performance if available

    def scan(self, iprange=None):
        target_ips = [str(x) for x in (self.iprange if iprange is None else iprange)]
        hosts = []
        result_queue = queue.Queue(maxsize=self.max_queue_size)
        processing_done = threading.Event()
        
        # Create progress bar
        progress_bar = tqdm(
            total=len(target_ips),
            ncols=45,
            bar_format="{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}"
        )
        
        # Start result processing thread
        processing_thread = threading.Thread(
            target=self._process_results,
            args=(result_queue, hosts, progress_bar, processing_done)
        )
        processing_thread.daemon = True
        processing_thread.start()
        
        try:
            # Split work into network segments for more efficient scanning
            network_segments = self._group_by_subnet(target_ips)
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit scanning tasks by network segment for better locality
                for segment, ips in network_segments.items():
                    # Process each segment in batches
                    ip_batches = [ips[i:i + self.batch_size] for i in range(0, len(ips), self.batch_size)]
                    for batch in ip_batches:
                        executor.submit(self._scan_batch_and_queue, batch, result_queue)
                
            # Signal processing is complete
            processing_done.set()
            processing_thread.join()
            progress_bar.close()
            
        except KeyboardInterrupt:
            progress_bar.close()
            IO.ok("aborted. waiting for shutdown...")
            processing_done.set()
            processing_thread.join(timeout=1.0)
        
        return hosts

    def _scan_batch_and_queue(self, ips, result_queue):
        """Scan a batch of IPs and put results in the queue"""
        # Measure response time to adaptively adjust timeout
        start_time = time.time()
        
        # Send ARP requests for all IPs in batch
        hosts = self._sweep_batch(ips)
        
        # Adjust timeout based on response time
        elapsed = time.time() - start_time
        if self.adaptive_timing and hosts and elapsed < self.timeout:
            # If we got responses faster than timeout, slightly decrease timeout
            self.timeout = max(0.5, min(self.timeout, elapsed * 1.5))
        
        # Queue results for processing
        for host in hosts:
            result_queue.put(host)

    def _process_results(self, result_queue, hosts, progress_bar, done_event):
        """Process scanning results from queue and resolve hostnames"""
        with ThreadPoolExecutor(max_workers=self.resolve_workers) as resolver:
            futures = {}
            processed_count = 0
            
            while not (done_event.is_set() and result_queue.empty()):
                try:
                    # Get host with timeout to allow checking done_event
                    host = result_queue.get(timeout=0.1)
                    processed_count += 1
                    
                    # Check hostname cache first
                    if host.ip in self.hostname_cache:
                        host.name = self.hostname_cache[host.ip]
                        hosts.append(host)
                    else:
                        # Submit hostname resolution to thread pool
                        future = resolver.submit(self._resolve_hostname, host)
                        futures[future] = host
                    
                    # Update progress
                    progress_bar.update(1)
                    result_queue.task_done()
                    
                except queue.Empty:
                    # Process any completed resolutions
                    pass
                
                # Process completed hostname resolutions
                for future in list(futures.keys()):
                    if future.done():
                        host = futures.pop(future)
                        try:
                            resolved_host = future.result()
                            if resolved_host.name:
                                self.hostname_cache[resolved_host.ip] = resolved_host.name
                            hosts.append(resolved_host)
                        except Exception:
                            # If resolution fails, still add the host
                            hosts.append(host)
            
            # Wait for remaining hostname resolutions
            for future in futures:
                try:
                    future.result(timeout=0.5)
                except Exception:
                    pass

    def scan_for_reconnects(self, hosts, iprange=None):
        target_ips = [str(x) for x in (self.iprange if iprange is None else iprange)]
        scanned_hosts = []
        
        # Create network segments for better locality
        network_segments = self._group_by_subnet(target_ips)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Submit batch scanning tasks by network segment
            for segment, ips in network_segments.items():
                ip_batches = [ips[i:i + self.batch_size] for i in range(0, len(ips), self.batch_size)]
                for batch in ip_batches:
                    futures.append(executor.submit(self._sweep_batch, batch))
            
            # Collect results
            for future in futures:
                batch_hosts = future.result()
                if batch_hosts:
                    scanned_hosts.extend(batch_hosts)
        
        # Use MAC address lookup table for O(1) comparison
        mac_to_scanned_host = {host.mac: host for host in scanned_hosts}
        mac_to_orig_host = {host.mac: host for host in hosts}
        
        # Find reconnected hosts (MAC address appears in both scans but with different IPs)
        reconnected_hosts = {}
        for mac, s_host in mac_to_scanned_host.items():
            if mac in mac_to_orig_host:
                orig_host = mac_to_orig_host[mac]
                if orig_host.ip != s_host.ip:
                    s_host.name = orig_host.name or s_host.name
                    reconnected_hosts[orig_host] = s_host

        return reconnected_hosts

    def _sweep_batch(self, ips):
        """
        Optimized batch ARP scanning
        """
        if not ips:
            return []
        
        # Create optimized ARP requests
        arp_requests = [Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip, hwlen=6, plen=4, op=1) for ip in ips]
        
        # Send requests with optimized parameters
        try:
            responses, _ = srp(
                arp_requests, 
                timeout=self.timeout,
                retry=self.retries,
                filter="arp",  # Only capture ARP responses
                verbose=0,
                iface=self.interface
            )
        except Exception as e:
            # Handle any scanning errors gracefully
            logging.debug(f"Scanning error: {str(e)}")
            return []
        
        # Process responses efficiently
        hosts = []
        for sent, received in responses:
            try:
                hosts.append(Host(received.psrc, received.hwsrc, ""))
            except Exception:
                # Skip malformed responses
                continue
            
        return hosts
        
    def _resolve_hostname(self, host, timeout=None):
        """
        Fast hostname resolution with caching
        """
        timeout = timeout or self.resolve_timeout
        
        try:
            # Check cache first
            if host.ip in self.hostname_cache:
                host.name = self.hostname_cache[host.ip]
                return host
                
            # Set timeout for socket operations
            socket.setdefaulttimeout(timeout)
            host_info = socket.gethostbyaddr(host.ip)
            name = "" if host_info is None else host_info[0]
            host.name = name
            
            # Update cache
            if name:
                self.hostname_cache[host.ip] = name
                
        except (socket.herror, socket.timeout, Exception):
            pass
            
        return host
    
    def _group_by_subnet(self, ips, mask=24):
        """
        Group IPs by subnet for more efficient scanning
        """
        subnets = {}
        for ip in ips:
            try:
                subnet = str(IPNetwork(f"{ip}/{mask}").network)
                if subnet not in subnets:
                    subnets[subnet] = []
                subnets[subnet].append(ip)
            except Exception:
                # Handle invalid IPs gracefully
                if "default" not in subnets:
                    subnets["default"] = []
                subnets["default"].append(ip)
        return subnets
        
    def _sweep(self, ip):
        """
        Legacy single IP sweep method (maintained for compatibility)
        """
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip, hwlen=6, plen=4, op=1)
            responses, _ = srp(packet, timeout=self.timeout, retry=self.retries, verbose=0, iface=self.interface)
            
            if responses and len(responses) > 0:
                _, received = responses[0]
                return Host(received.psrc, received.hwsrc, "")
            return None
        except Exception:
            return None