import argparse
import logging
import os
import signal
import socket
import struct
import subprocess
import threading
import time
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, get_if_addr, conf, ARP, Ether, srp
except ImportError:
    print("Scapy is required. Install with: pip install scapy")
    exit(1)

class StreamProtector:
    def __init__(self, server_ip=None, server_ports=None, interfaces=None, log_file=None):
        # Configuration
        self.server_ip = server_ip or self._get_local_ip()
        self.server_ports = server_ports or []
        self.interfaces = interfaces or self._get_default_interface()
        self.active_streams = {}  # {stream_id: {client_ip, port, start_time, bytes_sent}}
        self.trusted_devices = set()  # Set of known trusted MAC addresses
        self.blocked_ips = set()  # Set of blocked IP addresses
        
        # Protection state
        self.is_running = False
        self.lock = threading.Lock()
        self.poll_interval = 1  # seconds between network scans
        
        # Setup logging
        self.logger = logging.getLogger("StreamProtector")
        self.logger.setLevel(logging.INFO)
        
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(file_handler)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(console_handler)
        
        # Initialize network state
        self.current_network_map = {}  # {ip: mac}
        self.previous_network_map = {}  # To track changes
        
        self.logger.info(f"Stream Protector initialized for server {self.server_ip}")
        self.logger.info(f"Monitoring interfaces: {self.interfaces}")
        
    def _get_local_ip(self):
        """Get the local IP address of the server"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            return get_if_addr(conf.iface)
            
    def _get_default_interface(self):
        """Get the default network interface"""
        return [conf.iface]
        
    def scan_network(self):
        """Perform an ARP scan to map devices on the network"""
        self.logger.debug("Scanning network for devices...")
        network_map = {}
        
        for interface in self.interfaces:
            try:
                # Create ARP request for all devices in the subnet
                ip_range = f"{'.'.join(get_if_addr(interface).split('.')[:3])}.0/24"
                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
                
                # Send the packet and get responses
                answered, _ = srp(arp_request, timeout=2, verbose=0, iface=interface)
                
                # Process responses
                for sent, received in answered:
                    network_map[received.psrc] = received.hwsrc
                    
            except Exception as e:
                self.logger.error(f"Error scanning network on interface {interface}: {e}")
                
        return network_map
    
    def _detect_new_devices(self, current_map):
        """Check for new devices on the network"""
        new_devices = {}
        
        for ip, mac in current_map.items():
            if ip not in self.previous_network_map and ip != self.server_ip:
                new_devices[ip] = mac
                
        return new_devices
        
    def _detect_packet_capture(self, packet):
        """Detect if the packet might be part of a packet capture attempt"""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # If traffic is to/from our server
            if (dst_ip == self.server_ip or src_ip == self.server_ip):
                if TCP in packet:
                    dst_port = packet[TCP].dport
                    src_port = packet[TCP].sport
                    
                    # Check if this is traffic to/from an active stream
                    stream_key = None
                    client_ip = None
                    
                    if dst_ip == self.server_ip and dst_port in self.server_ports:
                        stream_key = f"{src_ip}:{src_port}-{dst_port}"
                        client_ip = src_ip
                    elif src_ip == self.server_ip and src_port in self.server_ports:
                        stream_key = f"{dst_ip}:{dst_port}-{src_port}"
                        client_ip = dst_ip
                        
                    if stream_key:
                        with self.lock:
                            if stream_key not in self.active_streams:
                                # New stream
                                self.active_streams[stream_key] = {
                                    "client_ip": client_ip,
                                    "start_time": time.time(),
                                    "bytes_sent": len(packet),
                                    "packet_count": 1
                                }
                                self.logger.info(f"New stream detected: {stream_key}")
                            else:
                                # Update existing stream
                                self.active_streams[stream_key]["bytes_sent"] += len(packet)
                                self.active_streams[stream_key]["packet_count"] += 1
                                
                    # Check for unauthorized capture
                    if client_ip and client_ip in self.blocked_ips:
                        self.logger.warning(f"Detected traffic from blocked IP: {client_ip}")
                        self._terminate_client_streams(client_ip)
                        return True
                        
        return False
    
    def _check_promiscuous_mode(self):
        """Detect interfaces in promiscuous mode (potential packet sniffing)"""
        suspicious_hosts = []
        
        try:
            # This approach uses Linux-specific commands
            if os.name == "posix":
                arp_output = subprocess.check_output(["arp", "-a"]).decode("utf-8")
                lines = arp_output.split("\n")
                
                for line in lines:
                    if "<incomplete>" in line:  # Potential sign of ARP spoofing
                        parts = line.split()
                        if len(parts) > 1:
                            ip = parts[1].strip("()")
                            suspicious_hosts.append(ip)
            
            # Check for unusual ARP entries that might indicate MITM attacks
            for ip, mac in self.current_network_map.items():
                for other_ip, other_mac in self.current_network_map.items():
                    if ip != other_ip and mac == other_mac:
                        self.logger.warning(f"Potential ARP spoofing detected: {ip} and {other_ip} have same MAC {mac}")
                        suspicious_hosts.extend([ip, other_ip])
                        
        except Exception as e:
            self.logger.error(f"Error checking for promiscuous mode: {e}")
            
        return suspicious_hosts
    
    def _terminate_client_streams(self, client_ip):
        """Terminate all streams from a specific client"""
        with self.lock:
            terminated_count = 0
            streams_to_terminate = []
            
            # Identify streams to terminate
            for stream_id, stream_data in self.active_streams.items():
                if stream_data["client_ip"] == client_ip:
                    streams_to_terminate.append(stream_id)
                    
            # Terminate identified streams
            for stream_id in streams_to_terminate:
                # For TCP streams, send RST packets to force disconnect
                parts = stream_id.split("-")
                if len(parts) == 2:
                    client_addr = parts[0].split(":")
                    if len(client_addr) == 2:
                        client_ip = client_addr[0]
                        client_port = int(client_addr[1])
                        server_port = int(parts[1])
                        
                        try:
                            # Create and send RST packet to terminate connection
                            rst_packet = IP(src=self.server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="R")
                            conf.L3socket(iface=self.interfaces[0]).send(rst_packet)
                            
                            self.logger.info(f"Sent RST packet to terminate stream {stream_id}")
                            terminated_count += 1
                            
                            # Remove the stream from tracking
                            del self.active_streams[stream_id]
                            
                        except Exception as e:
                            self.logger.error(f"Failed to terminate stream {stream_id}: {e}")
                            
            # Also attempt to block at firewall level if on Linux
            try:
                if os.name == "posix" and client_ip not in self.blocked_ips:
                    subprocess.call(["iptables", "-A", "INPUT", "-s", client_ip, "-j", "DROP"])
                    subprocess.call(["iptables", "-A", "OUTPUT", "-d", client_ip, "-j", "DROP"])
                    self.blocked_ips.add(client_ip)
                    self.logger.info(f"Blocked {client_ip} at firewall level")
            except Exception as e:
                self.logger.error(f"Failed to block {client_ip} at firewall: {e}")
                
            return terminated_count
    
    def _monitor_thread(self):
        """Background thread to monitor network for unauthorized packet capture"""
        self.logger.info("Starting network monitoring thread")
        
        while self.is_running:
            try:
                # Scan network to update device map
                self.previous_network_map = self.current_network_map.copy()
                self.current_network_map = self.scan_network()
                
                # Check for new devices
                new_devices = self._detect_new_devices(self.current_network_map)
                for ip, mac in new_devices.items():
                    self.logger.warning(f"New device detected on network: {ip} (MAC: {mac})")
                    
                    # Check if this device is associated with any active stream
                    with self.lock:
                        for stream_id, stream_data in self.active_streams.items():
                            if stream_data["client_ip"] == ip:
                                self.logger.info(f"New device {ip} has an active stream: {stream_id}")
                
                # Check for machines in promiscuous mode (potential packet sniffers)
                suspicious_hosts = self._check_promiscuous_mode()
                for ip in suspicious_hosts:
                    self.logger.warning(f"Suspicious network activity from {ip}, terminating any streams")
                    self._terminate_client_streams(ip)
                    
                # Clean up old streams
                current_time = time.time()
                with self.lock:
                    expired_streams = []
                    for stream_id, stream_data in self.active_streams.items():
                        if current_time - stream_data["start_time"] > 3600:  # 1 hour timeout
                            expired_streams.append(stream_id)
                            
                    for stream_id in expired_streams:
                        del self.active_streams[stream_id]
                        
                # Sleep before next check
                time.sleep(self.poll_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitor thread: {e}")
                time.sleep(5)  # Wait before retry on error
    
    def packet_handler(self, packet):
        """Process each captured packet to detect capture attempts"""
        if self._detect_packet_capture(packet):
            self.logger.warning("Packet capture attempt detected and blocked")
    
    def start(self):
        """Start the stream protection service"""
        self.logger.info("Starting Stream Protector service")
        self.is_running = True
        
        # Start the monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_thread)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Start packet capture
        try:
            for interface in self.interfaces:
                self.logger.info(f"Starting packet capture on {interface}")
                capture_thread = threading.Thread(
                    target=lambda: sniff(
                        iface=interface,
                        filter="ip",
                        prn=self.packet_handler,
                        store=0
                    )
                )
                capture_thread.daemon = True
                capture_thread.start()
                
            # Wait for shutdown signal
            while self.is_running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Received shutdown signal")
        except Exception as e:
            self.logger.error(f"Error during packet capture: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the stream protection service"""
        self.logger.info("Stopping Stream Protector service")
        self.is_running = False
        
        # Clean up firewall rules if any
        if os.name == "posix":
            for ip in self.blocked_ips:
                try:
                    subprocess.call(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                    subprocess.call(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
                except:
                    pass

# Server application integration code
class StreamServer:
    """Example server that integrates with the StreamProtector"""
    
    def __init__(self, protection_url, server_port=8080):
        self.protection_url = protection_url
        self.server_port = server_port
        self.protector = None
        self.logger = logging.getLogger("StreamServer")
        self.logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        
    def start_protection(self):
        """Initialize and start the stream protection module"""
        self.logger.info(f"Initializing stream protection on port {self.server_port}")
        
        # Parse the protection URL for configuration
        # Format: protocol://host:port/path?interface=eth0&log=/var/log/protector.log
        import urllib.parse
        parsed_url = urllib.parse.urlparse(self.protection_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Extract configuration from URL
        interfaces = query_params.get('interface', [None])[0]
        interfaces = [interfaces] if interfaces else None
        
        log_file = query_params.get('log', [None])[0]
        
        # Initialize the protector
        self.protector = StreamProtector(
            server_ports=[self.server_port],
            interfaces=interfaces,
            log_file=log_file
        )
        
        # Start protection in a separate thread
        protection_thread = threading.Thread(target=self.protector.start)
        protection_thread.daemon = True
        protection_thread.start()
        
        self.logger.info("Stream protection started")
        return True
        
    def stream_data(self, client_address):
        """Stream data to a client with protection active"""
        client_ip, client_port = client_address
        
        # Check if client is blocked
        if self.protector and client_ip in self.protector.blocked_ips:
            self.logger.warning(f"Rejecting connection from blocked client: {client_ip}")
            return False
            
        # Register this stream with the protector
        stream_id = f"{client_ip}:{client_port}-{self.server_port}"
        
        with self.protector.lock:
            self.protector.active_streams[stream_id] = {
                "client_ip": client_ip,
                "start_time": time.time(),
                "bytes_sent": 0,
                "packet_count": 0
            }
            
        self.logger.info(f"Registered stream {stream_id} with protector")
        return True
        
    def stop_protection(self):
        """Stop the protection module"""
        if self.protector:
            self.protector.stop()
            self.logger.info("Stream protection stopped")

def main():
    parser = argparse.ArgumentParser(description="Stream Protection Service")
    parser.add_argument("--url", required=True, help="URL of the protection module with configuration")
    parser.add_argument("--port", type=int, default=8080, help="Server port to protect")
    
    args = parser.parse_args()
    
    # Example of integrating with a server
    server = StreamServer(args.url, args.port)
    server.start_protection()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop_protection()

if __name__ == "__main__":
    main()
