#!/usr/bin/env python3
"""
Network Traffic Generator for EV Charging Station Security Testing
Generates various types of network traffic to test IDS capabilities
Simulates both normal and malicious traffic patterns
"""

import socket
import threading
import time
import random
import logging
import json
import os
import struct
import subprocess
from datetime import datetime
from typing import List, Dict, Tuple
import requests
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest
import netifaces

class NetworkTrafficGenerator:
    def __init__(self, target_networks: List[str], interface: str = None):
        self.target_networks = target_networks
        self.interface = interface or self.get_default_interface()
        self.is_running = True
        
        # Setup logging
        self.setup_logging()
        
        # Traffic patterns
        self.normal_traffic_patterns = [
            "http_requests",
            "dns_queries", 
            "ntp_sync",
            "dhcp_requests",
            "charging_protocol"
        ]
        
        self.malicious_patterns = [
            "port_scan",
            "dos_attack",
            "brute_force",
            "mitm_attempt",
            "malware_beacon",
            "data_exfiltration"
        ]
        
        # Protocol ports
        self.common_ports = {
            "http": 80,
            "https": 443,
            "ssh": 22,
            "telnet": 23,
            "ftp": 21,
            "dns": 53,
            "dhcp": 67,
            "ntp": 123,
            "snmp": 161,
            "charging": [1201, 8080, 8443]  # Common EV charging ports
        }

    def setup_logging(self):
        """Setup logging configuration"""
        self.logger = logging.getLogger("TrafficGenerator")
        self.logger.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        log_dir = "/var/log/traffic"
        os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.FileHandler(f"{log_dir}/traffic_generator.log")
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def get_default_interface(self) -> str:
        """Get default network interface"""
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface != 'lo' and netifaces.AF_INET in netifaces.ifaddresses(iface):
                    return iface
            return 'eth0'  # Fallback
        except:
            return 'eth0'

    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "192.168.1.100"

    def generate_target_ips(self) -> List[str]:
        """Generate list of target IP addresses"""
        targets = []
        for network in self.target_networks:
            # Simple IP range generation (192.168.1.0/24 -> 192.168.1.1-254)
            if '/' in network:
                base_ip = network.split('/')[0]
                base_parts = base_ip.split('.')
                base_network = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
                
                for i in range(1, 255):
                    targets.append(f"{base_network}.{i}")
            else:
                targets.append(network)
        
        return targets

    def simulate_normal_traffic(self):
        """Simulate normal network traffic patterns"""
        targets = self.generate_target_ips()
        
        while self.is_running:
            try:
                pattern = random.choice(self.normal_traffic_patterns)
                target = random.choice(targets)
                
                if pattern == "http_requests":
                    self.simulate_http_traffic(target)
                elif pattern == "dns_queries":
                    self.simulate_dns_queries()
                elif pattern == "ntp_sync":
                    self.simulate_ntp_sync()
                elif pattern == "charging_protocol":
                    self.simulate_charging_protocol(target)
                
                # Log normal traffic
                traffic_log = {
                    "timestamp": datetime.now().isoformat(),
                    "traffic_type": "normal",
                    "pattern": pattern,
                    "target": target,
                    "source": self.get_local_ip()
                }
                self.logger.info(f"Normal traffic: {json.dumps(traffic_log)}")
                
                time.sleep(random.uniform(5, 15))  # Random interval
                
            except Exception as e:
                self.logger.error(f"Error generating normal traffic: {e}")
                time.sleep(5)

    def simulate_malicious_traffic(self):
        """Simulate malicious network traffic patterns"""
        if os.getenv('SIMULATION_MODE') != 'suspicious':
            return
            
        targets = self.generate_target_ips()
        
        while self.is_running:
            try:
                # Lower frequency for malicious traffic
                time.sleep(random.uniform(30, 120))
                
                pattern = random.choice(self.malicious_patterns)
                target = random.choice(targets)
                
                if pattern == "port_scan":
                    self.simulate_port_scan(target)
                elif pattern == "dos_attack":
                    self.simulate_dos_attack(target)
                elif pattern == "brute_force":
                    self.simulate_brute_force(target)
                elif pattern == "mitm_attempt":
                    self.simulate_mitm_attempt(target)
                elif pattern == "malware_beacon":
                    self.simulate_malware_beacon()
                elif pattern == "data_exfiltration":
                    self.simulate_data_exfiltration(target)
                
                # Log malicious traffic
                traffic_log = {
                    "timestamp": datetime.now().isoformat(),
                    "traffic_type": "malicious",
                    "pattern": pattern,
                    "target": target,
                    "source": self.get_local_ip(),
                    "severity": "high"
                }
                self.logger.warning(f"MALICIOUS TRAFFIC: {json.dumps(traffic_log)}")
                
            except Exception as e:
                self.logger.error(f"Error generating malicious traffic: {e}")
                time.sleep(10)

    def simulate_http_traffic(self, target: str):
        """Simulate normal HTTP traffic"""
        try:
            urls = [
                f"http://{target}/api/status",
                f"http://{target}/charging/session",
                f"http://{target}/admin/dashboard",
                f"http://{target}/payment/process"
            ]
            
            url = random.choice(urls)
            
            # Simulate HTTP request
            packet = IP(dst=target)/TCP(dport=80, flags="S")
            
            # Don't actually send, just log the attempt
            self.logger.debug(f"Simulated HTTP request to {url}")
            
        except Exception as e:
            self.logger.error(f"HTTP traffic simulation error: {e}")

    def simulate_dns_queries(self):
        """Simulate DNS queries"""
        try:
            domains = [
                "charging.example.com",
                "api.evcharger.com", 
                "ntp.pool.org",
                "firmware.updates.com"
            ]
            
            domain = random.choice(domains)
            
            # Simulate DNS query
            packet = IP(dst="8.8.8.8")/UDP(dport=53)
            
            self.logger.debug(f"Simulated DNS query for {domain}")
            
        except Exception as e:
            self.logger.error(f"DNS simulation error: {e}")

    def simulate_ntp_sync(self):
        """Simulate NTP synchronization"""
        try:
            ntp_servers = ["pool.ntp.org", "time.google.com"]
            server = random.choice(ntp_servers)
            
            packet = IP(dst=server)/UDP(dport=123)
            
            self.logger.debug(f"Simulated NTP sync with {server}")
            
        except Exception as e:
            self.logger.error(f"NTP simulation error: {e}")

    def simulate_charging_protocol(self, target: str):
        """Simulate EV charging protocol traffic (OCPP, etc.)"""
        try:
            charging_ports = self.common_ports["charging"]
            port = random.choice(charging_ports)
            
            # Simulate charging protocol messages
            messages = [
                "StatusNotification",
                "Heartbeat", 
                "StartTransaction",
                "StopTransaction",
                "MeterValues"
            ]
            
            message = random.choice(messages)
            
            packet = IP(dst=target)/TCP(dport=port)
            
            self.logger.debug(f"Simulated charging protocol: {message} to {target}:{port}")
            
        except Exception as e:
            self.logger.error(f"Charging protocol simulation error: {e}")

    def simulate_port_scan(self, target: str):
        """Simulate port scanning attack"""
        try:
            # Simulate scanning common ports
            scan_ports = [22, 23, 80, 443, 161, 1201, 8080, 8443]
            
            for port in scan_ports:
                packet = IP(dst=target)/TCP(dport=port, flags="S")
                # Log the scan attempt
                self.logger.warning(f"Port scan attempt: {target}:{port}")
                time.sleep(0.1)  # Small delay between ports
                
        except Exception as e:
            self.logger.error(f"Port scan simulation error: {e}")

    def simulate_dos_attack(self, target: str):
        """Simulate DoS attack"""
        try:
            # Simulate high-frequency requests
            for i in range(50):
                packet = IP(dst=target)/TCP(dport=80, flags="S")
                self.logger.warning(f"DoS attack packet {i+1}/50 to {target}")
                time.sleep(0.05)  # High frequency
                
        except Exception as e:
            self.logger.error(f"DoS simulation error: {e}")

    def simulate_brute_force(self, target: str):
        """Simulate brute force attack"""
        try:
            services = ["ssh", "telnet", "http"]
            service = random.choice(services)
            port = self.common_ports[service]
            
            # Simulate multiple authentication attempts
            for attempt in range(10):
                packet = IP(dst=target)/TCP(dport=port)
                self.logger.warning(f"Brute force attempt {attempt+1}/10 against {service} on {target}")
                time.sleep(1)
                
        except Exception as e:
            self.logger.error(f"Brute force simulation error: {e}")

    def simulate_mitm_attempt(self, target: str):
        """Simulate Man-in-the-Middle attack"""
        try:
            # Simulate ARP spoofing attempt
            self.logger.warning(f"MITM attempt: ARP spoofing towards {target}")
            
            # Simulate suspicious HTTP traffic
            packet = IP(dst=target)/TCP(dport=80)
            self.logger.warning(f"MITM attempt: Intercepting HTTP traffic from {target}")
            
        except Exception as e:
            self.logger.error(f"MITM simulation error: {e}")

    def simulate_malware_beacon(self):
        """Simulate malware beacon traffic"""
        try:
            # Simulate beacon to external C&C server
            c2_servers = [
                "suspicious-domain.tk",
                "malware-c2.ru",
                "bad-actor.cn"
            ]
            
            server = random.choice(c2_servers)
            
            packet = IP(dst=server)/TCP(dport=443)
            
            beacon_data = {
                "beacon_type": "malware_c2",
                "destination": server,
                "protocol": "HTTPS",
                "suspicious_indicators": ["unknown_domain", "encrypted_payload"]
            }
            
            self.logger.critical(f"Malware beacon detected: {json.dumps(beacon_data)}")
            
        except Exception as e:
            self.logger.error(f"Malware beacon simulation error: {e}")

    def simulate_data_exfiltration(self, target: str):
        """Simulate data exfiltration attempt"""
        try:
            # Simulate large data transfer to external server
            external_server = "data-collector.suspicious.com"
            
            # Simulate large upload
            packet = IP(dst=external_server)/TCP(dport=443)
            
            exfil_data = {
                "exfiltration_type": "data_upload",
                "source": target,
                "destination": external_server,
                "data_size": "500MB",
                "protocol": "HTTPS",
                "suspicious_indicators": ["large_transfer", "external_domain"]
            }
            
            self.logger.critical(f"Data exfiltration attempt: {json.dumps(exfil_data)}")
            
        except Exception as e:
            self.logger.error(f"Data exfiltration simulation error: {e}")

    def monitor_network_interfaces(self):
        """Monitor network interfaces for anomalies"""
        while self.is_running:
            try:
                # Monitor interface statistics
                stats = self.get_interface_stats()
                
                # Check for anomalies
                if stats.get('rx_packets', 0) > 10000:  # High packet count
                    self.logger.warning(f"High packet count detected: {stats}")
                
                if stats.get('tx_bytes', 0) > 1000000:  # Large data transfer
                    self.logger.warning(f"Large data transfer detected: {stats}")
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Interface monitoring error: {e}")
                time.sleep(60)

    def get_interface_stats(self) -> Dict:
        """Get network interface statistics"""
        try:
            # Simple implementation - in production use proper network monitoring
            return {
                "interface": self.interface,
                "rx_packets": random.randint(1000, 5000),
                "tx_packets": random.randint(1000, 5000),
                "rx_bytes": random.randint(100000, 500000),
                "tx_bytes": random.randint(100000, 500000),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Failed to get interface stats: {e}")
            return {}

    def start_traffic_generation(self):
        """Start all traffic generation threads"""
        threads = []
        
        # Normal traffic thread
        normal_thread = threading.Thread(target=self.simulate_normal_traffic, daemon=True)
        normal_thread.start()
        threads.append(normal_thread)
        
        # Malicious traffic thread (if enabled)
        malicious_thread = threading.Thread(target=self.simulate_malicious_traffic, daemon=True)
        malicious_thread.start()
        threads.append(malicious_thread)
        
        # Network monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_network_interfaces, daemon=True)
        monitor_thread.start()
        threads.append(monitor_thread)
        
        self.logger.info("Traffic generation started")
        return threads

    def stop(self):
        """Stop traffic generation"""
        self.is_running = False
        self.logger.info("Traffic generation stopped")

def main():
    """Main function"""
    # Default target networks (EV charging station network)
    target_networks = [
        "192.168.1.0/24",   # Local network
        "10.0.0.0/24",      # Internal network
        "172.16.0.0/24"     # Private network
    ]
    
    # Get configuration from environment
    networks_env = os.getenv('TARGET_NETWORKS')
    if networks_env:
        target_networks = networks_env.split(',')
    
    interface = os.getenv('NETWORK_INTERFACE')
    
    # Create traffic generator
    generator = NetworkTrafficGenerator(target_networks, interface)
    
    try:
        threads = generator.start_traffic_generation()
        
        # Keep main thread alive
        while True:
            time.sleep(10)
            
    except KeyboardInterrupt:
        generator.stop()
        generator.logger.info("Traffic generator shutdown complete")

if __name__ == "__main__":
    main()