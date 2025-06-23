#!/usr/bin/env python3
"""
EV Charging Point Security Agent
Simulates an EV charging station and monitors for security threats
Integrates with Wazuh SIEM for centralized monitoring
"""

import json
import time
import random
import logging
import os
import socket
import threading
from datetime import datetime, timedelta
import hashlib
import requests
from dataclasses import dataclass
from typing import Dict, List, Optional
import psutil
import netifaces

@dataclass
class ChargingSession:
    session_id: str
    user_id: str
    start_time: datetime
    end_time: Optional[datetime]
    energy_consumed: float
    status: str
    payment_method: str
    connector_type: str

@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: str
    description: str
    charger_id: str
    additional_data: Dict

class EVChargerAgent:
    def __init__(self, charger_id: str, location: str, wazuh_manager_ip: str):
        self.charger_id = charger_id
        self.location = location
        self.wazuh_manager_ip = wazuh_manager_ip
        self.active_sessions: Dict[str, ChargingSession] = {}
        self.security_events: List[SecurityEvent] = []
        self.is_running = True
        
        # Setup logging
        self.setup_logging()
        
        # Charger status
        self.status = "online"
        self.firmware_version = "2.1.4"
        self.connectors = ["Type2", "CCS", "CHAdeMO"]
        self.max_power = 150  # kW
        
        # Security monitoring
        self.failed_auth_attempts = 0
        self.last_maintenance = datetime.now() - timedelta(days=30)
        self.network_anomalies = 0
        
        # Simulation parameters
        self.simulation_mode = os.getenv('SIMULATION_MODE', 'normal')
        
        self.logger.info(f"EV Charger {self.charger_id} initialized at {self.location}")

    def setup_logging(self):
        """Setup logging configuration for Wazuh integration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Console handler
        logging.basicConfig(level=logging.INFO, format=log_format)
        self.logger = logging.getLogger(f"EVCharger-{self.charger_id}")
        
        # File handler for Wazuh to monitor
        log_dir = "/var/log/ev-charger"
        os.makedirs(log_dir, exist_ok=True)
        
        file_handler = logging.FileHandler(f"{log_dir}/{self.charger_id}.log")
        file_handler.setFormatter(logging.Formatter(log_format))
        self.logger.addHandler(file_handler)
        
        # Security events log
        security_handler = logging.FileHandler(f"{log_dir}/{self.charger_id}_security.log")
        security_handler.setFormatter(logging.Formatter(log_format))
        self.security_logger = logging.getLogger(f"Security-{self.charger_id}")
        self.security_logger.addHandler(security_handler)

    def generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = str(int(time.time()))
        random_str = str(random.randint(1000, 9999))
        return hashlib.md5(f"{self.charger_id}{timestamp}{random_str}".encode()).hexdigest()[:12]

    def start_charging_session(self) -> str:
        """Simulate starting a new charging session"""
        session_id = self.generate_session_id()
        user_id = f"user_{random.randint(10000, 99999)}"
        connector_type = random.choice(self.connectors)
        payment_method = random.choice(["RFID", "Mobile_App", "Credit_Card"])
        
        session = ChargingSession(
            session_id=session_id,
            user_id=user_id,
            start_time=datetime.now(),
            end_time=None,
            energy_consumed=0.0,
            status="charging",
            payment_method=payment_method,
            connector_type=connector_type
        )
        
        self.active_sessions[session_id] = session
        
        log_data = {
            "event_type": "charging_session_start",
            "charger_id": self.charger_id,
            "session_id": session_id,
            "user_id": user_id,
            "connector_type": connector_type,
            "payment_method": payment_method,
            "location": self.location,
            "timestamp": session.start_time.isoformat()
        }
        
        self.logger.info(f"Charging session started: {json.dumps(log_data)}")
        return session_id

    def end_charging_session(self, session_id: str):
        """End a charging session"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            session.end_time = datetime.now()
            session.status = "completed"
            
            # Calculate energy consumed
            duration_hours = (session.end_time - session.start_time).total_seconds() / 3600
            session.energy_consumed = round(random.uniform(5, 50) * duration_hours, 2)
            
            log_data = {
                "event_type": "charging_session_end",
                "charger_id": self.charger_id,
                "session_id": session_id,
                "duration_minutes": int(duration_hours * 60),
                "energy_consumed_kwh": session.energy_consumed,
                "location": self.location,
                "timestamp": session.end_time.isoformat()
            }
            
            self.logger.info(f"Charging session completed: {json.dumps(log_data)}")
            del self.active_sessions[session_id]

    def monitor_system_health(self):
        """Monitor system health and log anomalies"""
        try:
            # CPU and Memory monitoring
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            # Temperature simulation (normally would come from sensors)
            ambient_temp = random.uniform(15, 35)
            internal_temp = random.uniform(25, 45)
            
            # Power grid metrics simulation
            grid_voltage = random.uniform(220, 240)
            grid_frequency = random.uniform(49.8, 50.2)
            
            health_data = {
                "event_type": "system_health",
                "charger_id": self.charger_id,
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "ambient_temperature": ambient_temp,
                "internal_temperature": internal_temp,
                "grid_voltage": grid_voltage,
                "grid_frequency": grid_frequency,
                "active_sessions": len(self.active_sessions),
                "timestamp": datetime.now().isoformat()
            }
            
            # Check for anomalies
            if cpu_percent > 90:
                self.generate_security_event("HIGH_CPU_USAGE", "warning", 
                                           f"CPU usage at {cpu_percent}%")
            
            if memory.percent > 85:
                self.generate_security_event("HIGH_MEMORY_USAGE", "warning",
                                           f"Memory usage at {memory.percent}%")
            
            if internal_temp > 40:
                self.generate_security_event("HIGH_TEMPERATURE", "warning",
                                           f"Internal temperature at {internal_temp}°C")
            
            if grid_voltage < 210 or grid_voltage > 250:
                self.generate_security_event("VOLTAGE_ANOMALY", "critical",
                                           f"Grid voltage at {grid_voltage}V")
            
            self.logger.info(f"System health: {json.dumps(health_data)}")
            
        except Exception as e:
            self.logger.error(f"Error monitoring system health: {e}")

    def monitor_network_security(self):
        """Monitor network traffic for security threats"""
        try:
            # Get network interfaces
            interfaces = netifaces.interfaces()
            
            for interface in interfaces:
                if interface != 'lo':  # Skip loopback
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        ip_info = addrs[netifaces.AF_INET][0]
                        
                        # Simulate network monitoring
                        if self.simulation_mode == "suspicious":
                            self.simulate_network_threats()
                        
                        network_data = {
                            "event_type": "network_status",
                            "charger_id": self.charger_id,
                            "interface": interface,
                            "ip_address": ip_info.get('addr', 'unknown'),
                            "timestamp": datetime.now().isoformat()
                        }
                        
                        self.logger.debug(f"Network status: {json.dumps(network_data)}")
                        
        except Exception as e:
            self.logger.error(f"Error monitoring network: {e}")

    def simulate_network_threats(self):
        """Simulate various network-based security threats"""
        threat_scenarios = [
            ("PORT_SCAN", "Port scan detected from suspicious IP"),
            ("BRUTE_FORCE", "Multiple failed authentication attempts"),
            ("DDoS_ATTEMPT", "Unusual traffic patterns detected"),
            ("MALWARE_COMMUNICATION", "Suspicious outbound connections"),
            ("UNAUTHORIZED_ACCESS", "Unauthorized configuration access attempt")
        ]
        
        if random.random() < 0.1:  # 10% chance of simulating a threat
            threat_type, description = random.choice(threat_scenarios)
            suspicious_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            
            self.generate_security_event(threat_type, "high", description, suspicious_ip)

    def generate_security_event(self, event_type: str, severity: str, description: str, source_ip: str = "127.0.0.1"):
        """Generate and log security events"""
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            description=description,
            charger_id=self.charger_id,
            additional_data={
                "location": self.location,
                "firmware_version": self.firmware_version
            }
        )
        
        self.security_events.append(event)
        
        security_log = {
            "alert_type": "security_event",
            "charger_id": self.charger_id,
            "event_type": event_type,
            "severity": severity,
            "source_ip": source_ip,
            "description": description,
            "location": self.location,
            "timestamp": event.timestamp.isoformat()
        }
        
        self.security_logger.warning(f"SECURITY_ALERT: {json.dumps(security_log)}")

    def simulate_authentication_events(self):
        """Simulate authentication events and potential attacks"""
        if random.random() < 0.05:  # 5% chance of failed auth
            self.failed_auth_attempts += 1
            
            auth_event = {
                "event_type": "authentication_failure",
                "charger_id": self.charger_id,
                "failed_attempts": self.failed_auth_attempts,
                "user_id": f"unknown_user_{random.randint(1000, 9999)}",
                "method": random.choice(["RFID", "Mobile_App", "Admin_Panel"]),
                "timestamp": datetime.now().isoformat()
            }
            
            self.logger.warning(f"Authentication failure: {json.dumps(auth_event)}")
            
            if self.failed_auth_attempts > 5:
                self.generate_security_event("MULTIPLE_AUTH_FAILURES", "high",
                                           f"{self.failed_auth_attempts} consecutive auth failures")
                self.failed_auth_attempts = 0  # Reset counter

    def send_heartbeat(self):
        """Send heartbeat to monitoring system"""
        heartbeat_data = {
            "event_type": "heartbeat",
            "charger_id": self.charger_id,
            "status": self.status,
            "location": self.location,
            "firmware_version": self.firmware_version,
            "active_sessions": len(self.active_sessions),
            "uptime": time.time(),
            "timestamp": datetime.now().isoformat()
        }
        
        self.logger.info(f"Heartbeat: {json.dumps(heartbeat_data)}")

    def run_monitoring_cycle(self):
        """Main monitoring cycle"""
        while self.is_running:
            try:
                # Random events simulation
                if random.random() < 0.3:  # 30% chance to start new session
                    if len(self.active_sessions) < 3:  # Max 3 concurrent sessions
                        self.start_charging_session()
                
                # End some sessions randomly
                if self.active_sessions and random.random() < 0.2:
                    session_to_end = random.choice(list(self.active_sessions.keys()))
                    self.end_charging_session(session_to_end)
                
                # Monitor system health
                self.monitor_system_health()
                
                # Monitor network security
                self.monitor_network_security()
                
                # Simulate authentication events
                self.simulate_authentication_events()
                
                # Send heartbeat every 60 seconds
                if int(time.time()) % 60 == 0:
                    self.send_heartbeat()
                
                time.sleep(10)  # Monitor every 10 seconds
                
            except KeyboardInterrupt:
                self.logger.info("Shutting down charger agent...")
                self.is_running = False
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring cycle: {e}")
                time.sleep(5)

def main():
    """Main function to start the EV charger agent"""
    charger_id = os.getenv('CHARGER_ID', 'EVCharge_001')
    location = os.getenv('CHARGER_LOCATION', 'Default_Location')
    wazuh_manager_ip = os.getenv('WAZUH_MANAGER_IP', 'localhost')
    
    agent = EVChargerAgent(charger_id, location, wazuh_manager_ip)
    
    try:
        agent.run_monitoring_cycle()
    except Exception as e:
        agent.logger.error(f"Fatal error: {e}")
    finally:
        agent.logger.info("EV Charger Agent stopped")

if __name__ == "__main__":
    main()