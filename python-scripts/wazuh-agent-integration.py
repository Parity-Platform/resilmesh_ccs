#!/usr/bin/env python3
"""
Wazuh Agent Integration Module
Handles communication between EV charging points and Wazuh SIEM
Sends security events, logs, and receives active response commands
"""

import json
import socket
import ssl
import threading
import time
import logging
import os
import subprocess
import requests
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
import hashlib
import base64

@dataclass
class WazuhEvent:
    timestamp: str
    agent_id: str
    event_type: str
    severity: str
    description: str
    raw_data: Dict
    rule_id: Optional[str] = None
    location: Optional[str] = None

class WazuhAgentIntegration:
    def __init__(self, agent_name: str, manager_ip: str, manager_port: int = 1514):
        self.agent_name = agent_name
        self.manager_ip = manager_ip
        self.manager_port = manager_port
        self.agent_key = None
        self.is_connected = False
        self.is_running = True
        
        # Setup logging
        self.setup_logging()
        
        # API configuration
        self.api_port = 55000
        self.api_user = os.getenv('WAZUH_API_USER', 'wazuh-wui')
        self.api_password = os.getenv('WAZUH_API_PASSWORD', 'MyS3cr37P450r.*-')
        self.api_token = None
        
        # Event queues
        self.event_queue = []
        self.response_handlers: Dict[str, Callable] = {}
        
        # Initialize connection
        self.initialize_agent()

    def setup_logging(self):
        """Setup logging for Wazuh integration"""
        self.logger = logging.getLogger(f"WazuhAgent-{self.agent_name}")
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def initialize_agent(self):
        """Initialize Wazuh agent configuration"""
        try:
            # Generate agent key (in production, this would be managed properly)
            self.agent_key = self.generate_agent_key()
            
            # Authenticate with Wazuh API
            self.authenticate_api()
            
            # Register agent if needed
            self.register_agent()
            
            self.logger.info(f"Wazuh agent {self.agent_name} initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Wazuh agent: {e}")

    def generate_agent_key(self) -> str:
        """Generate a simple agent key for communication"""
        # In production, use proper key exchange with Wazuh manager
        key_material = f"{self.agent_name}{self.manager_ip}{int(time.time())}"
        return hashlib.sha256(key_material.encode()).hexdigest()

    def authenticate_api(self):
        """Authenticate with Wazuh API to get access token"""
        try:
            url = f"https://{self.manager_ip}:{self.api_port}/security/user/authenticate"
            
            # Disable SSL verification for demo (enable in production)
            auth_data = {
                "user": self.api_user,
                "password": self.api_password
            }
            
            response = requests.post(
                url, 
                json=auth_data, 
                verify=False,  # In production, use proper SSL verification
                timeout=10
            )
            
            if response.status_code == 200:
                self.api_token = response.json().get('data', {}).get('token')
                self.logger.info("Successfully authenticated with Wazuh API")
            else:
                self.logger.warning(f"API authentication failed: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"API authentication error: {e}")

    def register_agent(self):
        """Register agent with Wazuh manager"""
        if not self.api_token:
            self.logger.warning("Cannot register agent without API token")
            return
            
        try:
            url = f"https://{self.manager_ip}:{self.api_port}/agents"
            headers = {
                'Authorization': f'Bearer {self.api_token}',
                'Content-Type': 'application/json'
            }
            
            agent_data = {
                'name': self.agent_name,
                'ip': self.get_local_ip(),
                'force': {'enabled': True}
            }
            
            response = requests.post(
                url,
                json=agent_data,
                headers=headers,
                verify=False,
                timeout=10
            )
            
            if response.status_code in [200, 409]:  # 409 = already exists
                self.logger.info(f"Agent {self.agent_name} registered/exists in Wazuh")
            else:
                self.logger.warning(f"Agent registration failed: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Agent registration error: {e}")

    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def send_event(self, event_type: str, severity: str, description: str, 
                   raw_data: Dict, rule_id: str = None, location: str = None):
        """Send security event to Wazuh manager"""
        event = WazuhEvent(
            timestamp=datetime.now().isoformat(),
            agent_id=self.agent_name,
            event_type=event_type,
            severity=severity,
            description=description,
            raw_data=raw_data,
            rule_id=rule_id,
            location=location
        )
        
        self.queue_event(event)

    def queue_event(self, event: WazuhEvent):
        """Queue event for transmission"""
        self.event_queue.append(event)
        self.logger.debug(f"Queued event: {event.event_type}")

    def send_queued_events(self):
        """Send all queued events to Wazuh manager"""
        if not self.event_queue:
            return
            
        try:
            # In a real implementation, this would use the Wazuh agent protocol
            # For demo purposes, we'll log the events in Wazuh format
            
            for event in self.event_queue:
                wazuh_log = self.format_wazuh_log(event)
                self.send_to_wazuh(wazuh_log)
                
            self.event_queue.clear()
            
        except Exception as e:
            self.logger.error(f"Failed to send events: {e}")

    def format_wazuh_log(self, event: WazuhEvent) -> str:
        """Format event as Wazuh log entry"""
        # Standard Wazuh log format
        log_entry = {
            "timestamp": event.timestamp,
            "agent": {
                "id": "001",  # In production, use actual agent ID
                "name": event.agent_id,
                "ip": self.get_local_ip()
            },
            "manager": {
                "name": self.manager_ip
            },
            "id": event.rule_id or "100001",
            "full_log": event.description,
            "decoder": {
                "name": "ev-charger-decoder"
            },
            "data": event.raw_data,
            "location": event.location or f"ev-charger-{self.agent_name}",
            "rule": {
                "level": self.severity_to_level(event.severity),
                "description": event.description,
                "id": event.rule_id or "100001",
                "groups": ["ev_charger", "security"]
            }
        }
        
        return json.dumps(log_entry)

    def severity_to_level(self, severity: str) -> int:
        """Convert severity string to Wazuh level"""
        severity_map = {
            "low": 3,
            "medium": 5,
            "warning": 7,
            "high": 10,
            "critical": 12
        }
        return severity_map.get(severity.lower(), 5)

    def send_to_wazuh(self, log_entry: str):
        """Send formatted log to Wazuh manager"""
        try:
            # Method 1: Send via syslog (most common)
            self.send_via_syslog(log_entry)
            
            # Method 2: Write to monitored log file
            self.write_to_monitored_log(log_entry)
            
        except Exception as e:
            self.logger.error(f"Failed to send log to Wazuh: {e}")

    def send_via_syslog(self, message: str):
        """Send message via syslog to Wazuh manager"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Syslog format: <priority>timestamp hostname tag: message
            priority = 165  # local4.notice
            hostname = socket.gethostname()
            tag = f"ev-charger-{self.agent_name}"
            
            syslog_msg = f"<{priority}>{datetime.now().strftime('%b %d %H:%M:%S')} {hostname} {tag}: {message}"
            
            sock.sendto(syslog_msg.encode(), (self.manager_ip, 514))
            sock.close()
            
            self.logger.debug("Event sent via syslog")
            
        except Exception as e:
            self.logger.error(f"Syslog transmission failed: {e}")

    def write_to_monitored_log(self, message: str):
        """Write to log file monitored by Wazuh agent"""
        try:
            log_dir = "/var/log/wazuh"
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = f"{log_dir}/{self.agent_name}-events.log"
            
            with open(log_file, 'a') as f:
                f.write(f"{datetime.now().isoformat()} {message}\n")
                
            self.logger.debug("Event written to monitored log")
            
        except Exception as e:
            self.logger.error(f"Failed to write to monitored log: {e}")

    def register_response_handler(self, command: str, handler: Callable):
        """Register handler for active response commands"""
        self.response_handlers[command] = handler
        self.logger.info(f"Registered response handler for: {command}")

    def handle_active_response(self, command: str, parameters: Dict):
        """Handle active response command from Wazuh"""
        if command in self.response_handlers:
            try:
                self.response_handlers[command](parameters)
                self.logger.info(f"Executed active response: {command}")
            except Exception as e:
                self.logger.error(f"Active response failed: {e}")
        else:
            self.logger.warning(f"Unknown active response command: {command}")

    def start_event_sender(self):
        """Start background thread to send events"""
        def sender_loop():
            while self.is_running:
                try:
                    self.send_queued_events()
                    time.sleep(5)  # Send events every 5 seconds
                except Exception as e:
                    self.logger.error(f"Event sender error: {e}")
                    time.sleep(10)
        
        sender_thread = threading.Thread(target=sender_loop, daemon=True)
        sender_thread.start()
        self.logger.info("Event sender thread started")

    def start_command_listener(self):
        """Start background thread to listen for commands"""
        def listener_loop():
            while self.is_running:
                try:
                    # In production, implement proper command receiving
                    # For demo, we'll simulate command reception
                    time.sleep(30)
                    
                except Exception as e:
                    self.logger.error(f"Command listener error: {e}")
                    time.sleep(10)
        
        listener_thread = threading.Thread(target=listener_loop, daemon=True)
        listener_thread.start()
        self.logger.info("Command listener thread started")

    def start(self):
        """Start the Wazuh integration"""
        self.start_event_sender()
        self.start_command_listener()
        self.is_connected = True
        self.logger.info("Wazuh integration started")

    def stop(self):
        """Stop the Wazuh integration"""
        self.is_running = False
        self.is_connected = False
        
        # Send any remaining events
        self.send_queued_events()
        
        self.logger.info("Wazuh integration stopped")

    def send_heartbeat(self):
        """Send heartbeat to Wazuh"""
        heartbeat_data = {
            "agent_name": self.agent_name,
            "status": "active",
            "timestamp": datetime.now().isoformat(),
            "local_ip": self.get_local_ip()
        }
        
        self.send_event(
            event_type="agent_heartbeat",
            severity="low",
            description=f"Heartbeat from agent {self.agent_name}",
            raw_data=heartbeat_data,
            rule_id="100000"
        )

# Example active response handlers for EV chargers
def block_charging_session(parameters: Dict):
    """Block a charging session (active response)"""
    session_id = parameters.get('session_id')
    logging.info(f"ACTIVE RESPONSE: Blocking charging session {session_id}")
    # Implementation would stop the charging session

def restart_charger(parameters: Dict):
    """Restart charger (active response)"""
    logging.info("ACTIVE RESPONSE: Restarting charger system")
    # Implementation would safely restart the charger

def update_firmware(parameters: Dict):
    """Update charger firmware (active response)"""
    version = parameters.get('version')
    logging.info(f"ACTIVE RESPONSE: Updating firmware to version {version}")
    # Implementation would initiate firmware update

def isolate_network(parameters: Dict):
    """Isolate charger from network (active response)"""
    logging.info("ACTIVE RESPONSE: Isolating charger from network")
    # Implementation would restrict network access

if __name__ == "__main__":
    # Example usage
    agent_name = os.getenv('CHARGER_ID', 'EVCharge_001')
    manager_ip = os.getenv('WAZUH_MANAGER_IP', 'localhost')
    
    wazuh_agent = WazuhAgentIntegration(agent_name, manager_ip)
    
    # Register active response handlers
    wazuh_agent.register_response_handler("block_session", block_charging_session)
    wazuh_agent.register_response_handler("restart_charger", restart_charger)
    wazuh_agent.register_response_handler("update_firmware", update_firmware)
    wazuh_agent.register_response_handler("isolate_network", isolate_network)
    
    try:
        wazuh_agent.start()
        
        # Send test event
        wazuh_agent.send_event(
            event_type="test_event",
            severity="low",
            description="Test event from EV charger",
            raw_data={"test": True, "charger_id": agent_name}
        )
        
        # Keep running
        while True:
            wazuh_agent.send_heartbeat()
            time.sleep(60)
            
    except KeyboardInterrupt:
        wazuh_agent.stop()
        print("Wazuh agent stopped")