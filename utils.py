import os
import json
import logging
from datetime import datetime
from collections import defaultdict, deque
import threading
from typing import Dict, List, Any, Optional
import ipaddress

class Config:
    """Configuration management for NIDS"""
    
    def __init__(self):
        self.config = {
            'network_interface': 'Ethernet',  # Default interface
            'packet_capture_timeout': 1,
            'max_packets_per_batch': 1000,
            'feature_window_size': 100,
            'anomaly_threshold': 0.7,
            'alert_cooldown': 60,  # seconds
            'web_port': 5000,
            'model_path': 'models/nids_model.pkl',
            'log_level': 'INFO',
            'max_log_size': 10 * 1024 * 1024,  # 10MB
            'backup_count': 5,
            'model_type': 'ensemble'
        }
    
    def get(self, key: str, default=None):
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        self.config[key] = value
    
    def load_from_env(self):
        """Load configuration from environment variables"""
        # Network settings
        self.set('network_interface', os.getenv('NIDS_NETWORK_INTERFACE', 'Ethernet'))
        self.set('anomaly_threshold', float(os.getenv('NIDS_ANOMALY_THRESHOLD', '0.7')))
        self.set('feature_window_size', int(os.getenv('NIDS_FEATURE_WINDOW_SIZE', '100')))
        
        # Alert settings
        self.set('alert_cooldown', int(os.getenv('NIDS_ALERT_COOLDOWN', '60')))
        self.set('max_alerts', int(os.getenv('NIDS_MAX_ALERTS', '1000')))
        
        # Web settings
        self.set('web_port', int(os.getenv('NIDS_WEB_PORT', '5000')))
        self.set('log_level', os.getenv('NIDS_LOG_LEVEL', 'INFO'))
        
        # Model settings
        self.set('model_path', os.getenv('NIDS_MODEL_PATH', 'models/nids_model.pkl'))
        self.set('model_type', os.getenv('NIDS_MODEL_TYPE', 'ensemble'))
        
        logger.info("Configuration loaded from environment variables")

class Logger:
    """Centralized logging for NIDS"""
    
    def __init__(self, name: str = 'NIDS'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # File handler
        file_handler = logging.FileHandler('logs/nids.log', encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Console handler with UTF-8 encoding
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        # Replace Unicode characters with ASCII equivalents for Windows compatibility
        safe_message = message.replace('⚠️', '[WARNING]').replace('✅', '[SUCCESS]').replace('❌', '[ERROR]')
        self.logger.warning(safe_message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def critical(self, message: str):
        self.logger.critical(message)

class AlertManager:
    """Manages alerts and prevents spam"""
    
    def __init__(self, cooldown: int = 60):
        self.cooldown = cooldown
        self.alerts = deque(maxlen=1000)
        self.alert_timestamps = defaultdict(float)
        self.lock = threading.Lock()
    
    def add_alert(self, alert_type: str, details: Dict[str, Any]) -> bool:
        """Add alert if not in cooldown period"""
        current_time = datetime.now().timestamp()
        explanation = self.get_alert_explanation(alert_type, details)
        with self.lock:
            last_alert_time = self.alert_timestamps.get(alert_type, 0)
            if current_time - last_alert_time >= self.cooldown:
                alert = {
                    'timestamp': current_time,
                    'type': alert_type,
                    'details': details,
                    'datetime': datetime.now().isoformat(),
                    'explanation': explanation
                }
                self.alerts.append(alert)
                self.alert_timestamps[alert_type] = current_time
                return True
        return False
    
    def get_alert_explanation(self, alert_type, details):
        if alert_type == 'port_scan':
            return 'A port scan was detected. This means a host is rapidly probing multiple ports on a target, which is often a precursor to an attack.'
        elif alert_type == 'ddos_indicator':
            return 'Possible Distributed Denial of Service (DDoS) activity detected. This means a large number of packets are being sent to a target, which may overwhelm the system.'
        elif alert_type == 'unusual_protocol':
            return 'Unusual network protocol detected. This could indicate suspicious or unauthorized network activity.'
        elif alert_type == 'ml_anomaly':
            return 'The machine learning model detected traffic that is statistically unusual compared to normal patterns.'
        else:
            return f'Alert type: {alert_type}. See details for more information.'
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        with self.lock:
            return list(self.alerts)[-limit:]
    
    def get_alert_stats(self) -> Dict[str, int]:
        """Get alert statistics"""
        with self.lock:
            stats = defaultdict(int)
            for alert in self.alerts:
                stats[alert['type']] += 1
            return dict(stats)

class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is private"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    @staticmethod
    def is_localhost(ip: str) -> bool:
        """Check if IP is localhost"""
        return ip in ['127.0.0.1', '::1', 'localhost']
    
    @staticmethod
    def get_common_ports() -> Dict[str, int]:
        """Get common port numbers"""
        return {
            'HTTP': 80,
            'HTTPS': 443,
            'SSH': 22,
            'FTP': 21,
            'SMTP': 25,
            'DNS': 53,
            'DHCP': 67,
            'HTTP_ALT': 8080,
            'MYSQL': 3306,
            'POSTGRES': 5432,
            'REDIS': 6379,
            'MONGODB': 27017
        }
    
    @staticmethod
    def get_protocol_name(protocol_number: int) -> str:
        """Get protocol name from number"""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            2: 'IGMP',
            89: 'OSPF'
        }
        return protocols.get(protocol_number, f'Protocol_{protocol_number}')

class DataStructures:
    """Thread-safe data structures for NIDS"""
    
    class CircularBuffer:
        """Thread-safe circular buffer"""
        
        def __init__(self, max_size: int = 1000):
            self.max_size = max_size
            self.buffer = deque(maxlen=max_size)
            self.lock = threading.Lock()
        
        def add(self, item: Any):
            """Add item to buffer"""
            with self.lock:
                self.buffer.append(item)
        
        def get_all(self) -> List[Any]:
            """Get all items"""
            with self.lock:
                return list(self.buffer)
        
        def get_recent(self, count: int) -> List[Any]:
            """Get recent items"""
            with self.lock:
                return list(self.buffer)[-count:]
        
        def clear(self):
            """Clear buffer"""
            with self.lock:
                self.buffer.clear()
        
        def size(self) -> int:
            """Get buffer size"""
            with self.lock:
                return len(self.buffer)
    
    class RateLimiter:
        """Rate limiter for events"""
        
        def __init__(self, max_events: int, time_window: int):
            self.max_events = max_events
            self.time_window = time_window
            self.events = deque()
            self.lock = threading.Lock()
        
        def is_allowed(self) -> bool:
            """Check if event is allowed"""
            current_time = datetime.now().timestamp()
            
            with self.lock:
                # Remove old events
                while self.events and current_time - self.events[0] > self.time_window:
                    self.events.popleft()
                
                # Check if we can add new event
                if len(self.events) < self.max_events:
                    self.events.append(current_time)
                    return True
            
            return False

# Global instances
config = Config()
logger = Logger()
alert_manager = AlertManager() 