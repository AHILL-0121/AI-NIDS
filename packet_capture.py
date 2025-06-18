import threading
import time
from typing import Dict, List, Any, Optional, Callable
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import queue
from utils import logger, config, DataStructures

class PacketCapture:
    """Real-time packet capture and processing"""
    
    def __init__(self, interface: str = None, callback: Callable = None):
        self.interface = interface or config.get('network_interface', 'Ethernet')
        self.callback = callback
        self.is_running = False
        self.packet_queue = queue.Queue(maxsize=10000)
        self.packet_buffer = DataStructures.CircularBuffer(
            max_size=config.get('max_packets_per_batch', 1000)
        )
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'bytes_captured': 0,
            'start_time': time.time()
        }
        self.lock = threading.Lock()
        
        # Rate limiters for different alert types
        self.port_scan_limiter = DataStructures.RateLimiter(10, 60)  # 10 events per minute
        self.ddos_limiter = DataStructures.RateLimiter(5, 60)  # 5 events per minute
        
        logger.info(f"Packet capture initialized on interface: {self.interface}")
    
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.is_running:
            logger.warning("Packet capture is already running")
            return
        
        self.is_running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        
        # Start processing thread
        self.process_thread = threading.Thread(target=self._process_loop, daemon=True)
        self.process_thread.start()
        
        logger.info("Packet capture started")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_running = False
        # Try to unblock sniff() by sending a dummy packet (if interface is up)
        try:
            sendp(Ether()/IP(dst="127.0.0.1"), iface=self.interface, count=1, verbose=False)
        except Exception as e:
            logger.debug(f"Could not send dummy packet to unblock sniff: {e}")
        # Join threads to ensure they stop
        if hasattr(self, 'capture_thread') and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        if hasattr(self, 'process_thread') and self.process_thread.is_alive():
            self.process_thread.join(timeout=2)
        logger.info("Packet capture stopped")
    
    def _capture_loop(self):
        """Main capture loop"""
        try:
            # Start sniffing packets
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=0,  # Don't store packets in memory
                stop_filter=lambda _: not self.is_running
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.is_running = False
    
    def _packet_handler(self, packet):
        """Handle individual packets"""
        try:
            if not self.is_running:
                return
            
            # Extract basic packet info
            packet_info = self._extract_packet_info(packet)
            
            if packet_info:
                # Add to queue for processing
                try:
                    self.packet_queue.put(packet_info, timeout=0.1)
                except queue.Full:
                    logger.warning("Packet queue is full, dropping packet")
                
                # Update statistics
                self._update_stats(packet_info)
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """Extract relevant information from packet"""
        try:
            packet_info = {
                'timestamp': time.time(),
                'length': len(packet),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'flags': None,
                'payload_size': 0
            }
            
            # Extract IP layer
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto
                
                # Extract TCP layer
                if TCP in packet:
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    packet_info['flags'] = packet[TCP].flags
                    packet_info['payload_size'] = len(packet[TCP].payload)
                
                # Extract UDP layer
                elif UDP in packet:
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    packet_info['payload_size'] = len(packet[UDP].payload)
                
                # Extract ICMP layer
                elif ICMP in packet:
                    packet_info['payload_size'] = len(packet[ICMP].payload)
            
            return packet_info
            
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _update_stats(self, packet_info: Dict[str, Any]):
        """Update capture statistics"""
        with self.lock:
            self.stats['total_packets'] += 1
            self.stats['bytes_captured'] += packet_info['length']
            
            protocol = packet_info.get('protocol')
            if protocol == 6:  # TCP
                self.stats['tcp_packets'] += 1
            elif protocol == 17:  # UDP
                self.stats['udp_packets'] += 1
            elif protocol == 1:  # ICMP
                self.stats['icmp_packets'] += 1
            else:
                self.stats['other_packets'] += 1
    
    def _process_loop(self):
        """Process packets from queue"""
        while self.is_running:
            try:
                # Get packet from queue with timeout
                packet_info = self.packet_queue.get(timeout=1)
                
                # Add to buffer
                self.packet_buffer.add(packet_info)
                
                # Check for anomalies
                self._check_anomalies(packet_info)
                
                # Call callback if provided
                if self.callback:
                    self.callback(packet_info)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in packet processing: {e}")
    
    def _check_anomalies(self, packet_info: Dict[str, Any]):
        """Check for basic anomalies in real-time"""
        try:
            # Check for port scanning
            if self._is_port_scan(packet_info):
                if self.port_scan_limiter.is_allowed():
                    self._raise_alert('port_scan', {
                        'src_ip': packet_info['src_ip'],
                        'dst_ip': packet_info['dst_ip'],
                        'dst_port': packet_info['dst_port'],
                        'protocol': packet_info['protocol']
                    })
            
            # Check for DDoS indicators
            if self._is_ddos_indicator(packet_info):
                if self.ddos_limiter.is_allowed():
                    self._raise_alert('ddos_indicator', {
                        'src_ip': packet_info['src_ip'],
                        'dst_ip': packet_info['dst_ip'],
                        'packet_size': packet_info['length'],
                        'protocol': packet_info['protocol']
                    })
            
            # Check for unusual protocols
            if self._is_unusual_protocol(packet_info):
                self._raise_alert('unusual_protocol', {
                    'src_ip': packet_info['src_ip'],
                    'dst_ip': packet_info['dst_ip'],
                    'protocol': packet_info['protocol']
                })
                
        except Exception as e:
            logger.error(f"Error checking anomalies: {e}")
    
    def _is_port_scan(self, packet_info: Dict[str, Any]) -> bool:
        """Detect potential port scanning"""
        # This is a simplified check - in a real system, you'd track connection attempts
        # over time windows and look for patterns
        dst_port = packet_info.get('dst_port')
        if dst_port:
            # Check for common scanning ports
            scanning_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
            return dst_port in scanning_ports
        return False
    
    def _is_ddos_indicator(self, packet_info: Dict[str, Any]) -> bool:
        """Detect potential DDoS indicators"""
        # Check for large payload sizes or unusual packet characteristics
        payload_size = packet_info.get('payload_size', 0)
        packet_length = packet_info.get('length', 0)
        
        # Large payload or unusual packet size
        if payload_size > 1400 or packet_length > 1500:
            return True
        
        return False
    
    def _is_unusual_protocol(self, packet_info: Dict[str, Any]) -> bool:
        """Detect unusual protocols"""
        protocol = packet_info.get('protocol')
        unusual_protocols = [2, 3, 4, 5, 7, 8, 9, 11, 12, 13, 14, 15, 16, 18, 19, 20]
        return protocol in unusual_protocols
    
    def _raise_alert(self, alert_type: str, details: Dict[str, Any]):
        """Raise an alert"""
        from utils import alert_manager
        
        if alert_manager.add_alert(alert_type, details):
            logger.warning(f"ALERT: {alert_type} - {details}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get capture statistics"""
        with self.lock:
            stats = self.stats.copy()
            stats['uptime'] = time.time() - stats['start_time']
            stats['packets_per_second'] = stats['total_packets'] / max(stats['uptime'], 1)
            stats['bytes_per_second'] = stats['bytes_captured'] / max(stats['uptime'], 1)
            return stats
    
    def get_recent_packets(self, count: int = 100) -> List[Dict[str, Any]]:
        """Get recent packets"""
        return self.packet_buffer.get_recent(count)
    
    def clear_buffer(self):
        """Clear packet buffer"""
        self.packet_buffer.clear()

class PCAPReader:
    """Read packets from PCAP files for training/testing"""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets = []
    
    def read_packets(self, max_packets: int = None) -> List[Dict[str, Any]]:
        """Read packets from PCAP file"""
        try:
            packets = rdpcap(self.pcap_file)
            packet_list = []
            
            for i, packet in enumerate(packets):
                if max_packets and i >= max_packets:
                    break
                
                packet_info = self._extract_packet_info(packet)
                if packet_info:
                    packet_list.append(packet_info)
            
            logger.info(f"Read {len(packet_list)} packets from {self.pcap_file}")
            return packet_list
            
        except Exception as e:
            logger.error(f"Error reading PCAP file: {e}")
            return []
    
    def _extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """Extract packet information (same as PacketCapture)"""
        try:
            packet_info = {
                'timestamp': packet.time,
                'length': len(packet),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'flags': None,
                'payload_size': 0
            }
            
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto
                
                if TCP in packet:
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    packet_info['flags'] = packet[TCP].flags
                    packet_info['payload_size'] = len(packet[TCP].payload)
                
                elif UDP in packet:
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    packet_info['payload_size'] = len(packet[UDP].payload)
                
                elif ICMP in packet:
                    packet_info['payload_size'] = len(packet[ICMP].payload)
            
            return packet_info
            
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return None 