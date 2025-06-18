import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import time
from datetime import datetime, timedelta
from utils import logger, config, NetworkUtils

class FeatureExtractor:
    """Extract features from network packets for ML models"""
    
    def __init__(self, window_size: int = None):
        self.window_size = window_size or config.get('feature_window_size', 100)
        self.packet_buffer = []
        self.connection_stats = defaultdict(lambda: {
            'packet_count': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'first_seen': None,
            'last_seen': None,
            'ports_accessed': set(),
            'protocols': set()
        })
        self.ip_stats = defaultdict(lambda: {
            'packet_count': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'connections': set(),
            'ports_accessed': set(),
            'protocols': set()
        })
        
        # Feature normalization parameters
        self.feature_stats = {
            'packet_length_mean': 0,
            'packet_length_std': 1,
            'payload_size_mean': 0,
            'payload_size_std': 1,
            'port_mean': 0,
            'port_std': 1
        }
        
        logger.info(f"Feature extractor initialized with window size: {self.window_size}")
    
    def add_packet(self, packet_info: Dict[str, Any]):
        """Add packet to buffer and update statistics"""
        try:
            # Add to buffer
            self.packet_buffer.append(packet_info)
            
            # Keep only recent packets
            if len(self.packet_buffer) > self.window_size:
                self.packet_buffer.pop(0)
            
            # Update connection statistics
            self._update_connection_stats(packet_info)
            
            # Update IP statistics
            self._update_ip_stats(packet_info)
            
        except Exception as e:
            logger.error(f"Error adding packet to feature extractor: {e}")
    
    def _update_connection_stats(self, packet_info: Dict[str, Any]):
        """Update connection-level statistics"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol')
        
        if src_ip and dst_ip:
            # Create connection key
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            reverse_conn_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            
            # Use the connection key that comes first alphabetically
            conn_key = min(conn_key, reverse_conn_key)
            
            stats = self.connection_stats[conn_key]
            current_time = packet_info.get('timestamp', time.time())
            
            # Update statistics
            stats['packet_count'] += 1
            stats['last_seen'] = current_time
            
            if stats['first_seen'] is None:
                stats['first_seen'] = current_time
            
            # Update bytes
            packet_length = packet_info.get('length', 0)
            if src_ip == conn_key.split('-')[0].split(':')[0]:
                stats['bytes_sent'] += packet_length
            else:
                stats['bytes_received'] += packet_length
            
            # Update ports and protocols
            if dst_port:
                stats['ports_accessed'].add(dst_port)
            if protocol:
                stats['protocols'].add(protocol)
    
    def _update_ip_stats(self, packet_info: Dict[str, Any]):
        """Update IP-level statistics"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol')
        packet_length = packet_info.get('length', 0)
        
        # Update source IP stats
        if src_ip:
            src_stats = self.ip_stats[src_ip]
            src_stats['packet_count'] += 1
            src_stats['bytes_sent'] += packet_length
            if dst_ip:
                src_stats['connections'].add(dst_ip)
            if dst_port:
                src_stats['ports_accessed'].add(dst_port)
            if protocol:
                src_stats['protocols'].add(protocol)
        
        # Update destination IP stats
        if dst_ip:
            dst_stats = self.ip_stats[dst_ip]
            dst_stats['packet_count'] += 1
            dst_stats['bytes_received'] += packet_length
            if src_ip:
                dst_stats['connections'].add(src_ip)
            if src_port:
                dst_stats['ports_accessed'].add(src_port)
            if protocol:
                dst_stats['protocols'].add(protocol)
    
    def extract_features(self) -> Dict[str, Any]:
        """Extract features from current packet buffer"""
        try:
            if not self.packet_buffer:
                return self._get_empty_features()
            
            features = {}
            
            # Basic packet statistics
            features.update(self._extract_basic_stats())
            
            # Protocol distribution
            features.update(self._extract_protocol_features())
            
            # Port distribution
            features.update(self._extract_port_features())
            
            # Connection patterns
            features.update(self._extract_connection_features())
            
            # IP behavior patterns
            features.update(self._extract_ip_behavior_features())
            
            # Time-based features
            features.update(self._extract_time_features())
            
            # Payload and size features
            features.update(self._extract_payload_features())
            
            # Flag patterns (TCP)
            features.update(self._extract_flag_features())
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return self._get_empty_features()
    
    def _extract_basic_stats(self) -> Dict[str, Any]:
        """Extract basic packet statistics"""
        packet_lengths = [p.get('length', 0) for p in self.packet_buffer]
        payload_sizes = [p.get('payload_size', 0) for p in self.packet_buffer]
        
        return {
            'packet_count': len(self.packet_buffer),
            'total_bytes': sum(packet_lengths),
            'avg_packet_length': np.mean(packet_lengths) if packet_lengths else 0,
            'std_packet_length': np.std(packet_lengths) if packet_lengths else 0,
            'min_packet_length': min(packet_lengths) if packet_lengths else 0,
            'max_packet_length': max(packet_lengths) if packet_lengths else 0,
            'avg_payload_size': np.mean(payload_sizes) if payload_sizes else 0,
            'std_payload_size': np.std(payload_sizes) if payload_sizes else 0,
            'total_payload_size': sum(payload_sizes)
        }
    
    def _extract_protocol_features(self) -> Dict[str, Any]:
        """Extract protocol-related features"""
        protocols = [p.get('protocol') for p in self.packet_buffer if p.get('protocol')]
        protocol_counts = Counter(protocols)
        
        features = {
            'tcp_count': protocol_counts.get(6, 0),
            'udp_count': protocol_counts.get(17, 0),
            'icmp_count': protocol_counts.get(1, 0),
            'other_protocol_count': sum(count for proto, count in protocol_counts.items() 
                                      if proto not in [1, 6, 17]),
            'protocol_diversity': len(protocol_counts)
        }
        
        # Protocol ratios
        total = len(protocols) if protocols else 1
        features.update({
            'tcp_ratio': features['tcp_count'] / total,
            'udp_ratio': features['udp_count'] / total,
            'icmp_ratio': features['icmp_count'] / total,
            'other_protocol_ratio': features['other_protocol_count'] / total
        })
        
        return features
    
    def _extract_port_features(self) -> Dict[str, Any]:
        """Extract port-related features"""
        src_ports = [p.get('src_port') for p in self.packet_buffer if p.get('src_port')]
        dst_ports = [p.get('dst_port') for p in self.packet_buffer if p.get('dst_port')]
        
        # Common ports
        common_ports = NetworkUtils.get_common_ports()
        common_port_values = set(common_ports.values())
        
        features = {
            'unique_src_ports': len(set(src_ports)),
            'unique_dst_ports': len(set(dst_ports)),
            'total_ports_accessed': len(set(src_ports + dst_ports)),
            'common_port_ratio': len([p for p in dst_ports if p in common_port_values]) / max(len(dst_ports), 1),
            'high_port_ratio': len([p for p in dst_ports if p > 1024]) / max(len(dst_ports), 1)
        }
        
        # Port statistics
        if dst_ports:
            features.update({
                'avg_dst_port': np.mean(dst_ports),
                'std_dst_port': np.std(dst_ports),
                'min_dst_port': min(dst_ports),
                'max_dst_port': max(dst_ports)
            })
        
        return features
    
    def _extract_connection_features(self) -> Dict[str, Any]:
        """Extract connection pattern features"""
        connections = []
        for p in self.packet_buffer:
            src_ip = p.get('src_ip')
            dst_ip = p.get('dst_ip')
            if src_ip and dst_ip:
                conn = f"{src_ip}-{dst_ip}"
                connections.append(conn)
        
        unique_connections = set(connections)
        connection_counts = Counter(connections)
        
        return {
            'unique_connections': len(unique_connections),
            'total_connection_attempts': len(connections),
            'avg_packets_per_connection': len(connections) / max(len(unique_connections), 1),
            'connection_diversity': len(unique_connections) / max(len(self.packet_buffer), 1),
            'max_packets_per_connection': max(connection_counts.values()) if connection_counts else 0
        }
    
    def _extract_ip_behavior_features(self) -> Dict[str, Any]:
        """Extract IP behavior patterns"""
        src_ips = [p.get('src_ip') for p in self.packet_buffer if p.get('src_ip')]
        dst_ips = [p.get('dst_ip') for p in self.packet_buffer if p.get('dst_ip')]
        
        # IP diversity
        unique_src_ips = set(src_ips)
        unique_dst_ips = set(dst_ips)
        
        # Private vs public IP analysis
        private_src_ips = [ip for ip in unique_src_ips if NetworkUtils.is_private_ip(ip)]
        private_dst_ips = [ip for ip in unique_dst_ips if NetworkUtils.is_private_ip(ip)]
        
        return {
            'unique_src_ips': len(unique_src_ips),
            'unique_dst_ips': len(unique_dst_ips),
            'src_ip_diversity': len(unique_src_ips) / max(len(self.packet_buffer), 1),
            'dst_ip_diversity': len(unique_dst_ips) / max(len(self.packet_buffer), 1),
            'private_src_ip_ratio': len(private_src_ips) / max(len(unique_src_ips), 1),
            'private_dst_ip_ratio': len(private_dst_ips) / max(len(unique_dst_ips), 1)
        }
    
    def _extract_time_features(self) -> Dict[str, Any]:
        """Extract time-based features"""
        if len(self.packet_buffer) < 2:
            return {
                'packet_rate': 0,
                'inter_arrival_time_mean': 0,
                'inter_arrival_time_std': 0,
                'burst_count': 0
            }
        
        timestamps = [p.get('timestamp', 0) for p in self.packet_buffer]
        timestamps.sort()
        
        # Calculate inter-arrival times
        inter_arrival_times = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        # Calculate packet rate
        time_window = timestamps[-1] - timestamps[0]
        packet_rate = len(timestamps) / max(time_window, 1)
        
        # Detect bursts (packets with very small inter-arrival times)
        burst_threshold = 0.001  # 1ms
        burst_count = len([t for t in inter_arrival_times if t < burst_threshold])
        
        return {
            'packet_rate': packet_rate,
            'inter_arrival_time_mean': np.mean(inter_arrival_times) if inter_arrival_times else 0,
            'inter_arrival_time_std': np.std(inter_arrival_times) if inter_arrival_times else 0,
            'burst_count': burst_count,
            'burst_ratio': burst_count / max(len(inter_arrival_times), 1)
        }
    
    def _extract_payload_features(self) -> Dict[str, Any]:
        """Extract payload-related features"""
        payload_sizes = [p.get('payload_size', 0) for p in self.packet_buffer]
        
        if not payload_sizes:
            return {
                'payload_size_mean': 0,
                'payload_size_std': 0,
                'zero_payload_ratio': 1,
                'large_payload_ratio': 0
            }
        
        zero_payload_count = len([p for p in payload_sizes if p == 0])
        large_payload_count = len([p for p in payload_sizes if p > 1000])
        
        return {
            'payload_size_mean': np.mean(payload_sizes),
            'payload_size_std': np.std(payload_sizes),
            'zero_payload_ratio': zero_payload_count / len(payload_sizes),
            'large_payload_ratio': large_payload_count / len(payload_sizes),
            'payload_size_entropy': self._calculate_entropy(payload_sizes)
        }
    
    def _extract_flag_features(self) -> Dict[str, Any]:
        """Extract TCP flag patterns"""
        tcp_packets = [p for p in self.packet_buffer if p.get('protocol') == 6]
        flags = [p.get('flags', 0) for p in tcp_packets]
        
        if not flags:
            return {
                'syn_count': 0,
                'fin_count': 0,
                'rst_count': 0,
                'psh_count': 0,
                'ack_count': 0,
                'urg_count': 0,
                'syn_ratio': 0,
                'fin_ratio': 0,
                'rst_ratio': 0
            }
        
        # Count individual flags
        syn_count = sum(1 for f in flags if f & 0x02)  # SYN flag
        fin_count = sum(1 for f in flags if f & 0x01)  # FIN flag
        rst_count = sum(1 for f in flags if f & 0x04)  # RST flag
        psh_count = sum(1 for f in flags if f & 0x08)  # PSH flag
        ack_count = sum(1 for f in flags if f & 0x10)  # ACK flag
        urg_count = sum(1 for f in flags if f & 0x20)  # URG flag
        
        total_tcp = len(flags)
        
        return {
            'syn_count': syn_count,
            'fin_count': fin_count,
            'rst_count': rst_count,
            'psh_count': psh_count,
            'ack_count': ack_count,
            'urg_count': urg_count,
            'syn_ratio': syn_count / total_tcp,
            'fin_ratio': fin_count / total_tcp,
            'rst_ratio': rst_count / total_tcp,
            'psh_ratio': psh_count / total_tcp,
            'ack_ratio': ack_count / total_tcp,
            'urg_ratio': urg_count / total_tcp
        }
    
    def _calculate_entropy(self, values: List[float]) -> float:
        """Calculate entropy of a list of values"""
        if not values:
            return 0
        
        # Discretize values into bins
        bins = np.histogram(values, bins=min(10, len(set(values))))[0]
        bins = bins[bins > 0]  # Remove zero bins
        
        if len(bins) <= 1:
            return 0
        
        # Calculate entropy
        probabilities = bins / bins.sum()
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    
    def _get_empty_features(self) -> Dict[str, Any]:
        """Return empty feature set"""
        return {
            'packet_count': 0,
            'total_bytes': 0,
            'avg_packet_length': 0,
            'std_packet_length': 0,
            'min_packet_length': 0,
            'max_packet_length': 0,
            'avg_payload_size': 0,
            'std_payload_size': 0,
            'total_payload_size': 0,
            'tcp_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'other_protocol_count': 0,
            'protocol_diversity': 0,
            'tcp_ratio': 0,
            'udp_ratio': 0,
            'icmp_ratio': 0,
            'other_protocol_ratio': 0,
            'unique_src_ports': 0,
            'unique_dst_ports': 0,
            'total_ports_accessed': 0,
            'common_port_ratio': 0,
            'high_port_ratio': 0,
            'avg_dst_port': 0,
            'std_dst_port': 0,
            'min_dst_port': 0,
            'max_dst_port': 0,
            'unique_connections': 0,
            'total_connection_attempts': 0,
            'avg_packets_per_connection': 0,
            'connection_diversity': 0,
            'max_packets_per_connection': 0,
            'unique_src_ips': 0,
            'unique_dst_ips': 0,
            'src_ip_diversity': 0,
            'dst_ip_diversity': 0,
            'private_src_ip_ratio': 0,
            'private_dst_ip_ratio': 0,
            'packet_rate': 0,
            'inter_arrival_time_mean': 0,
            'inter_arrival_time_std': 0,
            'burst_count': 0,
            'burst_ratio': 0,
            'payload_size_mean': 0,
            'payload_size_std': 0,
            'zero_payload_ratio': 0,
            'large_payload_ratio': 0,
            'payload_size_entropy': 0,
            'syn_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'psh_count': 0,
            'ack_count': 0,
            'urg_count': 0,
            'syn_ratio': 0,
            'fin_ratio': 0,
            'rst_ratio': 0,
            'psh_ratio': 0,
            'ack_ratio': 0,
            'urg_ratio': 0
        }
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names"""
        return list(self._get_empty_features().keys())
    
    def normalize_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize features using stored statistics"""
        normalized = features.copy()
        
        # Normalize packet length features
        if self.feature_stats['packet_length_std'] > 0:
            normalized['avg_packet_length'] = (
                (normalized['avg_packet_length'] - self.feature_stats['packet_length_mean']) /
                self.feature_stats['packet_length_std']
            )
        
        # Normalize payload size features
        if self.feature_stats['payload_size_std'] > 0:
            normalized['avg_payload_size'] = (
                (normalized['avg_payload_size'] - self.feature_stats['payload_size_mean']) /
                self.feature_stats['payload_size_std']
            )
        
        # Normalize port features
        if self.feature_stats['port_std'] > 0:
            normalized['avg_dst_port'] = (
                (normalized['avg_dst_port'] - self.feature_stats['port_mean']) /
                self.feature_stats['port_std']
            )
        
        return normalized
    
    def update_normalization_stats(self, features_list: List[Dict[str, Any]]):
        """Update normalization statistics from training data"""
        if not features_list:
            return
        
        df = pd.DataFrame(features_list)
        
        self.feature_stats.update({
            'packet_length_mean': df['avg_packet_length'].mean(),
            'packet_length_std': df['avg_packet_length'].std(),
            'payload_size_mean': df['avg_payload_size'].mean(),
            'payload_size_std': df['avg_payload_size'].std(),
            'port_mean': df['avg_dst_port'].mean(),
            'port_std': df['avg_dst_port'].std()
        })
        
        logger.info("Updated feature normalization statistics")
    
    def clear_buffer(self):
        """Clear packet buffer and statistics"""
        self.packet_buffer.clear()
        self.connection_stats.clear()
        self.ip_stats.clear() 