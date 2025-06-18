import threading
import time
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
import json

from packet_capture import PacketCapture
from feature_extraction import FeatureExtractor
from ml_models import AnomalyDetector, EnsembleAnomalyDetector
from utils import logger, config, alert_manager

class NIDSAnomalyDetector:
    """Main NIDS anomaly detection system"""
    
    def __init__(self, model_type: str = 'ensemble', interface: str = None):
        self.model_type = model_type
        self.interface = interface or config.get('network_interface', 'Ethernet')
        self.is_running = False
        
        # Initialize components
        self.packet_capture = PacketCapture(interface=self.interface, callback=self._packet_callback)
        self.feature_extractor = FeatureExtractor()
        
        # Initialize ML model
        if model_type == 'ensemble':
            self.ml_model = EnsembleAnomalyDetector()
        else:
            self.ml_model = AnomalyDetector(model_type)
        
        # Statistics and monitoring
        self.stats = {
            'total_packets_processed': 0,
            'anomalies_detected': 0,
            'false_positives': 0,
            'true_positives': 0,
            'start_time': time.time(),
            'last_anomaly_time': None,
            'model_accuracy': 0.0
        }
        
        # Configuration
        self.anomaly_threshold = config.get('anomaly_threshold', 0.7)
        self.feature_extraction_interval = 5  # seconds
        self.last_feature_extraction = time.time()
        
        # Threading
        self.processing_thread = None
        self.lock = threading.Lock()
        self.traffic_history = []  # Store (timestamp, packets_per_second)
        
        logger.info(f"NIDS Anomaly Detector initialized with {model_type} model")
    
    def start(self):
        """Start the NIDS system"""
        if self.is_running:
            logger.warning("NIDS is already running")
            return
        
        try:
            # Check if model is trained
            if not self.ml_model.is_trained:
                logger.warning("ML model is not trained. Please train the model first.")
                return
            
            self.is_running = True
            
            # Start packet capture
            self.packet_capture.start_capture()
            
            # Start processing thread
            self.processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
            self.processing_thread.start()
            
            logger.info("NIDS Anomaly Detection System started successfully")
            
        except Exception as e:
            logger.error(f"Error starting NIDS: {e}")
            self.is_running = False
            raise
    
    def stop(self):
        """Stop the NIDS system"""
        if not self.is_running:
            return
        
        self.is_running = False
        
        # Stop packet capture
        self.packet_capture.stop_capture()
        
        # Wait for processing thread to finish
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=5)
        
        logger.info("NIDS Anomaly Detection System stopped")
    
    def _packet_callback(self, packet_info: Dict[str, Any]):
        """Callback for packet capture"""
        try:
            # Add packet to feature extractor
            self.feature_extractor.add_packet(packet_info)
            
            # Update statistics
            with self.lock:
                self.stats['total_packets_processed'] += 1
            
        except Exception as e:
            logger.error(f"Error in packet callback: {e}")
    
    def _processing_loop(self):
        """Main processing loop"""
        while self.is_running:
            try:
                current_time = time.time()
                
                # Extract features periodically
                if current_time - self.last_feature_extraction >= self.feature_extraction_interval:
                    self._extract_and_analyze_features()
                    self.last_feature_extraction = current_time
                
                # Sleep to prevent high CPU usage
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                time.sleep(5)  # Wait before retrying
    
    def _extract_and_analyze_features(self):
        """Extract features and analyze for anomalies"""
        try:
            # Extract features from current packet window
            features = self.feature_extractor.extract_features()
            
            if not features or features.get('packet_count', 0) == 0:
                return
            
            # Make prediction
            is_anomaly, anomaly_score = self.ml_model.predict(features)
            
            # Update statistics
            with self.lock:
                if is_anomaly:
                    self.stats['anomalies_detected'] += 1
                    self.stats['last_anomaly_time'] = time.time()
                    
                    # Create detailed alert
                    alert_details = {
                        'anomaly_score': float(anomaly_score),
                        'features': features,
                        'timestamp': datetime.now().isoformat(),
                        'packet_count': features.get('packet_count', 0),
                        'protocol_distribution': {
                            'tcp': features.get('tcp_count', 0),
                            'udp': features.get('udp_count', 0),
                            'icmp': features.get('icmp_count', 0)
                        },
                        'connection_info': {
                            'unique_connections': features.get('unique_connections', 0),
                            'unique_src_ips': features.get('unique_src_ips', 0),
                            'unique_dst_ips': features.get('unique_dst_ips', 0)
                        }
                    }
                    
                    # Add alert
                    if alert_manager.add_alert('ml_anomaly', alert_details):
                        logger.warning(f"ML ANOMALY DETECTED - Score: {anomaly_score:.3f}, "
                                     f"Packets: {features.get('packet_count', 0)}")
            
        except Exception as e:
            logger.error(f"Error in feature analysis: {e}")
    
    def train_model(self, training_data: List[Dict[str, Any]], labels: Optional[List[int]] = None):
        """Train the ML model"""
        try:
            logger.info("Starting model training...")
            
            # Update feature extractor normalization stats
            self.feature_extractor.update_normalization_stats(training_data)
            
            # Train the model
            training_stats = self.ml_model.train(training_data, labels)
            
            # Save the trained model
            model_path = config.get('model_path', 'models/nids_model.pkl')
            if isinstance(self.ml_model, EnsembleAnomalyDetector):
                self.ml_model.save_ensemble(model_path)
            else:
                self.ml_model.save_model(model_path)
            
            logger.info("Model training completed successfully")
            return training_stats
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            raise
    
    def load_model(self, model_path: str = None):
        """Load a trained model"""
        try:
            model_path = model_path or config.get('model_path', 'models/nids_model.pkl')
            
            if isinstance(self.ml_model, EnsembleAnomalyDetector):
                self.ml_model.load_ensemble(model_path)
            else:
                self.ml_model.load_model(model_path)
            
            logger.info(f"Model loaded successfully from {model_path}")
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise
    
    def evaluate_model(self, test_data: List[Dict[str, Any]], labels: List[int]) -> Dict[str, float]:
        """Evaluate model performance"""
        try:
            metrics = self.ml_model.evaluate(test_data, labels)
            
            # Update statistics
            with self.lock:
                self.stats['model_accuracy'] = metrics.get('accuracy', 0.0)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error evaluating model: {e}")
            return {}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        with self.lock:
            stats = self.stats.copy()
            
            # Add packet capture stats
            capture_stats = self.packet_capture.get_stats()
            stats.update({
                'capture_stats': capture_stats,
                'uptime': time.time() - stats['start_time'],
                'anomaly_rate': stats['anomalies_detected'] / max(stats['total_packets_processed'], 1)
            })
            
            # Update traffic history
            now = time.strftime('%H:%M:%S')
            pps = capture_stats.get('packets_per_second', 0)
            self.traffic_history.append((now, pps))
            if len(self.traffic_history) > 30:
                self.traffic_history.pop(0)
            stats['traffic_history'] = self.traffic_history.copy()
            
            return stats
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return alert_manager.get_recent_alerts(limit)
    
    def get_alert_stats(self) -> Dict[str, int]:
        """Get alert statistics"""
        return alert_manager.get_alert_stats()
    
    def clear_alerts(self):
        """Clear all alerts"""
        # This would need to be implemented in AlertManager
        logger.info("Alert clearing requested")

class NIDSTrainer:
    """Utility class for training NIDS models with sample data"""
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
    
    def generate_training_data(self, pcap_file: str, max_packets: int = 10000) -> List[Dict[str, Any]]:
        """Generate training data from PCAP file"""
        try:
            from packet_capture import PCAPReader
            
            # Read packets from PCAP
            pcap_reader = PCAPReader(pcap_file)
            packets = pcap_reader.read_packets(max_packets)
            
            if not packets:
                raise ValueError("No packets found in PCAP file")
            
            # Extract features in windows
            features_list = []
            window_size = config.get('feature_window_size', 100)
            
            for i in range(0, len(packets), window_size // 2):  # 50% overlap
                window_packets = packets[i:i + window_size]
                
                # Add packets to feature extractor
                for packet in window_packets:
                    self.feature_extractor.add_packet(packet)
                
                # Extract features
                features = self.feature_extractor.extract_features()
                if features and features.get('packet_count', 0) > 0:
                    features_list.append(features)
            
            logger.info(f"Generated {len(features_list)} feature samples from {len(packets)} packets")
            return features_list
            
        except Exception as e:
            logger.error(f"Error generating training data: {e}")
            raise
    
    def generate_synthetic_data(self, n_samples: int = 1000) -> List[Dict[str, Any]]:
        """Generate synthetic training data for testing"""
        try:
            import random
            
            features_list = []
            
            for _ in range(n_samples):
                # Generate synthetic features with more realistic distributions
                features = {
                    'packet_count': random.randint(50, 200),
                    'total_bytes': random.randint(5000, 50000),
                    'avg_packet_length': random.uniform(60, 1500),
                    'std_packet_length': random.uniform(10, 500),
                    'min_packet_length': random.randint(40, 100),
                    'max_packet_length': random.randint(100, 1500),
                    'avg_payload_size': random.uniform(0, 1400),
                    'std_payload_size': random.uniform(0, 400),
                    'total_payload_size': random.randint(0, 50000),
                    'tcp_count': random.randint(0, 100),
                    'udp_count': random.randint(0, 50),
                    'icmp_count': random.randint(0, 10),
                    'other_protocol_count': random.randint(0, 5),
                    'protocol_diversity': random.randint(1, 4),
                    'tcp_ratio': random.uniform(0.3, 0.9),  # More realistic TCP ratio
                    'udp_ratio': random.uniform(0.1, 0.6),  # More realistic UDP ratio
                    'icmp_ratio': random.uniform(0, 0.1),   # Lower ICMP ratio
                    'other_protocol_ratio': random.uniform(0, 0.05),  # Very low other protocols
                    'unique_src_ports': random.randint(1, 15),
                    'unique_dst_ports': random.randint(1, 20),
                    'total_ports_accessed': random.randint(1, 30),
                    'common_port_ratio': random.uniform(0.2, 0.8),  # More realistic port usage
                    'high_port_ratio': random.uniform(0.1, 0.5),
                    'avg_dst_port': random.uniform(1024, 65535),
                    'std_dst_port': random.uniform(0, 8000),
                    'min_dst_port': random.randint(1, 1024),
                    'max_dst_port': random.randint(1024, 65535),
                    'unique_connections': random.randint(1, 40),
                    'total_connection_attempts': random.randint(10, 150),
                    'avg_packets_per_connection': random.uniform(1, 8),
                    'connection_diversity': random.uniform(0.1, 0.8),
                    'max_packets_per_connection': random.randint(1, 30),
                    'unique_src_ips': random.randint(1, 15),
                    'unique_dst_ips': random.randint(1, 20),
                    'src_ip_diversity': random.uniform(0.1, 0.8),
                    'dst_ip_diversity': random.uniform(0.1, 0.8),
                    'private_src_ip_ratio': random.uniform(0.3, 0.9),  # Most traffic from private IPs
                    'private_dst_ip_ratio': random.uniform(0.2, 0.8),
                    'packet_rate': random.uniform(0, 50),  # Lower packet rates for normal traffic
                    'inter_arrival_time_mean': random.uniform(0.01, 0.5),
                    'inter_arrival_time_std': random.uniform(0, 0.3),
                    'burst_count': random.randint(0, 8),
                    'burst_ratio': random.uniform(0, 0.3),
                    'payload_size_mean': random.uniform(0, 800),
                    'payload_size_std': random.uniform(0, 250),
                    'zero_payload_ratio': random.uniform(0, 0.2),
                    'large_payload_ratio': random.uniform(0, 0.15),
                    'payload_size_entropy': random.uniform(0, 4),
                    'syn_count': random.randint(0, 15),
                    'fin_count': random.randint(0, 10),
                    'rst_count': random.randint(0, 3),
                    'psh_count': random.randint(0, 8),
                    'ack_count': random.randint(0, 40),
                    'urg_count': random.randint(0, 1),
                    'syn_ratio': random.uniform(0, 0.2),
                    'fin_ratio': random.uniform(0, 0.15),
                    'rst_ratio': random.uniform(0, 0.05),
                    'psh_ratio': random.uniform(0, 0.15),
                    'ack_ratio': random.uniform(0.3, 0.7),
                    'urg_ratio': random.uniform(0, 0.02)
                }
                
                features_list.append(features)
            
            logger.info(f"Generated {len(features_list)} synthetic feature samples")
            return features_list
            
        except Exception as e:
            logger.error(f"Error generating synthetic data: {e}")
            raise
    
    def create_labels_for_synthetic_data(self, features_list: List[Dict[str, Any]], 
                                       anomaly_ratio: float = 0.1) -> List[int]:
        """Create labels for synthetic data (0 = normal, 1 = anomaly)"""
        try:
            n_samples = len(features_list)
            n_anomalies = int(n_samples * anomaly_ratio)
            
            # Create labels (mostly normal with some anomalies)
            labels = [0] * n_samples
            
            # Mark some samples as anomalies based on unusual patterns
            for i, features in enumerate(features_list):
                # Enhanced rule-based anomaly detection for synthetic data
                anomaly_score = 0
                
                # High packet rate (DDoS-like behavior)
                if features.get('packet_rate', 0) > 60:
                    anomaly_score += 2
                
                # Unusual protocol distribution
                if features.get('other_protocol_ratio', 0) > 0.2:
                    anomaly_score += 2
                
                # High port diversity (potential scanning)
                if features.get('unique_dst_ports', 0) > 20:
                    anomaly_score += 2
                
                # Unusual payload patterns
                if features.get('large_payload_ratio', 0) > 0.3:
                    anomaly_score += 1
                
                # High burst ratio (bursty traffic)
                if features.get('burst_ratio', 0) > 0.25:
                    anomaly_score += 1
                
                # Unusual TCP flag patterns
                if features.get('syn_ratio', 0) > 0.25:
                    anomaly_score += 1
                
                if features.get('rst_ratio', 0) > 0.08:
                    anomaly_score += 1
                
                # High connection diversity (potential scanning)
                if features.get('unique_connections', 0) > 35:
                    anomaly_score += 1
                
                # Unusual IP diversity
                if features.get('src_ip_diversity', 0) > 0.9:
                    anomaly_score += 1
                
                # High payload entropy (encrypted or random data)
                if features.get('payload_size_entropy', 0) > 3.5:
                    anomaly_score += 1
                
                # Mark as anomaly if score is high enough
                if anomaly_score >= 2:
                    labels[i] = 1
            
            # Ensure we have the desired number of anomalies
            current_anomalies = sum(labels)
            if current_anomalies < n_anomalies:
                # Add more anomalies randomly from samples with high anomaly scores
                normal_indices = [i for i, label in enumerate(labels) if label == 0]
                additional_needed = n_anomalies - current_anomalies
                
                import random
                for i in random.sample(normal_indices, min(additional_needed, len(normal_indices))):
                    labels[i] = 1
            elif current_anomalies > n_anomalies * 1.5:
                # Too many anomalies, reduce by converting some back to normal
                anomaly_indices = [i for i, label in enumerate(labels) if label == 1]
                to_convert = current_anomalies - n_anomalies
                
                import random
                for i in random.sample(anomaly_indices, min(to_convert, len(anomaly_indices))):
                    labels[i] = 0
            
            logger.info(f"Created labels: {sum(labels)} anomalies out of {len(labels)} samples")
            return labels
            
        except Exception as e:
            logger.error(f"Error creating labels: {e}")
            raise 