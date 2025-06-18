#!/usr/bin/env python3
"""
NIDS - Network Intrusion Detection System
Main entry point for the application
"""

import argparse
import sys
import os
import time
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from anomaly_detector import NIDSAnomalyDetector, NIDSTrainer
from web_dashboard import create_app
from utils import logger, config

# Import scapy at module level
try:
    from scapy.all import IP, TCP, UDP, Raw, wrpcap
except ImportError:
    logger.warning("Scapy not available - PCAP creation will not work")

def main():
    """Main entry point for NIDS"""
    parser = argparse.ArgumentParser(description='NIDS - Network Intrusion Detection System')
    parser.add_argument('--mode', choices=['web', 'cli', 'train'], default='web',
                       help='Operation mode: web (dashboard), cli (command line), train (training only)')
    parser.add_argument('--interface', type=str, default=None,
                       help='Network interface to monitor')
    parser.add_argument('--model-type', type=str, default='ensemble',
                       choices=['ensemble', 'isolation_forest', 'one_class_svm', 'local_outlier_factor'],
                       help='ML model type to use')
    parser.add_argument('--train-synthetic', action='store_true',
                       help='Train model with synthetic data')
    parser.add_argument('--train-pcap', type=str,
                       help='Train model with PCAP file')
    parser.add_argument('--n-samples', type=int, default=1000,
                       help='Number of synthetic samples for training')
    parser.add_argument('--anomaly-ratio', type=float, default=0.1,
                       help='Ratio of anomalies in synthetic data')
    parser.add_argument('--max-packets', type=int, default=10000,
                       help='Maximum packets to process from PCAP')
    parser.add_argument('--port', type=int, default=5000,
                       help='Web server port')
    
    args = parser.parse_args()
    
    # Load configuration
    config.load_from_env()
    
    # Override config with command line arguments
    if args.interface:
        config.set('network_interface', args.interface)
    if args.port:
        config.set('web_port', args.port)
    
    logger.info("NIDS System Starting...")
    logger.info(f"Mode: {args.mode}")
    logger.info(f"Interface: {config.get('network_interface')}")
    logger.info(f"Model Type: {args.model_type}")
    
    try:
        if args.mode == 'web':
            run_web_dashboard()
        elif args.mode == 'cli':
            run_cli_mode(args)
        elif args.mode == 'train':
            run_training_mode(args)
        else:
            logger.error(f"Unknown mode: {args.mode}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("NIDS System stopped by user")
    except Exception as e:
        logger.error(f"Error running NIDS: {e}")
        sys.exit(1)

def run_web_dashboard():
    """Run the web dashboard"""
    try:
        from web_dashboard import app
        port = config.get('web_port', 5000)
        
        logger.info(f"Starting web dashboard on port {port}")
        logger.info(f"Access the dashboard at: http://localhost:{port}")
        
        app.run(host='0.0.0.0', port=port, debug=False)
        
    except Exception as e:
        logger.error(f"Error starting web dashboard: {e}")
        raise

def run_cli_mode(args):
    """Run in command-line mode"""
    try:
        # Initialize NIDS
        nids = NIDSAnomalyDetector(
            model_type=args.model_type,
            interface=args.interface or config.get('network_interface')
        )
        
        # Try to load existing model
        try:
            nids.load_model()
            logger.info("Loaded existing trained model")
        except:
            logger.warning("No trained model found. Please train a model first.")
            logger.info("You can train a model using: python main.py --mode train --train-synthetic")
            return
        
        # Start NIDS
        logger.info("Starting NIDS in CLI mode...")
        logger.info("Press Ctrl+C to stop")
        
        nids.start()
        
        # Keep running until interrupted
        try:
            while True:
                time.sleep(1)
                
                # Print stats every 10 seconds
                if int(time.time()) % 10 == 0:
                    stats = nids.get_stats()
                    print(f"\rPackets: {stats.get('total_packets_processed', 0)}, "
                          f"Anomalies: {stats.get('anomalies_detected', 0)}, "
                          f"Rate: {stats.get('capture_stats', {}).get('packets_per_second', 0):.1f} pkt/s", end='')
                    
        except KeyboardInterrupt:
            pass
        finally:
            nids.stop()
            logger.info("NIDS stopped")
            
    except Exception as e:
        logger.error(f"Error in CLI mode: {e}")
        raise

def run_training_mode(args):
    """Run training mode"""
    try:
        # Initialize trainer
        trainer = NIDSTrainer()
        nids = NIDSAnomalyDetector(model_type=args.model_type)
        
        if args.train_synthetic:
            logger.info("Training with synthetic data...")
            logger.info(f"Samples: {args.n_samples}, Anomaly ratio: {args.anomaly_ratio}")
            
            # Generate synthetic data
            features_list = trainer.generate_synthetic_data(args.n_samples)
            labels = trainer.create_labels_for_synthetic_data(features_list, args.anomaly_ratio)
            
            # Train model
            training_stats = nids.train_model(features_list, labels)
            
            logger.info("Training completed successfully!")
            logger.info(f"Training stats: {training_stats}")
            
        elif args.train_pcap:
            logger.info(f"Training with PCAP file: {args.train_pcap}")
            logger.info(f"Max packets: {args.max_packets}")
            
            # Generate training data from PCAP
            features_list = trainer.generate_training_data(args.train_pcap, args.max_packets)
            
            if not features_list:
                logger.error("No features extracted from PCAP file")
                return
            
            # For PCAP data, assume it's mostly normal traffic
            labels = [0] * len(features_list)
            
            # Train model
            training_stats = nids.train_model(features_list, labels)
            
            logger.info("Training completed successfully!")
            logger.info(f"Training stats: {training_stats}")
            
        else:
            logger.error("No training method specified. Use --train-synthetic or --train-pcap")
            return
        
        logger.info("Model saved successfully!")
        logger.info("You can now run NIDS using: python main.py --mode cli")
        
    except Exception as e:
        logger.error(f"Error in training mode: {e}")
        raise

def create_sample_pcap():
    """Create a sample PCAP file for testing"""
    try:
        import random
        
        logger.info("Creating sample PCAP file...")
        
        # Create some sample packets
        packets = []
        
        # Normal traffic
        for i in range(100):
            # TCP packet
            pkt = IP(src=f"192.168.1.{random.randint(1, 254)}", 
                    dst=f"10.0.0.{random.randint(1, 254)}") / \
                 TCP(sport=random.randint(1024, 65535), 
                    dport=random.choice([80, 443, 22, 53])) / \
                 Raw(load="A" * random.randint(0, 100))
            packets.append(pkt)
            
            # UDP packet
            pkt = IP(src=f"192.168.1.{random.randint(1, 254)}", 
                    dst=f"10.0.0.{random.randint(1, 254)}") / \
                 UDP(sport=random.randint(1024, 65535), 
                    dport=random.choice([53, 67, 123])) / \
                 Raw(load="B" * random.randint(0, 50))
            packets.append(pkt)
        
        # Some anomalous traffic
        for i in range(10):
            # Port scan
            pkt = IP(src="192.168.1.100", dst="10.0.0.1") / \
                 TCP(sport=random.randint(1024, 65535), 
                    dport=random.randint(1, 1024))
            packets.append(pkt)
            
            # Large payload
            pkt = IP(src="192.168.1.101", dst="10.0.0.2") / \
                 TCP(sport=random.randint(1024, 65535), dport=80) / \
                 Raw(load="X" * 1500)
            packets.append(pkt)
        
        # Save to file
        wrpcap("sample_traffic.pcap", packets)
        logger.info("Sample PCAP file created: sample_traffic.pcap")
        
    except Exception as e:
        logger.error(f"Error creating sample PCAP: {e}")

if __name__ == "__main__":
    # Check if we need to create sample data
    if len(sys.argv) == 1:
        # No arguments, show help
        print("NIDS - Network Intrusion Detection System")
        print("\nUsage examples:")
        print("  python main.py --mode web                    # Start web dashboard")
        print("  python main.py --mode cli                    # Start CLI mode")
        print("  python main.py --mode train --train-synthetic # Train with synthetic data")
        print("  python main.py --mode train --train-pcap sample.pcap # Train with PCAP file")
        print("\nFor more options, run: python main.py --help")
        
        # Ask user what they want to do
        print("\nWhat would you like to do?")
        print("1. Start web dashboard")
        print("2. Start CLI mode")
        print("3. Train model with synthetic data")
        print("4. Create sample PCAP file")
        
        try:
            choice = input("\nEnter your choice (1-4): ").strip()
            
            if choice == "1":
                sys.argv = ["main.py", "--mode", "web"]
            elif choice == "2":
                sys.argv = ["main.py", "--mode", "cli"]
            elif choice == "3":
                sys.argv = ["main.py", "--mode", "train", "--train-synthetic"]
            elif choice == "4":
                create_sample_pcap()
                sys.exit(0)
            else:
                print("Invalid choice. Exiting.")
                sys.exit(1)
                
        except KeyboardInterrupt:
            print("\nExiting.")
            sys.exit(0)
    
    main() 