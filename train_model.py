#!/usr/bin/env python3
"""
NIDS Model Training Script
Trains ML models for network intrusion detection
"""

import argparse
import sys
import os
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from anomaly_detector import NIDSAnomalyDetector, NIDSTrainer
from ml_models import EnsembleAnomalyDetector
from utils import logger, config

def main():
    """Main training function"""
    parser = argparse.ArgumentParser(description='Train NIDS ML Models')
    parser.add_argument('--model-type', type=str, default='ensemble',
                       choices=['ensemble', 'isolation_forest', 'one_class_svm', 'local_outlier_factor'],
                       help='ML model type to train')
    parser.add_argument('--synthetic', action='store_true',
                       help='Train with synthetic data')
    parser.add_argument('--pcap', type=str,
                       help='Train with PCAP file')
    parser.add_argument('--n-samples', type=int, default=1000,
                       help='Number of synthetic samples')
    parser.add_argument('--anomaly-ratio', type=float, default=0.1,
                       help='Ratio of anomalies in synthetic data')
    parser.add_argument('--max-packets', type=int, default=10000,
                       help='Maximum packets to process from PCAP')
    parser.add_argument('--output', type=str, default=None,
                       help='Output model file path')
    parser.add_argument('--evaluate', action='store_true',
                       help='Evaluate model after training')
    parser.add_argument('--test-split', type=float, default=0.2,
                       help='Test split ratio for evaluation')
    
    args = parser.parse_args()
    
    # Load configuration
    config.load_from_env()
    
    logger.info("NIDS Model Training Starting...")
    logger.info(f"Model Type: {args.model_type}")
    
    try:
        # Initialize trainer and NIDS
        trainer = NIDSTrainer()
        nids = NIDSAnomalyDetector(model_type=args.model_type)
        
        training_data = None
        labels = None
        
        if args.synthetic:
            training_data, labels = train_with_synthetic_data(trainer, args)
        elif args.pcap:
            training_data, labels = train_with_pcap_data(trainer, args)
        else:
            logger.error("No training method specified. Use --synthetic or --pcap")
            return
        
        if not training_data:
            logger.error("No training data generated")
            return
        
        # Train the model
        logger.info("Training model...")
        training_stats = nids.train_model(training_data, labels)
        
        # Save model
        model_path = args.output or config.get('model_path', 'models/nids_model.pkl')
        if isinstance(nids.ml_model, EnsembleAnomalyDetector):
            nids.ml_model.save_ensemble(model_path)
        else:
            nids.ml_model.save_model(model_path)
        
        logger.info(f"Model saved to: {model_path}")
        logger.info(f"Training stats: {training_stats}")
        
        # Evaluate if requested
        if args.evaluate:
            evaluate_model(nids, training_data, labels, args.test_split)
        
        logger.info("Training completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during training: {e}")
        raise

def train_with_synthetic_data(trainer, args):
    """Train with synthetic data"""
    logger.info("Generating synthetic training data...")
    logger.info(f"Samples: {args.n_samples}, Anomaly ratio: {args.anomaly_ratio}")
    
    # Generate synthetic data
    features_list = trainer.generate_synthetic_data(args.n_samples)
    labels = trainer.create_labels_for_synthetic_data(features_list, args.anomaly_ratio)
    
    logger.info(f"Generated {len(features_list)} feature samples")
    logger.info(f"Labels: {sum(labels)} anomalies, {len(labels) - sum(labels)} normal")
    
    return features_list, labels

def train_with_pcap_data(trainer, args):
    """Train with PCAP data"""
    logger.info(f"Processing PCAP file: {args.pcap}")
    logger.info(f"Max packets: {args.max_packets}")
    
    # Generate training data from PCAP
    features_list = trainer.generate_training_data(args.pcap, args.max_packets)
    
    if not features_list:
        logger.error("No features extracted from PCAP file")
        return None, None
    
    # For PCAP data, assume it's mostly normal traffic
    # You might want to manually label some samples as anomalies
    labels = [0] * len(features_list)
    
    logger.info(f"Extracted {len(features_list)} feature samples from PCAP")
    logger.info(f"Labels: {sum(labels)} anomalies, {len(labels) - sum(labels)} normal")
    
    return features_list, labels

def evaluate_model(nids, features_list, labels, test_split):
    """Evaluate the trained model"""
    try:
        from sklearn.model_selection import train_test_split
        import numpy as np
        
        logger.info("Evaluating model...")
        
        # Split data for evaluation
        X_train, X_test, y_train, y_test = train_test_split(
            features_list, labels, test_size=test_split, random_state=42, stratify=labels
        )
        
        logger.info(f"Test set size: {len(X_test)} samples")
        logger.info(f"Test anomalies: {sum(y_test)}")
        
        # Evaluate on test set
        metrics = nids.evaluate_model(X_test, y_test)
        
        logger.info("Model Evaluation Results:")
        logger.info(f"Accuracy: {metrics.get('accuracy', 0):.3f}")
        logger.info(f"Precision: {metrics.get('precision', 0):.3f}")
        logger.info(f"Recall: {metrics.get('recall', 0):.3f}")
        logger.info(f"F1-Score: {metrics.get('f1_score', 0):.3f}")
        
        # Print confusion matrix
        cm = metrics.get('confusion_matrix', [])
        if cm:
            logger.info("Confusion Matrix:")
            logger.info(f"  TN: {cm[0][0]}, FP: {cm[0][1]}")
            logger.info(f"  FN: {cm[1][0]}, TP: {cm[1][1]}")
        
        # Check if accuracy meets requirements
        accuracy = metrics.get('accuracy', 0)
        if accuracy >= 0.8:
            logger.info("✅ Model meets accuracy requirement (>80%)")
        else:
            logger.warning(f"⚠️ Model accuracy ({accuracy:.1%}) is below 80% requirement")
        
        return metrics
        
    except Exception as e:
        logger.error(f"Error during evaluation: {e}")
        return {}

def create_training_report(model_type, training_stats, evaluation_metrics=None):
    """Create a training report"""
    report = f"""
NIDS Model Training Report
==========================
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Model Type: {model_type}

Training Statistics:
-------------------
"""
    
    for key, value in training_stats.items():
        report += f"{key}: {value}\n"
    
    if evaluation_metrics:
        report += f"""
Evaluation Results:
------------------
Accuracy: {evaluation_metrics.get('accuracy', 0):.3f}
Precision: {evaluation_metrics.get('precision', 0):.3f}
Recall: {evaluation_metrics.get('recall', 0):.3f}
F1-Score: {evaluation_metrics.get('f1_score', 0):.3f}
"""
    
    # Save report
    report_file = f"training_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    
    logger.info(f"Training report saved to: {report_file}")
    return report

if __name__ == "__main__":
    # Check if no arguments provided
    if len(sys.argv) == 1:
        print("NIDS Model Training")
        print("\nUsage examples:")
        print("  python train_model.py --synthetic --n-samples 2000")
        print("  python train_model.py --pcap sample.pcap --evaluate")
        print("  python train_model.py --model-type isolation_forest --synthetic")
        print("\nFor more options, run: python train_model.py --help")
        
        # Interactive mode
        print("\nInteractive Training Mode:")
        print("1. Train with synthetic data")
        print("2. Train with PCAP file")
        print("3. Train and evaluate")
        
        try:
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice == "1":
                n_samples = input("Number of samples (default 1000): ").strip() or "1000"
                sys.argv = ["train_model.py", "--synthetic", "--n-samples", n_samples]
            elif choice == "2":
                pcap_file = input("PCAP file path: ").strip()
                if pcap_file:
                    sys.argv = ["train_model.py", "--pcap", pcap_file]
                else:
                    print("No file specified. Exiting.")
                    sys.exit(1)
            elif choice == "3":
                n_samples = input("Number of samples (default 1000): ").strip() or "1000"
                sys.argv = ["train_model.py", "--synthetic", "--n-samples", n_samples, "--evaluate"]
            else:
                print("Invalid choice. Exiting.")
                sys.exit(1)
                
        except KeyboardInterrupt:
            print("\nExiting.")
            sys.exit(0)
    
    main() 