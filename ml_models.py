import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple, Union
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import os
from datetime import datetime
from utils import logger, config

class AnomalyDetector:
    """Base class for anomaly detection models"""
    
    def __init__(self, model_type: str = 'isolation_forest'):
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = []
        self.is_trained = False
        self.training_stats = {}
        
        logger.info(f"Initialized {model_type} anomaly detector")
    
    def _create_model(self, n_samples: int = None) -> Any:
        """Create the ML model based on type, with dynamic n_neighbors for LOF if needed"""
        if self.model_type == 'isolation_forest':
            return IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
        elif self.model_type == 'one_class_svm':
            return OneClassSVM(
                kernel='rbf',
                nu=0.1,
                gamma='scale'
            )
        elif self.model_type == 'local_outlier_factor':
            # Dynamically set n_neighbors based on n_samples
            n_neighbors = 20
            if n_samples is not None and n_samples > 1:
                n_neighbors = min(20, n_samples - 1)
            elif n_samples is not None and n_samples <= 1:
                n_neighbors = 1
            return LocalOutlierFactor(
                n_neighbors=n_neighbors,
                contamination=0.1,
                n_jobs=-1
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    def train(self, features: List[Dict[str, Any]], labels: Optional[List[int]] = None) -> Dict[str, float]:
        """Train the anomaly detection model"""
        try:
            # Convert features to DataFrame
            df = pd.DataFrame(features)
            self.feature_names = list(df.columns)
            
            # Remove any non-numeric columns
            numeric_columns = df.select_dtypes(include=[np.number]).columns
            df_numeric = df[numeric_columns]
            
            # Handle missing values
            df_numeric = df_numeric.fillna(0)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(df_numeric)
            
            n_samples = len(df_numeric)
            
            # Create and train model
            self.model = self._create_model(n_samples=n_samples)
            
            if self.model_type == 'local_outlier_factor':
                if n_samples < 2:
                    logger.error("LOF requires at least 2 samples to train. Skipping training.")
                    raise ValueError("LOF requires at least 2 samples to train.")
                self.model.fit_predict(X_scaled)
            else:
                self.model.fit(X_scaled)
            
            self.is_trained = True
            
            # Calculate training statistics
            self.training_stats = {
                'n_samples': n_samples,
                'n_features': len(numeric_columns),
                'feature_names': list(numeric_columns),
                'training_date': datetime.now().isoformat()
            }
            
            logger.info(f"Model trained successfully with {n_samples} samples and {len(numeric_columns)} features")
            
            return self.training_stats
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            raise
    
    def predict(self, features: Dict[str, Any]) -> Tuple[bool, float]:
        """Predict if features represent an anomaly"""
        try:
            if not self.is_trained:
                raise ValueError("Model must be trained before prediction")
            
            # Convert features to array
            feature_array = np.array([features.get(feature, 0) for feature in self.feature_names])
            feature_array = feature_array.reshape(1, -1)
            
            # Handle missing features
            feature_array = np.nan_to_num(feature_array, nan=0.0)
            
            # Scale features
            feature_scaled = self.scaler.transform(feature_array)
            
            # Make prediction
            if self.model_type == 'isolation_forest':
                # Isolation Forest returns -1 for anomalies, 1 for normal
                prediction = self.model.predict(feature_scaled)[0]
                anomaly_score = self.model.decision_function(feature_scaled)[0]
                is_anomaly = prediction == -1
                
            elif self.model_type == 'one_class_svm':
                # One-Class SVM returns -1 for anomalies, 1 for normal
                prediction = self.model.predict(feature_scaled)[0]
                anomaly_score = self.model.decision_function(feature_scaled)[0]
                is_anomaly = prediction == -1
                
            elif self.model_type == 'local_outlier_factor':
                try:
                    n_neighbors = getattr(self.model, 'n_neighbors_', 20)
                    if feature_scaled.shape[0] < n_neighbors + 1:
                        logger.warning(f"LOF prediction skipped: not enough samples (need at least n_neighbors+1={n_neighbors+1})")
                        return False, 0.0
                    prediction = self.model.fit_predict(feature_scaled)[0]
                    anomaly_score = -1.0 if prediction == -1 else 1.0
                    is_anomaly = prediction == -1
                except Exception as e:
                    logger.warning(f"LOF single prediction failed, using fallback: {e}")
                    is_anomaly = False
                    anomaly_score = 0.0
            
            return is_anomaly, anomaly_score
            
        except Exception as e:
            logger.error(f"Error making prediction: {e}")
            return False, 0.0
    
    def predict_batch(self, features_list: List[Dict[str, Any]]) -> List[Tuple[bool, float]]:
        """Predict anomalies for a batch of features"""
        try:
            if not self.is_trained:
                raise ValueError("Model must be trained before prediction")
            
            # Convert to DataFrame
            df = pd.DataFrame(features_list)
            
            # Select only trained features
            df_features = df[self.feature_names].fillna(0)
            
            # Scale features
            X_scaled = self.scaler.transform(df_features)
            
            # Make predictions
            if self.model_type == 'isolation_forest':
                predictions = self.model.predict(X_scaled)
                scores = self.model.decision_function(X_scaled)
                results = [(pred == -1, score) for pred, score in zip(predictions, scores)]
                
            elif self.model_type == 'one_class_svm':
                predictions = self.model.predict(X_scaled)
                scores = self.model.decision_function(X_scaled)
                results = [(pred == -1, score) for pred, score in zip(predictions, scores)]
                
            elif self.model_type == 'local_outlier_factor':
                try:
                    n_neighbors = getattr(self.model, 'n_neighbors_', 20)
                    if X_scaled.shape[0] < n_neighbors + 1:
                        logger.warning(f"LOF batch prediction skipped: not enough samples (need at least n_neighbors+1={n_neighbors+1})")
                        return [(False, 0.0)] * len(features_list)
                    predictions = self.model.fit_predict(X_scaled)
                    scores = [-1.0 if pred == -1 else 1.0 for pred in predictions]
                    results = [(pred == -1, score) for pred, score in zip(predictions, scores)]
                except Exception as e:
                    logger.warning(f"LOF batch prediction failed, using fallback: {e}")
                    results = [(False, 0.0)] * len(features_list)
            
            return results
            
        except Exception as e:
            logger.error(f"Error making batch predictions: {e}")
            return [(False, 0.0)] * len(features_list)
    
    def evaluate(self, features: List[Dict[str, Any]], labels: List[int]) -> Dict[str, float]:
        """Evaluate model performance"""
        try:
            if not self.is_trained:
                raise ValueError("Model must be trained before evaluation")
            
            # Make predictions
            predictions = self.predict_batch(features)
            pred_labels = [1 if is_anomaly else 0 for is_anomaly, _ in predictions]
            
            # Calculate metrics
            accuracy = accuracy_score(labels, pred_labels)
            precision = precision_score(labels, pred_labels, zero_division=0)
            recall = recall_score(labels, pred_labels, zero_division=0)
            f1 = f1_score(labels, pred_labels, zero_division=0)
            
            # Confusion matrix
            cm = confusion_matrix(labels, pred_labels)
            
            metrics = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'confusion_matrix': cm.tolist()
            }
            
            logger.info(f"Model evaluation - Accuracy: {accuracy:.3f}, F1: {f1:.3f}")
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error evaluating model: {e}")
            return {}
    
    def save_model(self, filepath: str):
        """Save the trained model"""
        try:
            if not self.is_trained:
                raise ValueError("Model must be trained before saving")
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Save model and metadata
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'model_type': self.model_type,
                'training_stats': self.training_stats,
                'is_trained': self.is_trained
            }
            
            joblib.dump(model_data, filepath)
            logger.info(f"Model saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            raise
    
    def load_model(self, filepath: str):
        """Load a trained model"""
        try:
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"Model file not found: {filepath}")
            
            # Load model data
            model_data = joblib.load(filepath)
            
            # Restore model state
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.model_type = model_data['model_type']
            self.training_stats = model_data.get('training_stats', {})
            self.is_trained = model_data['is_trained']
            
            logger.info(f"Model loaded from {filepath}")
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise

class EnsembleAnomalyDetector:
    """Ensemble of multiple anomaly detection models"""
    
    def __init__(self, models: List[str] = None):
        self.models = models or ['isolation_forest', 'one_class_svm', 'local_outlier_factor']
        self.detectors = {}
        self.weights = {}
        self.is_trained = False
        
        # Initialize detectors
        for model_type in self.models:
            self.detectors[model_type] = AnomalyDetector(model_type)
            self.weights[model_type] = 1.0 / len(self.models)  # Equal weights initially
        
        logger.info(f"Initialized ensemble with {len(self.models)} models")
    
    def train(self, features: List[Dict[str, Any]], labels: Optional[List[int]] = None) -> Dict[str, Any]:
        """Train all models in the ensemble"""
        try:
            training_results = {}
            
            for model_type, detector in self.detectors.items():
                logger.info(f"Training {model_type}...")
                result = detector.train(features, labels)
                training_results[model_type] = result
            
            self.is_trained = True
            
            # Optimize weights if labels are provided
            if labels:
                self._optimize_weights(features, labels)
            
            logger.info("Ensemble training completed")
            return training_results
            
        except Exception as e:
            logger.error(f"Error training ensemble: {e}")
            raise
    
    def _optimize_weights(self, features: List[Dict[str, Any]], labels: List[int]):
        """Optimize model weights based on performance"""
        try:
            performances = {}
            
            for model_type, detector in self.detectors.items():
                metrics = detector.evaluate(features, labels)
                performances[model_type] = metrics.get('f1_score', 0.0)
            
            # Normalize weights based on performance
            total_performance = sum(performances.values())
            if total_performance > 0:
                for model_type in self.models:
                    self.weights[model_type] = performances[model_type] / total_performance
            
            logger.info(f"Optimized weights: {self.weights}")
            
        except Exception as e:
            logger.error(f"Error optimizing weights: {e}")
    
    def predict(self, features: Dict[str, Any]) -> Tuple[bool, float]:
        """Make ensemble prediction"""
        try:
            if not self.is_trained:
                raise ValueError("Ensemble must be trained before prediction")
            
            predictions = []
            scores = []
            
            for model_type, detector in self.detectors.items():
                is_anomaly, score = detector.predict(features)
                predictions.append(is_anomaly)
                scores.append(score)
            
            # Weighted voting
            weighted_anomaly_score = sum(
                self.weights[model_type] * (1 if pred else 0)
                for model_type, pred in zip(self.models, predictions)
            )
            
            # Weighted average of scores
            weighted_score = sum(
                self.weights[model_type] * score
                for model_type, score in zip(self.models, scores)
            )
            
            # Final decision
            is_anomaly = weighted_anomaly_score > 0.5
            
            return is_anomaly, weighted_score
            
        except Exception as e:
            logger.error(f"Error making ensemble prediction: {e}")
            return False, 0.0
    
    def predict_batch(self, features_list: List[Dict[str, Any]]) -> List[Tuple[bool, float]]:
        """Make ensemble predictions for a batch"""
        try:
            if not self.is_trained:
                raise ValueError("Ensemble must be trained before prediction")
            
            results = []
            
            for features in features_list:
                is_anomaly, score = self.predict(features)
                results.append((is_anomaly, score))
            
            return results
            
        except Exception as e:
            logger.error(f"Error making ensemble batch predictions: {e}")
            return [(False, 0.0)] * len(features_list)
    
    def evaluate(self, features: List[Dict[str, Any]], labels: List[int]) -> Dict[str, float]:
        """Evaluate ensemble performance"""
        try:
            if not self.is_trained:
                raise ValueError("Ensemble must be trained before evaluation")
            
            # Make predictions
            predictions = self.predict_batch(features)
            pred_labels = [1 if is_anomaly else 0 for is_anomaly, _ in predictions]
            
            # Calculate metrics
            accuracy = accuracy_score(labels, pred_labels)
            precision = precision_score(labels, pred_labels, zero_division=0)
            recall = recall_score(labels, pred_labels, zero_division=0)
            f1 = f1_score(labels, pred_labels, zero_division=0)
            
            # Confusion matrix
            cm = confusion_matrix(labels, pred_labels)
            
            metrics = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'confusion_matrix': cm.tolist(),
                'weights': self.weights
            }
            
            logger.info(f"Ensemble evaluation - Accuracy: {accuracy:.3f}, F1: {f1:.3f}")
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error evaluating ensemble: {e}")
            return {}
    
    def save_ensemble(self, filepath: str):
        """Save the ensemble model"""
        try:
            if not self.is_trained:
                raise ValueError("Ensemble must be trained before saving")
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Save each model
            ensemble_data = {
                'models': self.models,
                'weights': self.weights,
                'is_trained': self.is_trained
            }
            
            # Save individual models
            for model_type in self.models:
                model_filepath = filepath.replace('.pkl', f'_{model_type}.pkl')
                self.detectors[model_type].save_model(model_filepath)
            
            # Save ensemble metadata
            joblib.dump(ensemble_data, filepath)
            logger.info(f"Ensemble saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving ensemble: {e}")
            raise
    
    def load_ensemble(self, filepath: str):
        """Load the ensemble model"""
        try:
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"Ensemble file not found: {filepath}")
            
            # Load ensemble metadata
            ensemble_data = joblib.load(filepath)
            
            # Load individual models
            for model_type in self.models:
                model_filepath = filepath.replace('.pkl', f'_{model_type}.pkl')
                self.detectors[model_type].load_model(model_filepath)
            
            # Restore ensemble state
            self.weights = ensemble_data['weights']
            self.is_trained = ensemble_data['is_trained']
            
            logger.info(f"Ensemble loaded from {filepath}")
            
        except Exception as e:
            logger.error(f"Error loading ensemble: {e}")
            raise

class AutoencoderAnomalyDetector:
    """Autoencoder-based anomaly detector using TensorFlow"""
    
    def __init__(self, input_dim: int = None, encoding_dim: int = None):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim or (input_dim // 4 if input_dim else 32)
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.threshold = 0.1
        
        logger.info(f"Initialized autoencoder with input_dim={input_dim}, encoding_dim={self.encoding_dim}")
    
    def _build_model(self):
        """Build the autoencoder model"""
        try:
            import tensorflow as tf
            from tensorflow.keras import layers, Model
            
            # Input layer
            input_layer = layers.Input(shape=(self.input_dim,))
            
            # Encoder
            encoded = layers.Dense(self.encoding_dim * 2, activation='relu')(input_layer)
            encoded = layers.Dropout(0.2)(encoded)
            encoded = layers.Dense(self.encoding_dim, activation='relu')(encoded)
            
            # Decoder
            decoded = layers.Dense(self.encoding_dim * 2, activation='relu')(encoded)
            decoded = layers.Dropout(0.2)(decoded)
            decoded = layers.Dense(self.input_dim, activation='sigmoid')(decoded)
            
            # Create model
            self.model = Model(input_layer, decoded)
            
            # Compile model
            self.model.compile(
                optimizer='adam',
                loss='mse',
                metrics=['mae']
            )
            
            logger.info("Autoencoder model built successfully")
            
        except ImportError:
            logger.error("TensorFlow not available. Please install tensorflow to use AutoencoderAnomalyDetector")
            raise
    
    def train(self, features: List[Dict[str, Any]], epochs: int = 50, batch_size: int = 32) -> Dict[str, Any]:
        """Train the autoencoder"""
        try:
            # Convert features to DataFrame
            df = pd.DataFrame(features)
            
            # Select numeric columns
            numeric_columns = df.select_dtypes(include=[np.number]).columns
            df_numeric = df[numeric_columns]
            
            # Handle missing values
            df_numeric = df_numeric.fillna(0)
            
            # Update input dimension if not set
            if self.input_dim is None:
                self.input_dim = len(numeric_columns)
                self.encoding_dim = self.input_dim // 4
            
            # Scale features
            X_scaled = self.scaler.fit_transform(df_numeric)
            
            # Build model
            self._build_model()
            
            # Train model
            history = self.model.fit(
                X_scaled, X_scaled,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=0.2,
                verbose=1
            )
            
            # Calculate reconstruction error threshold
            reconstructed = self.model.predict(X_scaled)
            mse = np.mean(np.square(X_scaled - reconstructed), axis=1)
            self.threshold = np.percentile(mse, 95)  # 95th percentile as threshold
            
            self.is_trained = True
            
            training_stats = {
                'n_samples': len(df_numeric),
                'n_features': len(numeric_columns),
                'input_dim': self.input_dim,
                'encoding_dim': self.encoding_dim,
                'threshold': self.threshold,
                'training_date': datetime.now().isoformat()
            }
            
            logger.info(f"Autoencoder trained successfully. Threshold: {self.threshold:.4f}")
            
            return training_stats
            
        except Exception as e:
            logger.error(f"Error training autoencoder: {e}")
            raise
    
    def predict(self, features: Dict[str, Any]) -> Tuple[bool, float]:
        """Predict if features represent an anomaly"""
        try:
            if not self.is_trained:
                raise ValueError("Autoencoder must be trained before prediction")
            
            # Convert features to array
            feature_array = np.array([features.get(feature, 0) for feature in self.feature_names])
            feature_array = feature_array.reshape(1, -1)
            
            # Handle missing features
            feature_array = np.nan_to_num(feature_array, nan=0.0)
            
            # Scale features
            feature_scaled = self.scaler.transform(feature_array)
            
            # Reconstruct
            reconstructed = self.model.predict(feature_scaled)
            
            # Calculate reconstruction error
            mse = np.mean(np.square(feature_scaled - reconstructed))
            
            # Determine if anomaly
            is_anomaly = mse > self.threshold
            
            return is_anomaly, mse
            
        except Exception as e:
            logger.error(f"Error making autoencoder prediction: {e}")
            return False, 0.0 