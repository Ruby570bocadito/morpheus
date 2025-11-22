"""
ML Classifier - Malware detection using ensemble of ML models
"""

import numpy as np
import pickle
from pathlib import Path
from typing import Dict, Any, List, Tuple
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import sys
sys.path.append(str(Path(__file__).parent.parent))

from utils.pe_parser import PEParser


class MalwareClassifier:
    """Ensemble classifier for malware detection"""
    
    def __init__(self):
        """Initialize classifier"""
        self.scaler = StandardScaler()
        self.rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42
        )
        self.gb_classifier = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.nn_classifier = MLPClassifier(
            hidden_layer_sizes=(256, 128, 64),
            max_iter=500,
            random_state=42
        )
        
        self.is_trained = False
    
    def extract_features(self, pe_file: str) -> np.ndarray:
        """
        Extract features from PE file
        
        Args:
            pe_file: Path to PE file
            
        Returns:
            Feature vector
        """
        with PEParser(pe_file) as parser:
            features_dict = parser.extract_all_features()
        
        # Convert to feature vector
        features = []
        
        # Basic features
        features.append(features_dict.get('file_size', 0))
        features.append(features_dict.get('number_of_sections', 0))
        features.append(features_dict.get('timestamp', 0))
        features.append(features_dict.get('size_of_code', 0))
        features.append(features_dict.get('size_of_initialized_data', 0))
        features.append(features_dict.get('size_of_uninitialized_data', 0))
        features.append(features_dict.get('address_of_entry_point', 0))
        features.append(features_dict.get('size_of_image', 0))
        features.append(features_dict.get('size_of_headers', 0))
        features.append(features_dict.get('checksum', 0))
        
        # Section features
        features.append(features_dict.get('section_count', 0))
        features.append(features_dict.get('total_virtual_size', 0))
        features.append(features_dict.get('total_raw_size', 0))
        features.append(features_dict.get('avg_section_entropy', 0))
        
        # Import features
        features.append(features_dict.get('imported_dll_count', 0))
        features.append(features_dict.get('total_imported_functions', 0))
        features.append(features_dict.get('suspicious_import_count', 0))
        
        # Export features
        features.append(features_dict.get('export_count', 0))
        
        # Entropy features
        features.append(features_dict.get('file_entropy', 0))
        features.append(features_dict.get('packed_probability', 0))
        
        # Resource features
        features.append(features_dict.get('resource_count', 0))
        
        # Suspicion features
        features.append(features_dict.get('suspicion_score', 0))
        
        # Boolean features
        features.append(1 if features_dict.get('is_dll', False) else 0)
        features.append(1 if features_dict.get('is_exe', False) else 0)
        features.append(1 if features_dict.get('is_driver', False) else 0)
        
        return np.array(features)
    
    def train(self, malware_files: List[str], benign_files: List[str]) -> Dict[str, float]:
        """
        Train classifier
        
        Args:
            malware_files: List of malware file paths
            benign_files: List of benign file paths
            
        Returns:
            Training metrics
        """
        print("[*] Extracting features from malware samples...")
        X_malware = []
        for i, file in enumerate(malware_files):
            try:
                features = self.extract_features(file)
                X_malware.append(features)
                if (i + 1) % 10 == 0:
                    print(f"    Processed {i+1}/{len(malware_files)} malware samples")
            except Exception as e:
                print(f"    Error processing {file}: {e}")
        
        print("[*] Extracting features from benign samples...")
        X_benign = []
        for i, file in enumerate(benign_files):
            try:
                features = self.extract_features(file)
                X_benign.append(features)
                if (i + 1) % 10 == 0:
                    print(f"    Processed {i+1}/{len(benign_files)} benign samples")
            except Exception as e:
                print(f"    Error processing {file}: {e}")
        
        # Create dataset
        X = np.array(X_malware + X_benign)
        y = np.array([1] * len(X_malware) + [0] * len(X_benign))
        
        print(f"[*] Dataset: {len(X_malware)} malware, {len(X_benign)} benign")
        
        # Split dataset
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        print("[*] Scaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        print("[*] Training Random Forest...")
        self.rf_classifier.fit(X_train_scaled, y_train)
        rf_pred = self.rf_classifier.predict(X_test_scaled)
        rf_acc = accuracy_score(y_test, rf_pred)
        print(f"    Random Forest Accuracy: {rf_acc:.4f}")
        
        # Train Gradient Boosting
        print("[*] Training Gradient Boosting...")
        self.gb_classifier.fit(X_train_scaled, y_train)
        gb_pred = self.gb_classifier.predict(X_test_scaled)
        gb_acc = accuracy_score(y_test, gb_pred)
        print(f"    Gradient Boosting Accuracy: {gb_acc:.4f}")
        
        # Train Neural Network
        print("[*] Training Neural Network...")
        self.nn_classifier.fit(X_train_scaled, y_train)
        nn_pred = self.nn_classifier.predict(X_test_scaled)
        nn_acc = accuracy_score(y_test, nn_pred)
        print(f"    Neural Network Accuracy: {nn_acc:.4f}")
        
        # Ensemble prediction
        ensemble_pred = self._ensemble_predict(X_test_scaled)
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_test, ensemble_pred),
            'precision': precision_score(y_test, ensemble_pred),
            'recall': recall_score(y_test, ensemble_pred),
            'f1': f1_score(y_test, ensemble_pred),
            'rf_accuracy': rf_acc,
            'gb_accuracy': gb_acc,
            'nn_accuracy': nn_acc,
        }
        
        self.is_trained = True
        
        print(f"[✓] Training complete!")
        print(f"    Ensemble Accuracy: {metrics['accuracy']:.4f}")
        print(f"    Precision: {metrics['precision']:.4f}")
        print(f"    Recall: {metrics['recall']:.4f}")
        print(f"    F1 Score: {metrics['f1']:.4f}")
        
        return metrics
    
    def predict(self, pe_file: str) -> Tuple[int, float]:
        """
        Predict if file is malware
        
        Args:
            pe_file: Path to PE file
            
        Returns:
            Tuple of (prediction, confidence)
            prediction: 1 = malware, 0 = benign
            confidence: 0.0 to 1.0
        """
        if not self.is_trained:
            raise ValueError("Classifier not trained. Call train() first.")
        
        # Extract features
        features = self.extract_features(pe_file)
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # Get predictions from all models
        rf_prob = self.rf_classifier.predict_proba(features_scaled)[0]
        gb_prob = self.gb_classifier.predict_proba(features_scaled)[0]
        nn_prob = self.nn_classifier.predict_proba(features_scaled)[0]
        
        # Ensemble (average probabilities)
        avg_prob = (rf_prob + gb_prob + nn_prob) / 3
        
        prediction = 1 if avg_prob[1] > 0.5 else 0
        confidence = avg_prob[1] if prediction == 1 else avg_prob[0]
        
        return prediction, confidence
    
    def _ensemble_predict(self, X: np.ndarray) -> np.ndarray:
        """Ensemble prediction using voting"""
        rf_pred = self.rf_classifier.predict(X)
        gb_pred = self.gb_classifier.predict(X)
        nn_pred = self.nn_classifier.predict(X)
        
        # Majority voting
        ensemble = []
        for i in range(len(X)):
            votes = [rf_pred[i], gb_pred[i], nn_pred[i]]
            ensemble.append(1 if sum(votes) >= 2 else 0)
        
        return np.array(ensemble)
    
    def get_detection_score(self, pe_file: str) -> float:
        """
        Get malware detection score (0-100)
        
        Args:
            pe_file: Path to PE file
            
        Returns:
            Detection score (0 = benign, 100 = definitely malware)
        """
        if not self.is_trained:
            # Use heuristics if not trained
            with PEParser(pe_file) as parser:
                features = parser.extract_all_features()
            
            score = 0
            
            # High entropy
            if features.get('file_entropy', 0) > 7.0:
                score += 30
            
            # Suspicious imports
            score += min(features.get('suspicious_import_count', 0) * 5, 30)
            
            # Suspicion indicators
            score += min(features.get('suspicion_score', 0) * 10, 40)
            
            return min(score, 100)
        
        else:
            prediction, confidence = self.predict(pe_file)
            return confidence * 100 if prediction == 1 else (1 - confidence) * 100
    
    def save(self, filepath: str):
        """Save classifier"""
        model_data = {
            'scaler': self.scaler,
            'rf_classifier': self.rf_classifier,
            'gb_classifier': self.gb_classifier,
            'nn_classifier': self.nn_classifier,
            'is_trained': self.is_trained
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"[✓] Saved classifier to {filepath}")
    
    def load(self, filepath: str):
        """Load classifier"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.scaler = model_data['scaler']
        self.rf_classifier = model_data['rf_classifier']
        self.gb_classifier = model_data['gb_classifier']
        self.nn_classifier = model_data['nn_classifier']
        self.is_trained = model_data['is_trained']
        
        print(f"[✓] Loaded classifier from {filepath}")
