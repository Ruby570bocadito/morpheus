"""
Example: Train classifier
"""

from models.classifier import MalwareClassifier
from pathlib import Path

def main():
    # Initialize classifier
    classifier = MalwareClassifier()
    
    # Get training data
    malware_dir = Path('data/malware')
    benign_dir = Path('data/benign')
    
    malware_files = [str(f) for f in malware_dir.glob('*.exe')]
    benign_files = [str(f) for f in benign_dir.glob('*.exe')]
    
    print(f"Training with {len(malware_files)} malware and {len(benign_files)} benign samples")
    
    # Train
    metrics = classifier.train(malware_files, benign_files)
    
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"F1 Score: {metrics['f1']:.4f}")
    
    # Save model
    classifier.save('models/pretrained/classifier.pkl')
    print("Model saved!")

if __name__ == '__main__':
    main()
