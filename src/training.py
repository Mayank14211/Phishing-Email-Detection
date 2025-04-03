import os
import json
from typing import List, Tuple
import numpy as np
from sklearn.model_selection import train_test_split
from .model import PhishingDetector

def load_dataset(data_dir: str) -> List[Tuple[str, int]]:
    """Load email dataset from directory"""
    dataset = []
    
    # Load phishing emails
    phishing_dir = os.path.join(data_dir, 'phishing')
    for filename in os.listdir(phishing_dir):
        if filename.endswith('.txt'):
            with open(os.path.join(phishing_dir, filename), 'r', encoding='utf-8') as f:
                email_content = f.read()
                dataset.append((email_content, 1))
    
    # Load legitimate emails
    legitimate_dir = os.path.join(data_dir, 'legitimate')
    for filename in os.listdir(legitimate_dir):
        if filename.endswith('.txt'):
            with open(os.path.join(legitimate_dir, filename), 'r', encoding='utf-8') as f:
                email_content = f.read()
                dataset.append((email_content, 0))
    
    return dataset

def main():
    """Main training function"""
    # Initialize paths
    data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
    model_dir = os.path.join(os.path.dirname(__file__), '..', 'models')
    os.makedirs(model_dir, exist_ok=True)
    
    # Load dataset
    print("Loading dataset...")
    dataset = load_dataset(data_dir)
    
    # Split dataset
    train_data, test_data = train_test_split(
        dataset,
        test_size=0.2,
        random_state=42,
        stratify=[label for _, label in dataset]
    )
    
    train_data, val_data = train_test_split(
        train_data,
        test_size=0.2,
        random_state=42,
        stratify=[label for _, label in train_data]
    )
    
    print(f"Dataset split: {len(train_data)} train, {len(val_data)} validation, {len(test_data)} test")
    
    # Initialize and train model
    print("Initializing model...")
    detector = PhishingDetector()
    
    print("Training model...")
    detector.train(
        train_data=train_data,
        validation_data=val_data,
        epochs=10,
        batch_size=32
    )
    
    # Evaluate model
    print("\nEvaluating model...")
    correct = 0
    total = len(test_data)
    results = []
    
    for email_content, true_label in test_data:
        prediction = detector.analyze_email(email_content)
        predicted_label = 1 if prediction['probability'] > 0.5 else 0
        
        if predicted_label == true_label:
            correct += 1
        
        results.append({
            'true_label': true_label,
            'predicted_label': predicted_label,
            'probability': prediction['probability'],
            'risk_level': prediction['risk_level'],
            'suspicious_features': prediction['suspicious_features']
        })
    
    accuracy = correct / total
    print(f"Test Accuracy: {accuracy:.4f}")
    
    # Save model
    print("\nSaving model...")
    model_path = os.path.join(model_dir, 'phishing_detector')
    detector.save_model(model_path)
    
    # Save evaluation results
    results_path = os.path.join(model_dir, 'evaluation_results.json')
    with open(results_path, 'w') as f:
        json.dump({
            'accuracy': accuracy,
            'results': results
        }, f, indent=2)
    
    print(f"Model and evaluation results saved to {model_dir}")

if __name__ == '__main__':
    main()