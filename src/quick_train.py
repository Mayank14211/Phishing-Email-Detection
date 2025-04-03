import os
from model import PhishingDetector

def main():
    """Quick training function using test emails"""
    # Initialize paths
    model_dir = "models"
    os.makedirs(model_dir, exist_ok=True)
    
    # Create training data from our test emails
    train_data = []
    
    # Load phishing email
    with open("test_emails/phishing1.eml", 'r', encoding='utf-8') as f:
        train_data.append((f.read(), 1))
    
    # Load legitimate email
    with open("test_emails/legitimate1.eml", 'r', encoding='utf-8') as f:
        train_data.append((f.read(), 0))
    
    # Initialize model
    print("Initializing model...")
    detector = PhishingDetector()
    
    # Train model
    print("Training model...")
    detector.train(
        train_data=train_data,
        epochs=5,
        batch_size=1
    )
    
    # Save model
    print("\nSaving model...")
    model_path = os.path.join(model_dir, "phishing_detector.h5")
    detector.save_model(model_path)
    print(f"Model saved to {model_path}")

if __name__ == '__main__':
    main() 