import os
from typing import List, Tuple
from model import PhishingDetector
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import logging

# Set up logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')

def load_email_from_file(file_path: str) -> str:
    """Load raw email content from a file"""
    logging.info(f"Loading email from {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        logging.error(f"Error loading email from {file_path}: {str(e)}")
        raise

def evaluate_single_email(detector: PhishingDetector, email_raw: str) -> dict:
    """Analyze a single email and return detailed results"""
    try:
        results = detector.analyze_email(email_raw)
        print("\nAnalysis Results:")
        print(f"Risk Level: {results['risk_level']}")
        print(f"Phishing Probability: {results['probability']:.2%}")
        if results['suspicious_features']:
            print("\nSuspicious Features Detected:")
            for feature in results['suspicious_features']:
                print(f"- {feature}")
        return results
    except Exception as e:
        logging.error(f"Error analyzing email: {str(e)}")
        raise

def evaluate_dataset(detector: PhishingDetector, 
                    email_files: List[Tuple[str, int]], 
                    output_dir: str = "results"):
    """Evaluate model performance on a dataset of emails"""
    logging.info("Starting dataset evaluation")
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logging.info(f"Created output directory: {output_dir}")
    
    results = []
    true_labels = []
    predicted_probs = []
    
    for email_path, true_label in email_files:
        try:
            logging.info(f"Processing {email_path}")
            email_raw = load_email_from_file(email_path)
            analysis = detector.analyze_email(email_raw)
            
            results.append({
                'file': email_path,
                'true_label': true_label,
                'predicted_prob': analysis['probability'],
                'predicted_label': 1 if analysis['probability'] > 0.5 else 0,
                'risk_level': analysis['risk_level'],
                'suspicious_features': '; '.join(analysis['suspicious_features'])
            })
            
            true_labels.append(true_label)
            predicted_probs.append(analysis['probability'])
            
            logging.info(f"Successfully analyzed {email_path}")
            
        except Exception as e:
            logging.error(f"Error processing {email_path}: {str(e)}")
            continue
    
    if not results:
        logging.error("No results generated. Evaluation failed.")
        return None, None, None
    
    # Convert results to DataFrame
    df = pd.DataFrame(results)
    
    try:
        # Calculate metrics
        predicted_labels = (df['predicted_prob'] > 0.5).astype(int)
        report = classification_report(df['true_label'], predicted_labels)
        conf_matrix = confusion_matrix(df['true_label'], predicted_labels)
        
        # Save results
        results_file = os.path.join(output_dir, 'detailed_results.csv')
        df.to_csv(results_file, index=False)
        logging.info(f"Saved detailed results to {results_file}")
        
        # Save metrics report
        metrics_file = os.path.join(output_dir, 'metrics_report.txt')
        with open(metrics_file, 'w') as f:
            f.write("Classification Report:\n")
            f.write(report)
            f.write("\n\nConfusion Matrix:\n")
            f.write(str(conf_matrix))
        logging.info(f"Saved metrics report to {metrics_file}")
        
        # Plot confusion matrix
        plt.figure(figsize=(8, 6))
        sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues')
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plot_file = os.path.join(output_dir, 'confusion_matrix.png')
        plt.savefig(plot_file)
        plt.close()
        logging.info(f"Saved confusion matrix plot to {plot_file}")
        
        return df, report, conf_matrix
    
    except Exception as e:
        logging.error(f"Error generating evaluation metrics: {str(e)}")
        return df, None, None

if __name__ == "__main__":
    try:
        # Initialize the model
        model_path = os.path.join("models", "phishing_detector.h5")
        logging.info(f"Loading model from {model_path}")
        
        detector = PhishingDetector(model_path)
        logging.info("Model loaded successfully!")
        
        # Test directory paths
        test_dir = "test_emails"
        if not os.path.exists(test_dir):
            os.makedirs(test_dir)
            logging.info(f"Created test directory: {test_dir}")
        
        # Example usage for dataset evaluation
        test_emails = [
            (os.path.join(test_dir, "phishing1.eml"), 1),
            (os.path.join(test_dir, "legitimate1.eml"), 0),
        ]
        
        logging.info("Starting evaluation of test emails")
        results_df, metrics_report, conf_matrix = evaluate_dataset(detector, test_emails)
        
        if results_df is not None:
            print("\nEvaluation completed successfully!")
            print("\nClassification Report:")
            print(metrics_report)
            
            # Print summary
            total = len(results_df)
            correct = sum(results_df['true_label'] == results_df['predicted_label'])
            accuracy = correct / total
            print(f"\nAccuracy: {accuracy:.2%} ({correct}/{total} correct)")
        
    except Exception as e:
        logging.error(f"Error in main execution: {str(e)}")
        raise 