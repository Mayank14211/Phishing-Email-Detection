import os
import sys
import logging
import zipfile
import json
from datetime import datetime
import pandas as pd
from sklearn.model_selection import train_test_split

# Add the src directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our email analysis functionality
from enhanced_email_analyzer import EmailClassifier
from test_lottery_scam import simple_phishing_analysis

# Set up logging
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, f"model_training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)

def prepare_data_from_csv(csv_path):
    """
    Prepare training data from CSV file
    Returns a list of tuples (email_content, is_phishing)
    """
    training_data = []
    
    try:
        # Read the CSV file using pandas
        logging.info(f"Reading CSV file: {csv_path}")
        df = pd.read_csv(csv_path)
        
        # Check if required columns exist
        if 'Email Text' not in df.columns or 'Email Type' not in df.columns:
            logging.error(f"CSV file does not have required columns (Email Text, Email Type)")
            return []
        
        # Ensure email text is string type
        df['Email Text'] = df['Email Text'].astype(str)
        
        # Log dataset information
        logging.info(f"Dataset contains {len(df)} emails")
        logging.info(f"Email types distribution: {df['Email Type'].value_counts().to_dict()}")
        
        # Split into training and test sets
        train_df, test_df = train_test_split(df, test_size=0.3, random_state=42, stratify=df['Email Type'])
        logging.info(f"Training set: {len(train_df)} emails, Test set: {len(test_df)} emails")
        
        # Extract data for training
        for idx, row in train_df.iterrows():
            email_content = str(row['Email Text'])
            is_phishing = 1 if row['Email Type'].lower() == 'phishing email' else 0
            training_data.append((email_content, is_phishing))
        
        # Extract data for testing
        test_data = []
        for idx, row in test_df.iterrows():
            email_content = str(row['Email Text'])
            is_phishing = 1 if row['Email Type'].lower() == 'phishing email' else 0
            test_data.append((email_content, is_phishing))
        
        logging.info(f"Prepared {len(training_data)} emails for training and {len(test_data)} emails for testing")
        return training_data, test_data
        
    except Exception as e:
        logging.error(f"Error preparing data from CSV: {str(e)}")
        logging.exception("Details:")
        return [], []

def train_model_with_csv(csv_path):
    """
    Train the model using CSV dataset
    """
    # Initialize classifier
    classifier = EmailClassifier()
    
    # Prepare data
    training_data, test_data = prepare_data_from_csv(csv_path)
    
    if not training_data:
        logging.error("No training data available")
        return False
    
    # Modify the train method for direct email content
    def train_with_content(classifier, training_data):
        """Train classifier with email content directly instead of file paths"""
        logging.info(f"Training on {len(training_data)} emails")
        
        # Process training emails and get scores
        scores_by_class = {'phishing': [], 'legitimate': []}
        
        for email_content, is_phishing in training_data:
            try:
                analysis = simple_phishing_analysis(email_content)
                
                if is_phishing:
                    scores_by_class['phishing'].append(analysis['probability'])
                else:
                    scores_by_class['legitimate'].append(analysis['probability'])
                
            except Exception as e:
                logging.error(f"Error processing email for training: {str(e)}")
        
        # Find optimal threshold if we have enough data
        if scores_by_class['phishing'] and scores_by_class['legitimate']:
            # Try different thresholds and pick the one with highest accuracy
            best_threshold = 0.5
            best_accuracy = 0.0
            
            for threshold in [t/100 for t in range(30, 90, 5)]:  # Try thresholds from 0.3 to 0.85
                correct = 0
                total = len(scores_by_class['phishing']) + len(scores_by_class['legitimate'])
                
                # Count correct classifications at this threshold
                correct += sum(1 for score in scores_by_class['phishing'] if score > threshold)
                correct += sum(1 for score in scores_by_class['legitimate'] if score <= threshold)
                
                accuracy = correct / total
                logging.info(f"Threshold {threshold:.2f} gives accuracy {accuracy:.2%}")
                
                if accuracy > best_accuracy:
                    best_accuracy = accuracy
                    best_threshold = threshold
            
            classifier.optimal_threshold = best_threshold
            logging.info(f"Optimal threshold determined: {classifier.optimal_threshold:.2f} (accuracy: {best_accuracy:.2%})")
            
            # Save the model
            classifier.save_model()
            classifier.trained = True
            
            return True
        else:
            logging.error("Not enough data for both classes")
            return False
    
    # Train the model
    success = train_with_content(classifier, training_data)
    
    if success:
        logging.info("Model training completed successfully!")
        
        # Evaluate on test data
        evaluate_with_content(classifier, test_data)
        
        return True
    else:
        logging.error("Model training failed")
        return False

def evaluate_with_content(classifier, test_data):
    """Evaluate classifier on test data using content directly"""
    results = []
    
    for email_content, true_label in test_data:
        try:
            prediction = classifier.predict(email_content)
            
            result = {
                'true_label': true_label,
                'predicted_class': prediction['predicted_class'],
                'probability': prediction['probability'],
                'risk_level': prediction['risk_level'],
                'correct': true_label == prediction['predicted_class']
            }
            
            results.append(result)
            
        except Exception as e:
            logging.error(f"Error evaluating email: {str(e)}")
    
    if results:
        # Calculate metrics
        total = len(results)
        correct = sum(1 for r in results if r['correct'])
        accuracy = correct / total if total > 0 else 0
        
        true_positives = sum(1 for r in results if r['true_label'] == 1 and r['predicted_class'] == 1)
        false_positives = sum(1 for r in results if r['true_label'] == 0 and r['predicted_class'] == 1)
        true_negatives = sum(1 for r in results if r['true_label'] == 0 and r['predicted_class'] == 0)
        false_negatives = sum(1 for r in results if r['true_label'] == 1 and r['predicted_class'] == 0)
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        logging.info(f"Evaluation metrics:")
        logging.info(f"Accuracy: {accuracy:.4f}")
        logging.info(f"Precision: {precision:.4f}")
        logging.info(f"Recall: {recall:.4f}")
        logging.info(f"F1 Score: {f1:.4f}")
        logging.info(f"True Positives: {true_positives}, False Positives: {false_positives}")
        logging.info(f"True Negatives: {true_negatives}, False Negatives: {false_negatives}")
        
        # Save confusion matrix
        confusion_matrix = {
            'true_positives': true_positives,
            'false_positives': false_positives,
            'true_negatives': true_negatives,
            'false_negatives': false_negatives,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
        
        # Save metrics to file
        metrics_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
        if not os.path.exists(metrics_dir):
            os.makedirs(metrics_dir)
            
        metrics_path = os.path.join(metrics_dir, f"model_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(metrics_path, 'w') as f:
            json.dump(confusion_matrix, f, indent=2)
            
        logging.info(f"Metrics saved to {metrics_path}")

def main():
    """Main function for training the model from CSV data"""
    try:
        print("Starting model training script...")
        
        # Set path to the extracted CSV file
        csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                              "Emails", "extracted", "Phishing_Email.csv")
        
        print(f"Looking for CSV file at: {csv_path}")
        
        # Check if CSV file exists
        if not os.path.exists(csv_path):
            print(f"CSV file not found at {csv_path}, checking for ZIP file...")
            # Try to extract from zip if CSV doesn't exist
            zip_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                  "Emails", "Phishing_Email.csv.zip")
            
            print(f"Looking for ZIP file at: {zip_path}")
            
            if os.path.exists(zip_path):
                extract_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                        "Emails", "extracted")
                
                if not os.path.exists(extract_dir):
                    os.makedirs(extract_dir)
                    print(f"Created extraction directory: {extract_dir}")
                
                print(f"Extracting {zip_path} to {extract_dir}")
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                
                if os.path.exists(csv_path):
                    print(f"Successfully extracted CSV file to {csv_path}")
                else:
                    print(f"Extraction failed, CSV file not found after extraction")
                    return
            else:
                print(f"ZIP file not found at {zip_path}")
                # List the contents of the Emails directory to see what's there
                emails_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Emails")
                if os.path.exists(emails_dir):
                    print(f"Contents of {emails_dir}:")
                    for item in os.listdir(emails_dir):
                        print(f"  - {item}")
                else:
                    print(f"Emails directory not found at {emails_dir}")
                return
        
        print(f"Starting model training with CSV data from {csv_path}")
        
        # Train the model with CSV data
        success = train_model_with_csv(csv_path)
        
        if success:
            print("Model training and evaluation completed successfully")
        else:
            print("Model training failed")
        
    except Exception as e:
        print(f"Error in main execution: {str(e)}")
        import traceback
        traceback.print_exc()
        logging.error(f"Error in main execution: {str(e)}")
        logging.error("Stack trace:", exc_info=True)

if __name__ == "__main__":
    main() 