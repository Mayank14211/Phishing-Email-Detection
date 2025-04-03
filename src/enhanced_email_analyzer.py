import os
import sys
import logging
import csv
import json
import random
from datetime import datetime
from test_lottery_scam import load_email_file, simple_phishing_analysis

# Set up logging
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, f"enhanced_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)

class EmailClassifier:
    def __init__(self):
        self.optimal_threshold = 0.5  # Default threshold
        self.feature_weights = {
            'urgent_words': 2,
            'money_words': 2,
            'sensitive_words': 3,
            'suspicious_domains': 5
        }
        self.trained = False
    
    def train(self, training_emails):
        """Train the classifier on labeled emails to find optimal threshold"""
        if not training_emails:
            logging.error("No training emails provided")
            return False
        
        logging.info(f"Training on {len(training_emails)} emails")
        
        # Process training emails and get scores
        scores_by_class = {'phishing': [], 'legitimate': []}
        
        for email_path, is_phishing in training_emails:
            try:
                email_content = load_email_file(email_path)
                analysis = simple_phishing_analysis(email_content)
                
                if is_phishing:
                    scores_by_class['phishing'].append(analysis['probability'])
                else:
                    scores_by_class['legitimate'].append(analysis['probability'])
                
            except Exception as e:
                logging.error(f"Error processing {email_path} for training: {str(e)}")
        
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
            
            self.optimal_threshold = best_threshold
            logging.info(f"Optimal threshold determined: {self.optimal_threshold:.2f} (accuracy: {best_accuracy:.2%})")
        
        # Optimize feature weights (simplified approach)
        # In a more advanced implementation, this would use statistical analysis or machine learning
        # to determine optimal weights based on feature correlation with correct classifications
        phishing_stats = self.calculate_feature_stats(scores_by_class['phishing'], True)
        legitimate_stats = self.calculate_feature_stats(scores_by_class['legitimate'], False)
        
        # Save the model
        self.save_model()
        self.trained = True
        
        return True
    
    def calculate_feature_stats(self, scores, is_phishing):
        """Calculate statistics about features for a class of emails"""
        return {
            'avg_score': sum(scores) / len(scores) if scores else 0,
            'count': len(scores),
            'class': 'phishing' if is_phishing else 'legitimate'
        }
    
    def save_model(self):
        """Save the trained model parameters"""
        model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
        
        model_path = os.path.join(model_dir, "email_classifier.json")
        
        model_data = {
            'optimal_threshold': self.optimal_threshold,
            'feature_weights': self.feature_weights,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(model_path, 'w') as f:
            json.dump(model_data, f, indent=2)
        
        logging.info(f"Model saved to {model_path}")
    
    def load_model(self):
        """Load a trained model if available"""
        model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                 "models", "email_classifier.json")
        
        if os.path.exists(model_path):
            try:
                with open(model_path, 'r') as f:
                    model_data = json.load(f)
                
                self.optimal_threshold = model_data.get('optimal_threshold', 0.5)
                self.feature_weights = model_data.get('feature_weights', self.feature_weights)
                
                logging.info(f"Model loaded from {model_path}")
                logging.info(f"Using threshold: {self.optimal_threshold}")
                self.trained = True
                return True
            except Exception as e:
                logging.error(f"Error loading model: {str(e)}")
                return False
        else:
            logging.warning("No model file found, using default parameters")
            return False
    
    def predict(self, email_content):
        """Predict if an email is phishing using the trained threshold"""
        # Analyze email using our existing function
        analysis = simple_phishing_analysis(email_content)
        
        # Apply trained threshold
        predicted_class = 1 if analysis['probability'] > self.optimal_threshold else 0
        
        return {
            'predicted_class': predicted_class,
            'probability': analysis['probability'],
            'risk_level': analysis['risk_level'],
            'suspicious_features': analysis['suspicious_features'],
            'threshold_used': self.optimal_threshold
        }

def load_email_data(email_dir):
    """Load email files from directory and return paths with labels"""
    email_data = []
    
    if not os.path.exists(email_dir):
        logging.error(f"Email directory does not exist: {email_dir}")
        return email_data
    
    for filename in os.listdir(email_dir):
        if filename.endswith('.eml'):
            file_path = os.path.join(email_dir, filename)
            is_phishing = 1 if 'phishing' in filename.lower() else 0
            email_data.append((file_path, is_phishing))
    
    return email_data

def split_data(email_data, train_ratio=0.7):
    """Split data into training and testing sets"""
    if not email_data:
        return [], []
    
    # Shuffle data
    random.shuffle(email_data)
    
    # Split based on ratio
    split_index = int(len(email_data) * train_ratio)
    train_data = email_data[:split_index]
    test_data = email_data[split_index:]
    
    return train_data, test_data

def evaluate_classifier(classifier, test_data):
    """Evaluate classifier on test data"""
    results = []
    
    for email_path, true_label in test_data:
        try:
            email_content = load_email_file(email_path)
            prediction = classifier.predict(email_content)
            
            result = {
                'filename': os.path.basename(email_path),
                'true_label': true_label,
                'predicted_class': prediction['predicted_class'],
                'probability': prediction['probability'],
                'risk_level': prediction['risk_level'],
                'suspicious_features': ', '.join(prediction['suspicious_features']),
                'correct': true_label == prediction['predicted_class']
            }
            
            results.append(result)
            
            # Log individual results
            logging.info(f"Analyzed: {os.path.basename(email_path)}")
            logging.info(f"  True Label: {'PHISHING' if true_label == 1 else 'LEGITIMATE'}")
            logging.info(f"  Predicted: {'PHISHING' if prediction['predicted_class'] == 1 else 'LEGITIMATE'}")
            logging.info(f"  Probability: {prediction['probability']:.2%}")
            logging.info(f"  Correct: {result['correct']}")
            
        except Exception as e:
            logging.error(f"Error evaluating {email_path}: {str(e)}")
    
    return results

def calculate_metrics(results):
    """Calculate performance metrics from results"""
    if not results:
        return None
    
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
    
    metrics = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'true_positives': true_positives,
        'false_positives': false_positives,
        'true_negatives': true_negatives,
        'false_negatives': false_negatives,
        'total': total
    }
    
    # Log metrics
    logging.info("\nPerformance Metrics:")
    logging.info(f"Accuracy: {accuracy:.2%} ({correct}/{total})")
    logging.info(f"Precision: {precision:.2%}")
    logging.info(f"Recall: {recall:.2%}")
    logging.info(f"F1 Score: {f1:.2%}")
    logging.info(f"True Positives: {true_positives}")
    logging.info(f"False Positives: {false_positives}")
    logging.info(f"True Negatives: {true_negatives}")
    logging.info(f"False Negatives: {false_negatives}")
    
    return metrics

def save_results(results, metrics, output_dir):
    """Save results and metrics to files"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Save results to CSV
    results_file = os.path.join(output_dir, f"results_{timestamp}.csv")
    with open(results_file, 'w', newline='') as csvfile:
        fieldnames = ['filename', 'true_label', 'predicted_class', 'probability', 
                      'risk_level', 'suspicious_features', 'correct']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)
    
    # Save metrics to text file
    metrics_file = os.path.join(output_dir, f"metrics_{timestamp}.txt")
    with open(metrics_file, 'w') as f:
        f.write("Performance Metrics:\n")
        f.write(f"Accuracy: {metrics['accuracy']:.2%}\n")
        f.write(f"Precision: {metrics['precision']:.2%}\n")
        f.write(f"Recall: {metrics['recall']:.2%}\n")
        f.write(f"F1 Score: {metrics['f1']:.2%}\n")
        f.write(f"True Positives: {metrics['true_positives']}\n")
        f.write(f"False Positives: {metrics['false_positives']}\n")
        f.write(f"True Negatives: {metrics['true_negatives']}\n")
        f.write(f"False Negatives: {metrics['false_negatives']}\n")
        f.write(f"Total Emails Analyzed: {metrics['total']}\n")
    
    logging.info(f"Results saved to {results_file}")
    logging.info(f"Metrics saved to {metrics_file}")
    
    return results_file, metrics_file

def analyze_lottery_scam(classifier, lottery_scam_path):
    """Analyze the lottery scam email with our trained classifier"""
    if not os.path.exists(lottery_scam_path):
        logging.error(f"Lottery scam email not found: {lottery_scam_path}")
        return
    
    try:
        email_content = load_email_file(lottery_scam_path)
        prediction = classifier.predict(email_content)
        
        print("\nLottery Scam Email Analysis:")
        print(f"Risk Level: {prediction['risk_level']}")
        print(f"Phishing Probability: {prediction['probability']:.2%}")
        print(f"Threshold Used: {prediction['threshold_used']:.2f}")
        
        if prediction['suspicious_features']:
            print("\nSuspicious Features Detected:")
            for feature in prediction['suspicious_features']:
                print(f"- {feature}")
        
        prediction_label = "PHISHING" if prediction['predicted_class'] == 1 else "LEGITIMATE"
        print(f"\nCONCLUSION: This email is classified as {prediction_label} with {prediction['probability']:.2%} confidence")
        
        return prediction
    
    except Exception as e:
        logging.error(f"Error analyzing lottery scam email: {str(e)}")
        return None

def main():
    """Main function for enhanced email analysis"""
    try:
        # Set up directories
        current_dir = os.path.dirname(os.path.abspath(__file__))
        email_dir = os.path.join(current_dir, "Emails")
        results_dir = os.path.join(os.path.dirname(current_dir), "results")
        
        logging.info("Starting enhanced email analysis")
        
        # Load email data
        email_data = load_email_data(email_dir)
        
        if not email_data:
            logging.error("No email data found")
            return
        
        logging.info(f"Loaded {len(email_data)} emails")
        
        # Add phishing_lottery_scam.eml to test data
        lottery_scam_path = os.path.join(current_dir, "phishing_lottery_scam.eml")
        if os.path.exists(lottery_scam_path):
            # We know it's phishing
            email_data.append((lottery_scam_path, 1))
            logging.info("Added lottery scam email to dataset")
        
        # Split data into training and testing sets
        train_data, test_data = split_data(email_data, train_ratio=0.7)
        logging.info(f"Split data: {len(train_data)} training emails, {len(test_data)} test emails")
        
        # Initialize and train classifier
        classifier = EmailClassifier()
        
        # Try to load existing model first
        if not classifier.load_model():
            logging.info("Training new classifier model")
            if not classifier.train(train_data):
                logging.error("Failed to train classifier")
                return
        
        # Evaluate on test data
        results = evaluate_classifier(classifier, test_data)
        
        if not results:
            logging.error("No results from evaluation")
            return
        
        # Calculate metrics
        metrics = calculate_metrics(results)
        
        # Save results
        save_results(results, metrics, results_dir)
        
        # Analyze lottery scam separately for demonstration
        lottery_scam_result = analyze_lottery_scam(classifier, lottery_scam_path)
        
        logging.info(f"Analysis complete! Log saved to: {log_file}")
        
    except Exception as e:
        logging.error(f"Error in main execution: {str(e)}")
        logging.error("Stack trace:", exc_info=True)

if __name__ == "__main__":
    main() 