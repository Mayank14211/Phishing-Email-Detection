import os
import sys
import logging
import json
from datetime import datetime
import pandas as pd
import random

# Add the src directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our email analysis functionality
from enhanced_email_analyzer import EmailClassifier
from test_lottery_scam import simple_phishing_analysis, load_email_file

# Set up logging
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, f"model_augmentation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)

def generate_augmented_data():
    """Generate additional synthetic phishing examples focused on modern techniques"""
    augmented_data = []
    
    # 1. Emails with URL shorteners
    url_shortener_template = """
    Dear Customer,

    We've noticed an unusual login attempt on your account.
    To verify your identity, please click the link below:
    {url_shortener}/verify-account

    This link will expire in 24 hours.

    Security Team
    """
    url_shorteners = ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "tiny.cc"]
    for _ in range(20):
        shortener = random.choice(url_shorteners)
        content = url_shortener_template.format(url_shortener=shortener)
        augmented_data.append((content, 1))  # 1 = phishing
    
    # 2. Emails with typosquatted domains
    typosquat_template = """
    Hello,

    Your {brand} account needs to be verified.
    Please login at {typo_domain} to complete this process.

    Regards,
    {brand} Support Team
    """
    typosquat_examples = [
        ("Amazon", "arnazon.com"), 
        ("PayPal", "paypa1.com"),
        ("Microsoft", "micr0soft.com"),
        ("Apple", "apple-id.co"),
        ("Facebook", "faceb00k.com")
    ]
    for _ in range(20):
        brand, domain = random.choice(typosquat_examples)
        content = typosquat_template.format(brand=brand, typo_domain=domain)
        augmented_data.append((content, 1))  # 1 = phishing
    
    # 3. Emails with urgency + threats
    urgency_threat_template = """
    URGENT NOTICE:

    Your account has been flagged for {violation}.
    
    You have {timeframe} to verify your identity or your account will be {consequence}.
    
    Click here to avoid {consequence}: http://secure-verification.{domain}
    
    Security Department
    """
    violations = ["suspicious activity", "unusual login", "policy violation", "security breach"]
    timeframes = ["24 hours", "48 hours", "3 business days", "until tomorrow"]
    consequences = ["permanently suspended", "terminated", "locked", "reported to authorities"]
    domains = ["com", "net", "online", "site", "info"]
    
    for _ in range(30):
        content = urgency_threat_template.format(
            violation=random.choice(violations),
            timeframe=random.choice(timeframes),
            consequence=random.choice(consequences),
            domain=random.choice(domains)
        )
        augmented_data.append((content, 1))  # 1 = phishing
    
    # 4. Legitimate security notices (to reduce false positives)
    legitimate_template = """
    Security Notice from {company}

    We're contacting you about some changes to your account.
    
    We've updated our security policies. Please review them at:
    https://www.{company_domain}/security
    
    No immediate action is required.
    
    {company} Security Team
    """
    legitimate_companies = [
        ("Google", "google.com"),
        ("Microsoft", "microsoft.com"),
        ("Apple", "apple.com"),
        ("Amazon", "amazon.com"),
        ("Facebook", "facebook.com")
    ]
    
    for _ in range(20):
        company, domain = random.choice(legitimate_companies)
        content = legitimate_template.format(company=company, company_domain=domain)
        augmented_data.append((content, 0))  # 0 = legitimate
    
    logging.info(f"Generated {len(augmented_data)} augmented training examples")
    return augmented_data

def load_existing_model():
    """Load the existing pre-trained model"""
    classifier = EmailClassifier()
    if classifier.load_model():
        logging.info(f"Successfully loaded existing model with threshold {classifier.optimal_threshold}")
        return classifier
    else:
        logging.error("Failed to load existing model")
        return None

def fine_tune_model(classifier, augmented_data, real_examples=None):
    """Fine-tune the classifier using augmented data while preserving existing knowledge"""
    if not classifier:
        logging.error("No classifier provided for fine-tuning")
        return False
    
    logging.info(f"Starting fine-tuning with {len(augmented_data)} augmented examples")
    
    # Add real examples if available
    training_data = augmented_data.copy()
    if real_examples:
        logging.info(f"Adding {len(real_examples)} real examples to training data")
        training_data.extend(real_examples)
        
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
        best_threshold = classifier.optimal_threshold  # Start with existing threshold
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
        
        # Only update if the new threshold is better
        if best_accuracy > 0.7:  # Set a minimum acceptable accuracy
            classifier.optimal_threshold = best_threshold
            logging.info(f"Updated optimal threshold to {classifier.optimal_threshold:.2f} (accuracy: {best_accuracy:.2%})")
        else:
            logging.info(f"Keeping original threshold {classifier.optimal_threshold} as new accuracy {best_accuracy:.2%} is not sufficient")
        
        # Save the model with a different name to preserve the original
        model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
        model_path = os.path.join(model_dir, "email_classifier_augmented.json")
        
        model_data = {
            'optimal_threshold': classifier.optimal_threshold,
            'feature_weights': classifier.feature_weights,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(model_path, 'w') as f:
            json.dump(model_data, f, indent=2)
        
        logging.info(f"Augmented model saved to {model_path}")
        return True
    else:
        logging.error("Not enough data for both classes")
        return False

def load_real_examples():
    """Load real email examples from the uploads directory"""
    real_examples = []
    uploads_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
    
    if not os.path.exists(uploads_dir):
        logging.warning(f"Uploads directory not found at {uploads_dir}")
        return real_examples
    
    email_files = [f for f in os.listdir(uploads_dir) if f.endswith('.eml')]
    logging.info(f"Found {len(email_files)} real email files in uploads directory")
    
    for email_file in email_files:
        try:
            is_phishing = 1 if any(kw in email_file.lower() for kw in ["phish", "scam", "fraud"]) else 0
            file_path = os.path.join(uploads_dir, email_file)
            email_content = load_email_file(file_path)
            real_examples.append((email_content, is_phishing))
            logging.info(f"Added {email_file} as {'phishing' if is_phishing else 'legitimate'} example")
        except Exception as e:
            logging.error(f"Error loading {email_file}: {str(e)}")
    
    return real_examples

def evaluate_model(classifier, test_data):
    """Evaluate the fine-tuned model on test data"""
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
        
        logging.info(f"Evaluation metrics for augmented model:")
        logging.info(f"Accuracy: {accuracy:.4f}")
        logging.info(f"Precision: {precision:.4f}")
        logging.info(f"Recall: {recall:.4f}")
        logging.info(f"F1 Score: {f1:.4f}")
        logging.info(f"True Positives: {true_positives}, False Positives: {false_positives}")
        logging.info(f"True Negatives: {true_negatives}, False Negatives: {false_negatives}")
        
        # Save metrics to file
        metrics_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
        if not os.path.exists(metrics_dir):
            os.makedirs(metrics_dir)
            
        metrics_path = os.path.join(metrics_dir, f"augmented_model_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(metrics_path, 'w') as f:
            json.dump({
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'true_positives': true_positives,
                'false_positives': false_positives,
                'true_negatives': true_negatives,
                'false_negatives': false_negatives
            }, f, indent=2)
            
        logging.info(f"Metrics saved to {metrics_path}")
        return accuracy, precision, recall, f1
    
    return 0, 0, 0, 0

def main():
    """Augment training and fine-tune the model"""
    try:
        logging.info("Starting model augmentation process...")
        
        # Load existing model
        classifier = load_existing_model()
        if not classifier:
            logging.error("Exiting: Could not load existing model")
            return
        
        # Generate augmented data
        augmented_data = generate_augmented_data()
        
        # Load real examples from uploads directory
        real_examples = load_real_examples()
        
        # Split data for training and testing
        random.shuffle(augmented_data)
        train_size = int(len(augmented_data) * 0.7)
        train_data = augmented_data[:train_size]
        test_data = augmented_data[train_size:]
        
        # Add real examples to test data
        if real_examples:
            test_data.extend(real_examples)
        
        # Fine-tune the model
        success = fine_tune_model(classifier, train_data, real_examples)
        
        if success:
            logging.info("Model augmentation completed successfully")
            
            # Load the augmented model
            augmented_classifier = EmailClassifier()
            model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                     "models", "email_classifier_augmented.json")
            
            if os.path.exists(model_path):
                with open(model_path, 'r') as f:
                    model_data = json.load(f)
                
                augmented_classifier.optimal_threshold = model_data.get('optimal_threshold', 0.5)
                augmented_classifier.feature_weights = model_data.get('feature_weights', {})
                augmented_classifier.trained = True
                
                # Evaluate the augmented model
                accuracy, precision, recall, f1 = evaluate_model(augmented_classifier, test_data)
                
                logging.info(f"Augmented model performance: Accuracy={accuracy:.2%}, F1={f1:.2%}")
                
                # Compare with original model on the same test data
                orig_accuracy, orig_precision, orig_recall, orig_f1 = evaluate_model(classifier, test_data)
                
                logging.info(f"Original model performance: Accuracy={orig_accuracy:.2%}, F1={orig_f1:.2%}")
                logging.info(f"Improvement: Accuracy={accuracy-orig_accuracy:.2%}, F1={f1-orig_f1:.2%}")
            else:
                logging.error(f"Augmented model file not found at {model_path}")
        else:
            logging.error("Model augmentation failed")
        
    except Exception as e:
        logging.error(f"Error in augmentation process: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 