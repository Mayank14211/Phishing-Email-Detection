from model import PhishingDetector
import os
import spacy
import nltk
import logging
import sys
from datetime import datetime

# Set up logging
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, f"test_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)

def initialize_nlp():
    """Initialize NLP components"""
    logging.info("Initializing NLP components...")
    # Download NLTK data
    nltk.download('punkt', quiet=True)
    nltk.download('averaged_perceptron_tagger', quiet=True)
    nltk.download('maxent_ne_chunker', quiet=True)
    nltk.download('words', quiet=True)
    
    # Verify spaCy model
    try:
        nlp = spacy.load('en_core_web_sm')
        logging.info("SpaCy model loaded successfully")
    except OSError:
        logging.info("Downloading spaCy model...")
        os.system("python -m spacy download en_core_web_sm")
    logging.info("NLP initialization complete!")

def test_single_email(email_path: str, is_phishing: bool):
    """Test a single email and print the results"""
    try:
        # Load the email
        logging.info(f"Loading email from: {email_path}")
        with open(email_path, 'r', encoding='utf-8') as f:
            email_content = f.read()
        logging.info("Email loaded successfully")
        
        # Initialize detector without loading model (it will be trained on this email)
        logging.info("Initializing detector...")
        detector = PhishingDetector()
        logging.info("Detector initialized")
        
        # Train on this single example
        logging.info("Training on the email...")
        detector.train(
            train_data=[(email_content, 1 if is_phishing else 0)],
            epochs=1,
            batch_size=1
        )
        logging.info("Training complete")
        
        # Analyze the same email
        logging.info("Analyzing email...")
        results = detector.analyze_email(email_content)
        
        # Print results
        logging.info(f"\nResults for {os.path.basename(email_path)}:")
        logging.info(f"Expected classification: {'Phishing' if is_phishing else 'Legitimate'}")
        logging.info(f"Risk Level: {results['risk_level']}")
        logging.info(f"Phishing Probability: {results['probability']:.2%}")
        
        if results['suspicious_features']:
            logging.info("\nSuspicious Features Detected:")
            for feature in results['suspicious_features']:
                logging.info(f"- {feature}")
        
    except FileNotFoundError:
        logging.error(f"Error: Email file not found at {email_path}")
        logging.error("Please ensure the test email files exist in the test_emails directory")
    except Exception as e:
        logging.error(f"Error testing {email_path}: {str(e)}")
        logging.error("Stack trace:", exc_info=True)

if __name__ == "__main__":
    try:
        logging.info("Starting email testing process...")
        
        # Initialize NLP components first
        initialize_nlp()
        
        # Get the absolute path to the test emails
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)
        test_dir = os.path.join(project_root, "test_emails")
        
        # Ensure test directory exists
        if not os.path.exists(test_dir):
            logging.info(f"Creating test directory at: {test_dir}")
            os.makedirs(test_dir)
        
        # Verify test files exist
        phishing_path = os.path.join(test_dir, "phishing1.eml")
        legitimate_path = os.path.join(test_dir, "legitimate1.eml")
        
        files_exist = True
        if not os.path.exists(phishing_path):
            logging.error(f"Error: Phishing test file not found at {phishing_path}")
            files_exist = False
        if not os.path.exists(legitimate_path):
            logging.error(f"Error: Legitimate test file not found at {legitimate_path}")
            files_exist = False
            
        if not files_exist:
            logging.error("\nPlease ensure both test email files exist:")
            logging.error("1. test_emails/phishing1.eml")
            logging.error("2. test_emails/legitimate1.eml")
            sys.exit(1)
        
        # Test phishing email
        logging.info("\nTesting phishing email...")
        test_single_email(phishing_path, True)
        
        # Test legitimate email
        logging.info("\nTesting legitimate email...")
        test_single_email(legitimate_path, False)
        
        logging.info(f"\nTest complete! Check the log file at: {log_file}")
        
    except Exception as e:
        logging.error(f"Error in main execution: {str(e)}")
        logging.error("Stack trace:", exc_info=True) 