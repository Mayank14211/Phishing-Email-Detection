import os
import sys
import logging
import csv
from datetime import datetime
from test_lottery_scam import simple_phishing_analysis, load_email_file

# Set up logging
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, f"batch_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)

def process_email_directory(email_dir):
    """Process all emails in a directory"""
    results = []
    
    # Make sure directory exists
    if not os.path.exists(email_dir):
        logging.error(f"Directory not found: {email_dir}")
        return results
    
    # Get all .eml files
    email_files = [f for f in os.listdir(email_dir) if f.endswith('.eml')]
    
    if not email_files:
        logging.warning(f"No .eml files found in {email_dir}")
        return results
    
    logging.info(f"Found {len(email_files)} emails to analyze")
    
    # Process each email
    for filename in email_files:
        file_path = os.path.join(email_dir, filename)
        logging.info(f"Processing {filename}...")
        
        try:
            # Load email content
            email_content = load_email_file(file_path)
            
            # Analyze email
            analysis = simple_phishing_analysis(email_content)
            
            # Determine expected classification from filename
            expected_class = 1 if 'phishing' in filename.lower() else 0
            predicted_class = 1 if analysis['probability'] > 0.5 else 0
            
            # Add to results
            results.append({
                'filename': filename,
                'expected_class': expected_class,
                'predicted_class': predicted_class,
                'probability': analysis['probability'],
                'risk_level': analysis['risk_level'],
                'risk_score': analysis['risk_score'],
                'suspicious_features': ', '.join(analysis['suspicious_features']),
                'correct': expected_class == predicted_class
            })
            
            # Display individual results
            logging.info(f"  Risk Level: {analysis['risk_level']}")
            logging.info(f"  Phishing Probability: {analysis['probability']:.2%}")
            logging.info(f"  Expected Class: {'PHISHING' if expected_class == 1 else 'LEGITIMATE'}")
            logging.info(f"  Predicted Class: {'PHISHING' if predicted_class == 1 else 'LEGITIMATE'}")
            logging.info(f"  Prediction: {'CORRECT' if expected_class == predicted_class else 'INCORRECT'}")
            
        except Exception as e:
            logging.error(f"Error processing {filename}: {str(e)}")
    
    return results

def save_results_to_csv(results, output_file):
    """Save results to CSV file"""
    try:
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['filename', 'expected_class', 'predicted_class', 'probability', 
                          'risk_level', 'risk_score', 'suspicious_features', 'correct']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow(result)
                
        logging.info(f"Results saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving results to CSV: {str(e)}")

def calculate_metrics(results):
    """Calculate performance metrics"""
    if not results:
        logging.warning("No results to calculate metrics")
        return
    
    total = len(results)
    correct = sum(1 for r in results if r['correct'])
    accuracy = correct / total if total > 0 else 0
    
    # True positives, false positives, etc.
    tp = sum(1 for r in results if r['expected_class'] == 1 and r['predicted_class'] == 1)
    fp = sum(1 for r in results if r['expected_class'] == 0 and r['predicted_class'] == 1)
    tn = sum(1 for r in results if r['expected_class'] == 0 and r['predicted_class'] == 0)
    fn = sum(1 for r in results if r['expected_class'] == 1 and r['predicted_class'] == 0)
    
    # Calculate precision, recall, f1-score
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    # Log metrics
    logging.info("\nPerformance Metrics:")
    logging.info(f"Accuracy: {accuracy:.2%} ({correct}/{total})")
    logging.info(f"Precision: {precision:.2%}")
    logging.info(f"Recall: {recall:.2%}")
    logging.info(f"F1 Score: {f1:.2%}")
    logging.info(f"True Positives: {tp}")
    logging.info(f"False Positives: {fp}")
    logging.info(f"True Negatives: {tn}")
    logging.info(f"False Negatives: {fn}")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'tp': tp,
        'fp': fp,
        'tn': tn,
        'fn': fn
    }

def main():
    """Main function to batch analyze emails"""
    try:
        # Set up directories
        current_dir = os.path.dirname(os.path.abspath(__file__))
        email_dir = os.path.join(current_dir, "Emails")
        results_dir = os.path.join(os.path.dirname(current_dir), "results")
        
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        logging.info(f"Starting batch analysis of emails in {email_dir}")
        
        # Process emails
        results = process_email_directory(email_dir)
        
        if not results:
            logging.error("No emails were successfully analyzed")
            return
        
        # Save results to CSV
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(results_dir, f"email_analysis_{timestamp}.csv")
        save_results_to_csv(results, output_file)
        
        # Calculate metrics
        metrics = calculate_metrics(results)
        
        # Save metrics to a separate file
        metrics_file = os.path.join(results_dir, f"metrics_{timestamp}.txt")
        try:
            with open(metrics_file, 'w') as f:
                f.write("Performance Metrics:\n")
                f.write(f"Accuracy: {metrics['accuracy']:.2%}\n")
                f.write(f"Precision: {metrics['precision']:.2%}\n")
                f.write(f"Recall: {metrics['recall']:.2%}\n")
                f.write(f"F1 Score: {metrics['f1']:.2%}\n")
                f.write(f"True Positives: {metrics['tp']}\n")
                f.write(f"False Positives: {metrics['fp']}\n")
                f.write(f"True Negatives: {metrics['tn']}\n")
                f.write(f"False Negatives: {metrics['fn']}\n")
            logging.info(f"Metrics saved to {metrics_file}")
        except Exception as e:
            logging.error(f"Error saving metrics: {str(e)}")
        
        # Add lottery scam email to the analysis
        lottery_scam_path = os.path.join(current_dir, "phishing_lottery_scam.eml")
        if os.path.exists(lottery_scam_path):
            logging.info("\nAnalyzing lottery scam email...")
            try:
                email_content = load_email_file(lottery_scam_path)
                analysis = simple_phishing_analysis(email_content)
                
                print("\nLottery Scam Email Analysis:")
                print(f"Risk Level: {analysis['risk_level']}")
                print(f"Phishing Probability: {analysis['probability']:.2%}")
                
                if analysis['suspicious_features']:
                    print("\nSuspicious Features Detected:")
                    for feature in analysis['suspicious_features']:
                        print(f"- {feature}")
                
                prediction = "PHISHING" if analysis['probability'] > 0.5 else "LEGITIMATE"
                print(f"\nCONCLUSION: This email is classified as {prediction} with {analysis['probability']:.2%} confidence")
            except Exception as e:
                logging.error(f"Error analyzing lottery scam email: {str(e)}")
        
        logging.info(f"\nAnalysis complete! Check logs at: {log_file}")
        
    except Exception as e:
        logging.error(f"Error in main execution: {str(e)}")
        logging.error("Stack trace:", exc_info=True)

if __name__ == "__main__":
    main() 