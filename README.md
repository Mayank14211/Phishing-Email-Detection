# Phishing Email Detection System

A machine learning-based system for detecting phishing emails, featuring a web interface for easy analysis.

## Features

- Email content analysis for phishing indicators
- Web interface for uploading and analyzing email files
- CSV dataset support for training and evaluation
- Detailed reporting of suspicious features and risk levels

## Setup and Installation

1. Ensure you have Python 3.8+ installed
2. Install required dependencies:
   ```
   pip install flask pandas scikit-learn beautifulsoup4
   ```
3. Clone this repository:
   ```
   git clone <repository-url>
   cd phishing-detection
   ```

## Training the Model

The system comes with a pre-trained model, but you can train it on your own dataset:

1. Place your dataset in the `src/Emails` directory (supports CSV or ZIP files)
2. Run the training script:
   ```
   python src/train_model.py
   ```
3. The trained model will be saved to the `models` directory

### Dataset Format

The training script expects a CSV file with at least these columns:
- `Email Text`: The content of the email
- `Email Type`: Classification label ('Phishing Email' or 'Safe Email')

## Running the Web Interface

1. Start the web server:
   ```
   python src/web_interface.py
   ```
2. Open your browser and go to `http://localhost:5000`
3. Upload an email file (`.eml` or `.txt`) and analyze

## Project Structure

- `src/`: Source code for the phishing detection system
  - `web_interface.py`: Flask web application
  - `enhanced_email_analyzer.py`: Core analysis functionality
  - `test_lottery_scam.py`: Helper functions for email processing
  - `train_model.py`: Script for training on CSV dataset
- `models/`: Trained model files
- `templates/`: HTML templates for web interface
- `static/`: CSS, JavaScript, and other static assets
- `uploads/`: Temporary storage for uploaded email files
- `logs/`: Application logs
- `results/`: Performance metrics and analysis results

## Performance Metrics

After training, the system provides performance metrics including:
- Accuracy, Precision, Recall, and F1 Score
- Confusion matrix (True/False positives/negatives)
- Optimal threshold for classification

## License

[Specify your license here] 