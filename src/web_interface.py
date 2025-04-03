import os
import sys
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
import json

# Add the src directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


# Import our email analysis functionality
from enhanced_email_analyzer import EmailClassifier, load_email_file

# Set up logging
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, f"web_interface_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)

# Initialize Flask app
app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates"),
            static_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static"))
app.secret_key = 'phishing_detection_secret_key'

# Configure file upload settings
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
ALLOWED_EXTENSIONS = {'eml', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize the classifier
classifier = EmailClassifier()
model_loaded = False

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_model():
    """Load the trained model"""
    global classifier, model_loaded
    
    try:
        model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
        
        # Try to load augmented model first
        augmented_model_path = os.path.join(model_dir, "email_classifier_augmented.json")
        original_model_path = os.path.join(model_dir, "email_classifier.json")
        
        if os.path.exists(augmented_model_path):
            logging.info("Found augmented model, loading it instead of original model")
            # Load augmented model directly
            with open(augmented_model_path, 'r') as f:
                model_data = json.load(f)
            
            classifier.optimal_threshold = model_data.get('optimal_threshold', 0.5)
            classifier.feature_weights = model_data.get('feature_weights', classifier.feature_weights)
            classifier.trained = True
            model_loaded = True
            
            logging.info(f"Augmented model loaded from {augmented_model_path}")
            logging.info(f"Using threshold: {classifier.optimal_threshold}")
            logging.info("Model loaded successfully")
            return True
        elif os.path.exists(original_model_path):
            success = classifier.load_model()
            model_loaded = success

            if success:
                logging.info("Model loaded successfully")
            else:
                logging.warning("Failed to load model, using default parameters")
            return success
        else:
            logging.warning("Model file not found, analyzer will use default parameters")
            return False
    except Exception as e:
        logging.error(f"Error loading model: {str(e)}")
        logging.exception("Details:")
        return False

@app.route('/')
def index():
    """Main page for email phishing detection"""
    return render_template('index.html', model_loaded=model_loaded)

@app.route('/analyze', methods=['POST'])
def analyze_email():
    """Handle email upload and analysis"""
    global classifier
    
    if 'email_file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['email_file']
    
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            # Get user-selected classification
            user_classification = request.form.get('classification', 'unknown')
            true_label = 1 if user_classification.lower() == 'phishing' else 0
            
            # Load and analyze the email
            email_content = load_email_file(file_path)
            
            # Run the analysis
            prediction = classifier.predict(email_content)

            
            # Store analysis results
            results = {
                'filename': filename,
                'true_label': true_label,
                'predicted_class': prediction['predicted_class'],
                'probability': prediction['probability'],
                'risk_level': prediction['risk_level'],
                'suspicious_features': prediction['suspicious_features'],
                'threshold_used': prediction['threshold_used'],
                'correct': prediction['predicted_class'] == true_label
            }
            
            return render_template('results.html', 
                                  results=results, 
                                  user_classification=user_classification)
            
        except Exception as e:
            logging.error(f"Error analyzing email: {str(e)}")
            flash(f"Error analyzing email: {str(e)}")
            return redirect(url_for('index'))
    else:
        flash('File type not allowed. Please upload .eml or .txt files only.')
        return redirect(url_for('index'))

@app.route('/analyze-directory', methods=['POST'])
def analyze_directory():
    """Analyze all files in the uploaded directory"""
    if 'email_directory' not in request.files:
        flash('No directory selected')
        return redirect(url_for('index'))
    
    files = request.files.getlist('email_directory')
    
    if not files or len(files) == 0:
        flash('No files found in directory')
        return redirect(url_for('index'))
    
    analysis_results = []
    
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            try:
                # Determine expected class from filename
                expected_class = 1 if 'phishing' in filename.lower() else 0
                
                # Load and analyze the email
                email_content = load_email_file(file_path)
                prediction = classifier.predict(email_content)
                
                # Store analysis results
                results = {
                    'filename': filename,
                    'true_label': expected_class,
                    'predicted_class': prediction['predicted_class'],
                    'probability': prediction['probability'],
                    'risk_level': prediction['risk_level'],
                    'suspicious_features': prediction['suspicious_features'],
                    'threshold_used': prediction['threshold_used'],
                    'correct': prediction['predicted_class'] == expected_class
                }
                
                analysis_results.append(results)
                
            except Exception as e:
                logging.error(f"Error analyzing email {filename}: {str(e)}")
    
    # Calculate overall accuracy
    if analysis_results:
        accuracy = sum(1 for r in analysis_results if r['correct']) / len(analysis_results)
    else:
        accuracy = 0
    
    return render_template('batch_results.html', 
                          results=analysis_results, 
                          accuracy=accuracy)

@app.template_filter('tojson')
def template_to_json(obj):
    """Convert a Python object to a JSON string for template use"""
    return json.dumps(obj)

if __name__ == '__main__':
    # Load the model before starting the app
    load_model()
    
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5000))
    
    print(f"Starting Phishing Detection Web Interface on port {port}...")
    print(f"Open your browser and navigate to http://localhost:{port}")
    print("Press Ctrl+C to stop the server")
    
    app.run(host='0.0.0.0', port=port, debug=True)
    