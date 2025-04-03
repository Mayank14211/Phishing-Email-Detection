import os
import csv
import json
from datetime import datetime
import webbrowser

def read_results_file(results_file):
    """Read the CSV results file"""
    results = []
    try:
        with open(results_file, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Convert string values to appropriate types
                row['probability'] = float(row['probability'])
                row['true_label'] = int(row['true_label'])
                row['predicted_class'] = int(row['predicted_class'])
                row['correct'] = row['correct'].lower() == 'true'
                results.append(row)
        return results
    except Exception as e:
        print(f"Error reading results file: {str(e)}")
        return []

def read_metrics_file(metrics_file):
    """Read the metrics file"""
    metrics = {}
    try:
        with open(metrics_file, 'r') as f:
            lines = f.readlines()
            for line in lines[1:]:  # Skip the header
                if ':' in line:
                    key, value = line.strip().split(':', 1)
                    # Clean up the value and convert percentages
                    value = value.strip()
                    if '%' in value:
                        value = float(value.strip('%')) / 100
                    elif value.isdigit():
                        value = int(value)
                    metrics[key] = value
        return metrics
    except Exception as e:
        print(f"Error reading metrics file: {str(e)}")
        return {}

def create_html_dashboard(results, metrics, output_file, model_data=None):
    """Create an HTML dashboard"""
    
    # Count emails by category
    phishing_count = sum(1 for r in results if r['true_label'] == 1)
    legitimate_count = sum(1 for r in results if r['true_label'] == 0)
    
    # Get threshold if available
    threshold = model_data.get('optimal_threshold', 0.5) if model_data else 0.5
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Phishing Email Analysis Dashboard</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            h1, h2, h3 {{
                color: #2c3e50;
            }}
            .dashboard-header {{
                background: linear-gradient(to right, #3498db, #2c3e50);
                color: white;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
                text-align: center;
            }}
            .stats-container {{
                display: flex;
                flex-wrap: wrap;
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                flex: 1;
                min-width: 200px;
                background-color: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                text-align: center;
            }}
            .stat-card h2 {{
                margin-top: 0;
                font-size: 36px;
                margin-bottom: 10px;
            }}
            .accuracy {{
                color: #27ae60;
            }}
            .warning {{
                color: #e74c3c;
            }}
            .neutral {{
                color: #3498db;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
                background-color: white;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                border-radius: 10px;
                overflow: hidden;
            }}
            th, td {{
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background-color: #3498db;
                color: white;
            }}
            tr:nth-child(even) {{
                background-color: #f2f2f2;
            }}
            tr:hover {{
                background-color: #e6f7ff;
            }}
            .phishing {{
                background-color: #ffecec;
            }}
            .legitimate {{
                background-color: #f0fff0;
            }}
            .correct {{
                color: #27ae60;
                font-weight: bold;
            }}
            .incorrect {{
                color: #e74c3c;
                font-weight: bold;
            }}
            .risk-high {{
                color: white;
                background-color: #e74c3c;
                padding: 3px 8px;
                border-radius: 4px;
                font-weight: bold;
            }}
            .risk-medium {{
                color: white;
                background-color: #f39c12;
                padding: 3px 8px;
                border-radius: 4px;
                font-weight: bold;
            }}
            .risk-low {{
                color: white;
                background-color: #3498db;
                padding: 3px 8px;
                border-radius: 4px;
                font-weight: bold;
            }}
            .footer {{
                margin-top: 40px;
                text-align: center;
                color: #7f8c8d;
                font-size: 14px;
            }}
            .progress-container {{
                background-color: #e0e0e0;
                border-radius: 10px;
                height: 20px;
                width: 100%;
                margin-top: 10px;
            }}
            .progress-bar {{
                height: 20px;
                border-radius: 10px;
                background-color: #3498db;
            }}
            .feature-list {{
                margin-top: 5px;
                padding-left: 20px;
            }}
            .threshold-container {{
                margin-top: 10px;
                margin-bottom: 20px;
                text-align: center;
            }}
            .threshold-marker {{
                position: relative;
                width: 80%;
                height: 30px;
                background: linear-gradient(to right, #2ecc71, #f1c40f, #e74c3c);
                margin: 0 auto;
                border-radius: 15px;
            }}
            .threshold-pointer {{
                position: absolute;
                top: -10px;
                width: 2px;
                height: 50px;
                background-color: black;
                left: {threshold * 100}%;
            }}
            .threshold-label {{
                position: absolute;
                top: -30px;
                transform: translateX(-50%);
                left: {threshold * 100}%;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <div class="dashboard-header">
            <h1>Phishing Email Detection Results</h1>
            <p>Analysis performed on {datetime.now().strftime('%B %d, %Y at %H:%M')}</p>
        </div>

        <div class="threshold-container">
            <h3>Detection Threshold: {threshold:.2f}</h3>
            <p>Emails with scores above this threshold are classified as phishing</p>
            <br>
            <div class="threshold-marker">
                <div class="threshold-pointer">
                    <span class="threshold-label">{threshold:.2f}</span>
                </div>
            </div>
        </div>
        
        <div class="stats-container">
            <div class="stat-card">
                <h3>Accuracy</h3>
                <h2 class="accuracy">{metrics.get('Accuracy', 0) * 100:.1f}%</h2>
                <p>Correct predictions</p>
            </div>
            <div class="stat-card">
                <h3>Analyzed Emails</h3>
                <h2 class="neutral">{len(results)}</h2>
                <p>{phishing_count} phishing, {legitimate_count} legitimate</p>
            </div>
            <div class="stat-card">
                <h3>Precision</h3>
                <h2 class="accuracy">{metrics.get('Precision', 0) * 100:.1f}%</h2>
                <p>True positives accuracy</p>
            </div>
            <div class="stat-card">
                <h3>Recall</h3>
                <h2 class="accuracy">{metrics.get('Recall', 0) * 100:.1f}%</h2>
                <p>Detection rate</p>
            </div>
        </div>

        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Risk Level</th>
                    <th>Phishing Score</th>
                    <th>Classification</th>
                    <th>Suspicious Features</th>
                    <th>Result</th>
                </tr>
            </thead>
            <tbody>
    """
    
    # Add rows for each result
    for result in results:
        filename = result['filename']
        risk_level = result['risk_level']
        probability = result['probability']
        true_label = "PHISHING" if result['true_label'] == 1 else "LEGITIMATE"
        predicted = "PHISHING" if result['predicted_class'] == 1 else "LEGITIMATE"
        features = result['suspicious_features']
        correct = result['correct']
        
        # Determine CSS classes
        row_class = "phishing" if result['true_label'] == 1 else "legitimate"
        result_class = "correct" if correct else "incorrect"
        risk_class = f"risk-{risk_level.lower()}"
        
        # Format features as list if available
        features_html = ""
        if features:
            features_html = "<ul class='feature-list'>"
            for feature in features.split(', '):
                if feature:
                    features_html += f"<li>{feature}</li>"
            features_html += "</ul>"
        
        # Build progress bar for probability
        progress_width = probability * 100
        progress_bar = f"""
        <div class="progress-container">
            <div class="progress-bar" style="width: {progress_width}%"></div>
        </div>
        """
        
        # Add table row
        html += f"""
            <tr class="{row_class}">
                <td>{filename}</td>
                <td><span class="{risk_class}">{risk_level}</span></td>
                <td>{probability:.1%} {progress_bar}</td>
                <td>Expected: {true_label}<br>Predicted: {predicted}</td>
                <td>{features_html}</td>
                <td class="{result_class}">{predicted if correct else f"Wrong! Should be {true_label}"}</td>
            </tr>
        """
    
    # Complete the HTML
    html += """
            </tbody>
        </table>
        
        <div class="footer">
            <p>Email Phishing Detection System - Results Dashboard</p>
        </div>
    </body>
    </html>
    """
    
    # Write to file
    with open(output_file, 'w') as f:
        f.write(html)
    
    return output_file

def find_latest_files():
    """Find the latest results and metrics files"""
    results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
    results_files = [f for f in os.listdir(results_dir) if f.startswith('results_') and f.endswith('.csv')]
    metrics_files = [f for f in os.listdir(results_dir) if f.startswith('metrics_') and f.endswith('.txt')]
    
    # Sort by timestamp in filename
    results_files.sort(reverse=True)
    metrics_files.sort(reverse=True)
    
    if not results_files or not metrics_files:
        return None, None
    
    return os.path.join(results_dir, results_files[0]), os.path.join(results_dir, metrics_files[0])

def main():
    """Main function for visualization"""
    print("Generating phishing detection results dashboard...")
    
    # Find the latest results files
    results_file, metrics_file = find_latest_files()
    
    if not results_file or not metrics_file:
        print("Error: Results files not found")
        return
    
    print(f"Using results: {os.path.basename(results_file)}")
    print(f"Using metrics: {os.path.basename(metrics_file)}")
    
    # Read the data
    results = read_results_file(results_file)
    metrics = read_metrics_file(metrics_file)
    
    # Check if we have model data
    model_data = None
    model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                             "models", "email_classifier.json")
    if os.path.exists(model_path):
        try:
            with open(model_path, 'r') as f:
                model_data = json.load(f)
        except:
            pass
    
    # Create output path
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    output_file = os.path.join(output_dir, f"phishing_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    
    # Create dashboard
    dashboard_path = create_html_dashboard(results, metrics, output_file, model_data)
    
    print(f"Dashboard created at: {dashboard_path}")
    
    # Open in web browser
    webbrowser.open(f"file://{os.path.abspath(dashboard_path)}")

if __name__ == "__main__":
    main() 