import os
import sys
import logging
import re
from bs4 import BeautifulSoup

# Set up logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s',
                   handlers=[
                       logging.StreamHandler(sys.stdout)
                   ])

def load_email_file(email_path):
    """Load email content from file"""
    with open(email_path, 'r', encoding='utf-8') as f:
        return f.read()

def simple_phishing_analysis(email_content):
    """Perform a simple analysis of potential phishing indicators"""
    suspicious_features = []
    risk_score = 0
    
    # Check for suspicious keywords
    urgent_words = ['urgent', 'immediate', 'act now', 'fast', 'limited time', 'deadline', 'quickly', 'hurry',
                   'limited offer', 'expires', 'today only', 'final notice']
    money_words = ['dollar', '$', 'money', 'cash', 'payment', 'prize', 'winning', 'lottery', 'won', 'fortune',
                  'profit', 'earnings', 'discount', 'investment', 'offer', 'free']
    sensitive_words = ['password', 'account', 'login', 'verify', 'confirm', 'update', 'validate', 'security', 'bank',
                      'suspended', 'locked', 'unauthorized', 'access', 'credentials', 'identity', 'verification']
    threat_words = ['suspended', 'terminated', 'legal', 'police', 'court', 'arrest', 'violation', 'crime', 'fine',
                   'penalty', 'warning', 'failure', 'compromised', 'hacked', 'fraud', 'investigation']
    
    # Lowercase for easier matching
    email_lower = email_content.lower()
    
    # Count urgent keywords
    urgent_count = sum(1 for word in urgent_words if word in email_lower)
    if urgent_count > 0:
        suspicious_features.append(f"Contains {urgent_count} urgency indicators")
        risk_score += urgent_count * 2
    
    # Count money references
    money_count = sum(1 for word in money_words if word in email_lower)
    if money_count > 0:
        suspicious_features.append(f"Contains {money_count} money-related terms")
        risk_score += money_count * 2
    
    # Count sensitive information requests
    sensitive_count = sum(1 for word in sensitive_words if word in email_lower)
    if sensitive_count > 0:
        suspicious_features.append(f"Requests sensitive information ({sensitive_count} instances)")
        risk_score += sensitive_count * 3
    
    # Count threat-based language
    threat_count = sum(1 for word in threat_words if word in email_lower)
    if threat_count > 0:
        suspicious_features.append(f"Contains {threat_count} threatening terms")
        risk_score += threat_count * 3

    # Check for URLs in the email
    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', email_content)
    urls.extend(re.findall(r'href=[\'"](https?://[^\'"]+)[\'"]', email_content))
    
    suspicious_domains = []
    legit_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com', 'facebook.com', 'instagram.com']
    
    for url in urls:
        # Check for suspicious TLDs
        if any(tld in url.lower() for tld in ['.tk', '.xyz', '.info', '.online', '.site', '.club', '.top']):
            suspicious_domains.append(url)
        # Check for domain/URL mismatch (e.g., google.com.phishing.com)
        elif re.search(r'(paypal|google|microsoft|apple|amazon|facebook|bank|login).*\.[a-zA-Z]{2,}', url.lower()):
            suspicious_domains.append(url)
        # Check for URL shorteners
        elif any(shortener in url.lower() for shortener in ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'tiny.cc']):
            suspicious_domains.append(url)
        # Check for numeric IP in URL instead of domain name
        elif re.search(r'https?://\d+\.\d+\.\d+\.\d+', url.lower()):
            suspicious_domains.append(url)
        # Check for typosquatting of legitimate domains
        elif any(levenshtein_distance(extract_domain(url), domain) <= 2 and levenshtein_distance(extract_domain(url), domain) > 0 for domain in legit_domains):
            suspicious_domains.append(url)
    
    if suspicious_domains:
        suspicious_features.append(f"Contains {len(suspicious_domains)} suspicious URLs")
        risk_score += len(suspicious_domains) * 5
    
    # Check for HTML forms (often used to collect credentials)
    if re.search(r'<form\s+.*?>.*?</form>', email_content, re.DOTALL | re.IGNORECASE):
        suspicious_features.append("Contains HTML form that may collect data")
        risk_score += 5
    
    # Check if the email contains both urgency and action requests
    if urgent_count > 0 and (sensitive_count > 0 or len(suspicious_domains) > 0):
        suspicious_features.append("Combines urgency with action requests (high-risk pattern)")
        risk_score += 8
    
    # Check for threat combined with urgency (common in scam emails)
    if threat_count > 0 and urgent_count > 0:
        suspicious_features.append("Combines threats with urgency (high-risk pattern)")
        risk_score += 10
        
    # Calculate final risk level
    if risk_score > 20:
        risk_level = "HIGH"
        probability = 0.95
    elif risk_score > 12:
        risk_level = "MEDIUM"
        probability = 0.7
    elif risk_score > 5:
        risk_level = "LOW"
        probability = 0.4
    else:
        risk_level = "MINIMAL"
        probability = 0.1
    
    return {
        'probability': probability,
        'risk_level': risk_level,
        'risk_score': risk_score,
        'suspicious_features': suspicious_features
    }

def extract_domain(url):
    """Extract the domain name from a URL"""
    match = re.search(r'https?://(?:www\.)?([^/]+)', url.lower())
    if match:
        return match.group(1)
    return url

def levenshtein_distance(s1, s2):
    """Calculate the Levenshtein distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def main():
    """Analyze the phishing_lottery_scam.eml file"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        email_path = os.path.join(current_dir, "phishing_lottery_scam.eml")
        
        # Check if the email file exists
        if not os.path.exists(email_path):
            logging.error(f"Email file not found at {email_path}")
            return
        
        logging.info("Loading email content...")
        email_content = load_email_file(email_path)
        
        # Analyze the email
        logging.info("Analyzing lottery scam email...")
        result = simple_phishing_analysis(email_content)
        
        # Print results
        print("\nAnalysis Results:")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Phishing Probability: {result['probability']:.2%}")
        
        if result['suspicious_features']:
            print("\nSuspicious Features Detected:")
            for feature in result['suspicious_features']:
                print(f"- {feature}")
        
        # Print a clear conclusion
        prediction = "PHISHING" if result["probability"] > 0.5 else "LEGITIMATE"
        print(f"\nCONCLUSION: This email is classified as {prediction} with {result['probability']:.2%} confidence")
        
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        logging.error("Stack trace:", exc_info=True)

if __name__ == "__main__":
    main() 