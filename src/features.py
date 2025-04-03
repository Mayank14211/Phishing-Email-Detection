import re
from typing import Dict, List, Union
from urllib.parse import urlparse
import numpy as np
from datetime import datetime
from email_validator import validate_email, EmailNotValidError

class FeatureExtractor:
    def __init__(self):
        """Initialize feature extractor with necessary configurations"""
        self.suspicious_tlds = {'xyz', 'top', 'work', 'live', 'stream', 'bid'}
        self.suspicious_keywords = {
            'urgent', 'account', 'suspended', 'verify', 'login', 'unusual',
            'security', 'important', 'password', 'access', 'confirm'
        }
    
    def analyze_urls(self, urls: List[str]) -> Dict[str, Union[int, float]]:
        """Analyze URLs for suspicious patterns"""
        features = {
            'num_urls': len(urls),
            'num_unique_domains': len({urlparse(url).netloc for url in urls}),
            'suspicious_tld_count': 0,
            'ip_based_urls': 0,
            'url_length_mean': 0,
            'num_suspicious_domains': 0
        }
        
        if urls:
            features['url_length_mean'] = np.mean([len(url) for url in urls])
            
            for url in urls:
                parsed = urlparse(url)
                domain = parsed.netloc
                
                # Check for IP-based URLs
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    features['ip_based_urls'] += 1
                
                # Check for suspicious TLDs
                tld = domain.split('.')[-1].lower()
                if tld in self.suspicious_tlds:
                    features['suspicious_tld_count'] += 1
                    features['num_suspicious_domains'] += 1
        
        return features
    
    def analyze_sender(self, sender: str) -> Dict[str, Union[bool, float]]:
        """Analyze sender information for suspicious patterns"""
        features = {
            'is_valid_email': False,
            'domain_age_score': 0.0,
            'sender_name_present': False,
            'multiple_at_signs': False
        }
        
        try:
            valid = validate_email(sender)
            features['is_valid_email'] = True
            features['sender_name_present'] = '<' in sender and '>' in sender
            features['multiple_at_signs'] = sender.count('@') > 1
        except EmailNotValidError:
            pass
        
        return features
    
    def analyze_content(self, text: str, linguistic_features: Dict) -> Dict[str, Union[int, float, bool]]:
        """Analyze email content for suspicious patterns"""
        features = {
            'urgency_score': 0,
            'suspicious_keyword_count': 0,
            'has_money_references': False,
            'has_suspicious_formatting': False,
            'sentiment_score': 0
        }
        
        # Count suspicious keywords
        text_lower = text.lower()
        features['suspicious_keyword_count'] = sum(
            1 for keyword in self.suspicious_keywords if keyword in text_lower
        )
        
        # Check for urgency indicators
        urgency_patterns = [
            r'urgent',
            r'immediate(ly)?',
            r'within \d+ (hour|day)',
            r'as soon as possible',
            r'quick(ly)?'
        ]
        features['urgency_score'] = sum(
            1 for pattern in urgency_patterns if re.search(pattern, text_lower)
        )
        
        # Check for money references
        money_patterns = [
            r'\$\d+',
            r'dollar',
            r'payment',
            r'bank',
            r'account'
        ]
        features['has_money_references'] = any(
            re.search(pattern, text_lower) for pattern in money_patterns
        )
        
        # Check for suspicious formatting
        suspicious_formatting = [
            r'\b[A-Z]{5,}\b',  # All caps words
            r'!{2,}',          # Multiple exclamation marks
            r'\?{2,}'          # Multiple question marks
        ]
        features['has_suspicious_formatting'] = any(
            re.search(pattern, text) for pattern in suspicious_formatting
        )
        
        return features
    
    def extract_all_features(self, 
                           metadata: Dict,
                           linguistic_features: Dict,
                           urls: List[str],
                           cleaned_text: str) -> Dict:
        """Extract all features from email data"""
        url_features = self.analyze_urls(urls)
        sender_features = self.analyze_sender(metadata.get('sender', ''))
        content_features = self.analyze_content(cleaned_text, linguistic_features)
        
        # Extract numeric features from linguistic_features
        numeric_linguistic_features = {
            'num_sentences': linguistic_features.get('num_sentences', 0),
            'num_tokens': linguistic_features.get('num_tokens', 0),
            'avg_token_length': linguistic_features.get('avg_token_length', 0),
            'num_entities': linguistic_features.get('num_entities', 0)
        }
        
        # Add POS tag counts as features
        pos_tags = linguistic_features.get('pos_tags', {})
        for pos_tag, count in pos_tags.items():
            numeric_linguistic_features[f'pos_{pos_tag.lower()}'] = count
            
        # Add named entity counts as features
        named_entities = linguistic_features.get('named_entities', {})
        for ent_type, count in named_entities.items():
            if ent_type:  # Skip empty string key
                numeric_linguistic_features[f'ent_{ent_type.lower()}'] = count
        
        # Combine all features
        features = {
            **url_features,
            **sender_features,
            **content_features,
            'subject_length': len(metadata.get('subject', '')),
            'has_attachments': int(metadata.get('has_attachments', False)),
            'is_html': int(metadata.get('content_type', '').lower() == 'text/html'),
            **numeric_linguistic_features
        }
        
        return features 