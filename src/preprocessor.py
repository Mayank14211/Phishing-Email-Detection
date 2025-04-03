import re
import nltk
import spacy
from bs4 import BeautifulSoup
from email.parser import Parser
from email import policy
from typing import Dict, List, Tuple
import numpy as np

class EmailPreprocessor:
    def __init__(self):
        """Initialize the email preprocessor with necessary NLP models"""
        self.nlp = spacy.load('en_core_web_sm')
        self.email_parser = Parser(policy=policy.default)
        
    def extract_metadata(self, email_raw: str) -> Dict:
        """Extract metadata from email headers"""
        email = self.email_parser.parsestr(email_raw)
        return {
            'sender': email.get('from', ''),
            'subject': email.get('subject', ''),
            'date': email.get('date', ''),
            'reply_to': email.get('reply-to', ''),
            'received': email.get_all('received', []),
            'content_type': email.get_content_type(),
            'has_attachments': bool(email.get_payload()),
        }
    
    def extract_urls(self, content: str) -> List[str]:
        """Extract URLs from email content"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, content)
    
    def clean_text(self, text: str) -> str:
        """Clean and normalize text content"""
        # Remove HTML tags
        soup = BeautifulSoup(text, 'html.parser')
        text = soup.get_text()
        
        # Basic text cleaning
        text = text.lower()
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'[^\w\s]', '', text)
        
        return text.strip()
    
    def extract_linguistic_features(self, text: str) -> Dict:
        """Extract linguistic features from text"""
        doc = self.nlp(text)
        
        # Count POS tags
        pos_counts = {}
        for token in doc:
            pos_counts[token.pos_] = pos_counts.get(token.pos_, 0) + 1
            
        # Count named entities
        ent_counts = {}
        for ent in doc.ents:
            ent_counts[ent.label_] = ent_counts.get(ent.label_, 0) + 1
        
        return {
            'num_sentences': len(list(doc.sents)),
            'num_tokens': len(doc),
            'avg_token_length': np.mean([len(token.text) for token in doc]),
            'num_entities': len(doc.ents),
            'pos_tags': pos_counts,
            'named_entities': ent_counts,
        }
    
    def process_email(self, email_raw: str) -> Tuple[Dict, Dict, List[str], str]:
        """Process entire email and extract all relevant features"""
        metadata = self.extract_metadata(email_raw)
        
        # Get email body
        email = self.email_parser.parsestr(email_raw)
        body = ''
        if email.is_multipart():
            for part in email.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_payload()
        else:
            body = email.get_payload()
        
        cleaned_text = self.clean_text(body)
        urls = self.extract_urls(body)
        linguistic_features = self.extract_linguistic_features(cleaned_text)
        
        return metadata, linguistic_features, urls, cleaned_text 