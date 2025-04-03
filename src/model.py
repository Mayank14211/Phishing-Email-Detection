import numpy as np
from typing import Dict, List, Tuple, Union
import tensorflow as tf
from transformers import DistilBertTokenizer, TFDistilBertModel
from sklearn.preprocessing import StandardScaler
import joblib
from preprocessor import EmailPreprocessor
from features import FeatureExtractor

class PhishingDetector:
    def __init__(self, model_path: str = None):
        """Initialize the phishing detector with all necessary components"""
        self.preprocessor = EmailPreprocessor()
        self.feature_extractor = FeatureExtractor()
        
        # Initialize BERT model for text analysis
        self.tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
        self.bert_model = TFDistilBertModel.from_pretrained('distilbert-base-uncased')
        
        # Initialize neural network for combined features
        self.feature_scaler = StandardScaler()
        self.model = self._build_model()
        
        if model_path:
            self.load_model(model_path)
    
    def _build_model(self) -> tf.keras.Model:
        """Build the neural network model architecture"""
        # Text input branch (BERT embeddings)
        text_input = tf.keras.layers.Input(shape=(768,), name='bert_embeddings')
        text_dense = tf.keras.layers.Dense(256, activation='relu')(text_input)
        text_dropout = tf.keras.layers.Dropout(0.3)(text_dense)
        
        # Feature input branch (dynamic size)
        feature_input = tf.keras.layers.Input(shape=(None,), name='extracted_features')
        feature_dense = tf.keras.layers.Dense(128, activation='relu')(feature_input)
        feature_dropout = tf.keras.layers.Dropout(0.3)(feature_dense)
        
        # Combine both branches
        combined = tf.keras.layers.Concatenate()([text_dropout, feature_dropout])
        
        # Additional dense layers
        dense1 = tf.keras.layers.Dense(128, activation='relu')(combined)
        dropout1 = tf.keras.layers.Dropout(0.3)(dense1)
        dense2 = tf.keras.layers.Dense(64, activation='relu')(dropout1)
        dropout2 = tf.keras.layers.Dropout(0.3)(dense2)
        
        # Output layer
        output = tf.keras.layers.Dense(1, activation='sigmoid')(dropout2)
        
        # Create model
        model = tf.keras.Model(
            inputs=[text_input, feature_input],
            outputs=output
        )
        
        # Compile model
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.AUC()]
        )
        
        return model
    
    def _get_bert_embeddings(self, text: str) -> np.ndarray:
        """Get BERT embeddings for text input"""
        # Tokenize text
        inputs = self.tokenizer(
            text,
            return_tensors='tf',
            truncation=True,
            max_length=512,
            padding='max_length'
        )
        
        # Get BERT embeddings
        outputs = self.bert_model(inputs)
        # Use [CLS] token embedding as text representation
        embeddings = outputs.last_hidden_state[:, 0, :].numpy()
        
        return embeddings
    
    def analyze_email(self, email_raw: str) -> Dict[str, Union[float, List[str]]]:
        """Analyze an email and return phishing probability and suspicious features"""
        # Preprocess email
        metadata, linguistic_features, urls, cleaned_text = self.preprocessor.process_email(email_raw)
        
        # Extract features
        features = self.feature_extractor.extract_all_features(
            metadata, linguistic_features, urls, cleaned_text
        )
        
        # Get BERT embeddings
        bert_embeddings = self._get_bert_embeddings(cleaned_text)
        
        # Prepare features for model input
        feature_vector = np.array(list(features.values())).reshape(1, -1)
        scaled_features = self.feature_scaler.transform(feature_vector)
        
        # Make prediction
        prediction = self.model.predict(
            [bert_embeddings, scaled_features]
        )[0][0]
        
        # Collect suspicious features
        suspicious_features = []
        if features['suspicious_keyword_count'] > 2:
            suspicious_features.append('High number of suspicious keywords')
        if features['urgency_score'] > 1:
            suspicious_features.append('High urgency indicators')
        if features['suspicious_tld_count'] > 0:
            suspicious_features.append(f"Suspicious domains: {', '.join(features['suspicious_domains'])}")
        if features['has_money_references']:
            suspicious_features.append('Contains money-related content')
        if features['has_suspicious_formatting']:
            suspicious_features.append('Suspicious text formatting')
        if not features['is_valid_email']:
            suspicious_features.append('Invalid sender email format')
        
        return {
            'probability': float(prediction),
            'suspicious_features': suspicious_features,
            'risk_level': 'High' if prediction > 0.8 else 'Medium' if prediction > 0.5 else 'Low'
        }
    
    def train(self, 
             train_data: List[Tuple[str, int]],
             validation_data: List[Tuple[str, int]] = None,
             epochs: int = 10,
             batch_size: int = 32):
        """Train the model on labeled email data"""
        X_text = []
        X_features = []
        y = []
        
        # Process first email to get feature size
        first_email = train_data[0][0]
        metadata, linguistic_features, urls, cleaned_text = self.preprocessor.process_email(first_email)
        first_features = self.feature_extractor.extract_all_features(
            metadata, linguistic_features, urls, cleaned_text
        )
        feature_size = len(first_features)
        
        # Rebuild model with correct feature size
        self.model = self._build_model()
        
        # Prepare training data
        for email_raw, label in train_data:
            metadata, linguistic_features, urls, cleaned_text = self.preprocessor.process_email(email_raw)
            features = self.feature_extractor.extract_all_features(
                metadata, linguistic_features, urls, cleaned_text
            )
            
            bert_embeddings = self._get_bert_embeddings(cleaned_text)
            feature_vector = np.array(list(features.values()), dtype=np.float32)
            
            X_text.append(bert_embeddings[0])
            X_features.append(feature_vector)
            y.append(label)
        
        # Convert to numpy arrays
        X_text = np.array(X_text)
        X_features = np.array(X_features)
        y = np.array(y)
        
        # Fit feature scaler
        self.feature_scaler.fit(X_features)
        X_features_scaled = self.feature_scaler.transform(X_features)
        
        # Prepare validation data if provided
        validation_data = None
        if validation_data:
            val_X_text = []
            val_X_features = []
            val_y = []
            
            for email_raw, label in validation_data:
                metadata, linguistic_features, urls, cleaned_text = self.preprocessor.process_email(email_raw)
                features = self.feature_extractor.extract_all_features(
                    metadata, linguistic_features, urls, cleaned_text
                )
                
                bert_embeddings = self._get_bert_embeddings(cleaned_text)
                feature_vector = np.array(list(features.values()))
                
                val_X_text.append(bert_embeddings[0])
                val_X_features.append(feature_vector)
                val_y.append(label)
            
            val_X_text = np.array(val_X_text)
            val_X_features = np.array(val_X_features)
            val_y = np.array(val_y)
            
            val_X_features_scaled = self.feature_scaler.transform(val_X_features)
            validation_data = ([val_X_text, val_X_features_scaled], val_y)
        
        # Train model
        self.model.fit(
            [X_text, X_features_scaled],
            y,
            epochs=epochs,
            batch_size=batch_size,
            validation_data=validation_data,
            callbacks=[
                tf.keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=3,
                    restore_best_weights=True
                )
            ]
        )
    
    def save_model(self, model_path: str):
        """Save the model and associated components"""
        # Save neural network
        self.model.save(f"{model_path}_nn")
        
        # Save feature scaler
        joblib.dump(self.feature_scaler, f"{model_path}_scaler.pkl")
    
    def load_model(self, model_path: str):
        """Load the model and associated components"""
        # Load neural network
        self.model = tf.keras.models.load_model(f"{model_path}_nn")
        
        # Load feature scaler
        self.feature_scaler = joblib.load(f"{model_path}_scaler.pkl") 