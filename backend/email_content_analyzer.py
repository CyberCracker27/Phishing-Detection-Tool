import re
import spacy
import numpy as np
from textstat import flesch_reading_ease
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import pickle
from urllib.parse import urlparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class EmailContentAnalyzer:
    def __init__(self, model_path="phishing_model.pkl", phishing_threshold=0.7):
        # Load NLP model
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except Exception as e:
            logging.error(f"Failed to load SpaCy model: {e}")
            raise
        
        # Predefined lists of phishing indicators
        self.urgency_phrases = ["immediately", "urgent", "action required", "within 24 hours", 
                               "account suspension", "verify now", "click below", "limited time"]
        self.threat_phrases = ["account closure", "legal action", "security alert", "unauthorized access",
                              "password expired", "update now", "failure to comply"]
        self.generic_greetings = ["dear customer", "dear user", "dear account holder", "dear member"]
        
        # Phishing classification threshold
        self.phishing_threshold = phishing_threshold
        
        # Initialize model and vectorizer
        self.model = None
        self.vectorizer = None
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path):
        """Load pre-trained model and vectorizer"""
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
            self.model = model_data['model']
            self.vectorizer = model_data['vectorizer']
            logging.info(f"Model loaded successfully from {model_path}")
        except Exception as e:
            logging.error(f"Error loading model: {e}")
            raise
    
    def train_model(self, texts, labels):
        """Train a RandomForestClassifier with TF-IDF features"""
        try:
            self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
            X = self.vectorizer.fit_transform(texts)
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.model.fit(X, labels)
            logging.info("Model trained successfully")
            return {'model': self.model, 'vectorizer': self.vectorizer}
        except Exception as e:
            logging.error(f"Error training model: {e}")
            raise
    
    def extract_features(self, email_body):
        """Extract NLP-based features from email content"""
        email_body = email_body.lower()
        features = {}
        
        # 1. Basic Text Features
        features['length'] = len(email_body)
        features['word_count'] = len(email_body.split())
        
        # 2. Readability Score
        features['readability'] = flesch_reading_ease(email_body)
        
        # 3. Urgency and Threat Detection
        features['urgency_score'] = sum(email_body.count(phrase) for phrase in self.urgency_phrases)
        features['threat_score'] = sum(email_body.count(phrase) for phrase in self.threat_phrases)
        
        # 4. Greeting Analysis
        features['generic_greeting'] = any(greet in email_body[:100] for greet in self.generic_greetings)
        
        # 5. Link Analysis
        links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_body)
        features['link_count'] = len(links)
        features['suspicious_domain'] = False
        if links:
            domains = [urlparse(link).netloc for link in links]
            features['suspicious_domain'] = any(self.is_suspicious_domain(domain) for domain in domains)
        
        # 6. Personalization Check
        doc = self.nlp(email_body)
        features['personal_pronouns'] = sum(1 for token in doc if token.tag_ == 'PRP' and token.text.lower() in ['i', 'you', 'we'])
        
        # 7. Spelling Errors (approximate)
        features['typo_density'] = self.estimate_typo_density(email_body)
        
        # 8. Sentence Structure Analysis
        sentences = [sent.text for sent in doc.sents]
        features['avg_sentence_length'] = np.mean([len(sent.split()) for sent in sentences]) if sentences else 0
        features['question_marks'] = email_body.count('?')
        
        return features
    
    def analyze_headers(self, headers):
        """Analyze email headers for suspicious patterns"""
        suspicious_headers = []
        spf_result = "fail"
        dkim_result = "fail"
        dmarc_result = "fail"

        # Analyze SPF, DKIM, and DMARC
        auth_results = headers.get("Authentication-Results", "")
        if "spf=pass" in auth_results.lower():
            spf_result = "pass"
        if "dkim=pass" in auth_results.lower():
            dkim_result = "pass"
        if "dmarc=pass" in auth_results.lower():
            dmarc_result = "pass"

        # Check for suspicious headers
        if "X-PHP-Originating-Script" in headers:
            suspicious_headers.append("X-PHP-Originating-Script (possible forged email)")
        if "X-Mailer" in headers and "PHP" in headers["X-Mailer"]:
            suspicious_headers.append("X-Mailer: PHP (common in spam emails)")

        return {
            "spf_result": spf_result,
            "dkim_result": dkim_result,
            "dmarc_result": dmarc_result,
            "suspicious_headers": suspicious_headers
        }
    
    def is_suspicious_domain(self, domain):
        """Check for suspicious domain characteristics"""
        domain = domain.lower()
        if domain.count('.') > 1:
            main_domain = '.'.join(domain.split('.')[-2:])
            if main_domain in ['gmail.com', 'yahoo.com', 'paypal.com', 'bankofamerica.com']:
                return True
        
        common_domains = ['paypal', 'apple', 'microsoft', 'bankofamerica', 'wellsfargo']
        for common in common_domains:
            if common in domain and domain != common + '.com':
                if len(domain) - len(common) < 4:
                    return True
        return False
    
    def estimate_typo_density(self, text):
        """Simple heuristic for typo detection"""
        common_words = set(['the', 'and', 'have', 'that', 'for', 'you', 'with', 'this', 'your'])
        words = text.lower().split()
        if len(words) < 10:
            return 0
        
        typos = 0
        for word in words[:50]:
            if word in common_words:
                continue
            if len(word) > 3 and not any(word in common for common in common_words):
                typos += 1
        return typos / min(50, len(words))
    
    def predict(self, email_body, headers=None):
        """Make phishing prediction using rules, ML, and header analysis"""
        if not self.model or not self.vectorizer:
            logging.error("Model or vectorizer not loaded")
            raise ValueError("Model or vectorizer not loaded")
        
        # Extract features
        features = self.extract_features(email_body)
        
        # Rule-based checks
        rule_based_score = 0
        if features['urgency_score'] > 2:
            rule_based_score += 0.3
        if features['threat_score'] > 1:
            rule_based_score += 0.2
        if features['generic_greeting']:
            rule_based_score += 0.1
        if features['suspicious_domain']:
            rule_based_score += 0.4
        
        # ML-based prediction
        try:
            X = self.vectorizer.transform([email_body])
            proba = self.model.predict_proba(X)
            ml_score = proba[0][1]  # Probability of being phishing
            logging.debug(f"Predict Proba Output: {proba}")
        except Exception as e:
            logging.error(f"Error in ML prediction: {e}")
            ml_score = 0.0
        
        # Header analysis
        header_analysis = self.analyze_headers(headers or {})
        
        # Adjust score based on header analysis
        if header_analysis['spf_result'] == 'fail' or header_analysis['dkim_result'] == 'fail':
            rule_based_score += 0.2
        if header_analysis['suspicious_headers']:
            rule_based_score += 0.3
        
        # Combine scores
        final_score = 0.7 * ml_score + 0.3 * min(rule_based_score, 1.0)  # Cap rule-based score
        
        return {
            'phishing_probability': final_score,
            'is_phishing': final_score > self.phishing_threshold,
            'features': features,
            'rule_based_score': rule_based_score,
            'ml_score': ml_score,
            'header_analysis': header_analysis
        }

if __name__ == "__main__":
    analyzer = EmailContentAnalyzer(phishing_threshold=0.7)
    test_email = """
    Dear Customer,
    
    We have detected unusual activity on your account. To prevent immediate suspension, 
    you must verify your identity within 24 hours by clicking here: http://security-paypal.com/login.
    
    Failure to comply will result in permanent account closure.
    
    Sincerely,
    PayPal Security Team
    """
    headers = {
        "Authentication-Results": "spf=fail; dkim=pass; dmarc=fail",
        "X-Mailer": "PHP/7.4"
    }
    result = analyzer.predict(test_email, headers)
    logging.info(f"Phishing Probability: {result['phishing_probability']:.2%}")
    logging.info(f"IsPhishing: {result['is_phishing']}")
    logging.info("\nFeature Breakdown:")
    for k, v in result['features'].items():
        logging.info(f"{k}: {v}")
    logging.info(f"Header Analysis: {result['header_analysis']}")