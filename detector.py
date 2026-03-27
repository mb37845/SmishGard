"""
Smishing Detection Module
ML-based smishing detection with LIME explainability
"""
import numpy as np
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline
from lime.lime_text import LimeTextExplainer
from config import Config


class SmishingDetector:
    """ML-based smishing detector with explainability"""
    
    def __init__(self, model_path=None, min_word_length=None):
        """Initialize smishing detector"""
        self.model_path = model_path or Config.MODEL_PATH
        self.MIN_WORD_LENGTH = min_word_length or Config.MIN_WORD_LENGTH
        self.model_loaded = False
        
        try:
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.classifier = pipeline(
                "text-classification",
                model=self.model,
                tokenizer=self.tokenizer,
                device=-1
            )
            self.lime_explainer = LimeTextExplainer(
                class_names=['ham', 'smishing'],
                split_expression=r'\W+',
                bow=False
            )
            print("Fine-tuned DistilBERT model loaded successfully!")
            self.model_loaded = True
        except Exception as e:
            print(f"Error loading model: {e}")
            self.classifier = None
    
    def categorize_confidence(self, confidence):
        """Categorize confidence level"""
        if confidence >= 0.9:
            return "VERY HIGH"
        elif confidence >= 0.75:
            return "HIGH"
        elif confidence >= 0.6:
            return "MEDIUM"
        else:
            return "LOW"
    
    def predict_proba_for_lime(self, texts):
        """Prediction function for LIME"""
        if not self.model_loaded:
            return np.array([[0.5, 0.5]] * len(texts))
        
        results = []
        for text in texts:
            try:
                output = self.classifier(text)[0]
                label = output['label']
                confidence = output['score']
                
                # Map to probabilities
                if label.lower() in ['smish', 'smishing', '1', 'label_1']:
                    ham_prob = 1 - confidence
                    smishing_prob = confidence
                else:
                    ham_prob = confidence
                    smishing_prob = 1 - confidence
                
                results.append([ham_prob, smishing_prob])
                
            except Exception as e:
                results.append([0.5, 0.5])
        
        return np.array(results)
    
    def get_lime_explanation(self, text, final_prediction, num_features=None):
        """Generate LIME explanation"""
        if not self.model_loaded or self.lime_explainer is None:
            return None
        
        # Check if text is too long for LIME processing
        if len(text) > Config.MAX_MESSAGE_LENGTH:
            print(f"Text too long for LIME ({len(text)} chars). Skipping explanation.")
            return {'explanation_available': False, 'error': 'Text too long for explanation'}
        
        num_features = num_features or Config.LIME_NUM_FEATURES
        
        try:
            print(f"Generating LIME explanation for: {final_prediction.upper()}")
                
            # Generate explanation for both classes
            exp = self.lime_explainer.explain_instance(
                text,
                self.predict_proba_for_lime,
                num_features=num_features,
                num_samples=Config.LIME_NUM_SAMPLES,
                labels=(0, 1)  # Force explanation for both classes
            )
            
            # Map prediction to class index
            predicted_class_index = 1 if final_prediction.lower() == 'smishing' else 0
            
            # Verify class exists
            available_classes = list(exp.local_exp.keys())
            
            if predicted_class_index not in exp.local_exp:
                print(f"Warning: Class {predicted_class_index} not found")
                if len(available_classes) > 0:
                    predicted_class_index = available_classes[0]
                else:
                    raise ValueError("No labels available in LIME explanation")
            
            class_name = 'SMISHING' if predicted_class_index == 1 else 'HAM'
            print(f"Explaining class {predicted_class_index} ({class_name})")
            
            # Extract explanation
            explanation = exp.as_list(label=predicted_class_index)
            
            # Store positive weights only
            predicted_weights = {}
            for feature, weight in explanation:
                cleaned_feature = feature.strip('<>=').lower()
                
                if len(cleaned_feature) < self.MIN_WORD_LENGTH:
                    continue
                
                if weight > 0:
                    predicted_weights[cleaned_feature] = float(weight)
            
            max_weight = max(predicted_weights.values()) if predicted_weights else 1
            
            print(f"Extracted {len(predicted_weights)} words (max: {max_weight:.4f})")

            return {
                'predicted_class': final_prediction,
                'predicted_weights': predicted_weights,
                'max_weight': max_weight,
                'explanation_available': True,
                'min_word_length': self.MIN_WORD_LENGTH
            }
            
        except Exception as e:
            print(f"LIME error: {e}")
            return {'explanation_available': False, 'error': str(e)}
    
    def check_harmful_urls(self, url_scan_results):
        """Check if any URLs are flagged as harmful"""
        if not url_scan_results:
            return False, []
        
        harmful_urls = []
        for result in url_scan_results:
            if result.get('is_harmful', False):
                harmful_urls.append(result)
        
        return len(harmful_urls) > 0, harmful_urls
    
    def predict(self, text, include_lime=True, url_scan_results=None):
        """Main prediction method with URL priority"""
        
        # PRIORITY CHECK: Harmful URLs override everything
        has_harmful_urls, harmful_url_list = self.check_harmful_urls(url_scan_results)
        
        if has_harmful_urls:
            print(f"⚠️  HARMFUL URL DETECTED - Overriding model prediction")
            print(f"   Found {len(harmful_url_list)} harmful URL(s)")
            
            # Calculate threat severity
            total_malicious = sum(url.get('malicious_count', 0) for url in harmful_url_list)
            total_suspicious = sum(url.get('suspicious_count', 0) for url in harmful_url_list)
            
            response = {
                'prediction': 'smishing',
                'url_override': True,
                'detection_method': 'VirusTotal URL Analysis',
                'harmful_url_details': {
                    'count': len(harmful_url_list),
                    'total_malicious_flags': total_malicious,
                    'total_suspicious_flags': total_suspicious,
                    'urls': harmful_url_list
                },
                'override_message': 'This message contains URLs flagged as harmful by VirusTotal security engines. The AI text analysis was not used for this classification.'
            }
            
            return response
        
        # No harmful URLs - proceed with normal model prediction
        if not self.model_loaded:
            return self.fallback_predict(text, url_scan_results)
        
        try:
            # Get model prediction
            result = self.classifier(text)[0]
            label = result['label']
            confidence = result['score']
            
            # Determine prediction class
            if label.lower() in ['smish', 'smishing', '1', 'label_1']:
                prediction = 'smishing'
                smishing_prob = confidence
                ham_prob = 1 - confidence
            else:
                prediction = 'ham'
                ham_prob = confidence
                smishing_prob = 1 - confidence
            
            confidence_level = self.categorize_confidence(confidence)
            
            # Build response
            response = {
                'prediction': prediction,
                'confidence': float(confidence),
                'confidence_level': confidence_level,
                'probabilities': {
                    'ham': float(ham_prob),
                    'smishing': float(smishing_prob)
                },
                'model_label': label,
                'model_used': 'Fine-tuned DistilBERT',
                'url_override': False
            }
            
            # Add LIME explanation
            if include_lime:
                lime_result = self.get_lime_explanation(text, prediction)
                if lime_result and lime_result.get('explanation_available'):
                    response['lime_explanation'] = lime_result
            
            # Check for conflict between model and URL scan
            if url_scan_results:
                clean_urls = [r for r in url_scan_results if not r.get('is_harmful', False) and not r.get('error')]
                if clean_urls and prediction == 'smishing':
                    response['url_model_conflict'] = True
                    response['conflict_message'] = 'The AI model detected suspicious text patterns, but the URLs were verified as safe by VirusTotal. Exercise caution and verify through official channels.'
            
            return response
            
        except Exception as e:
            print(f"Prediction error: {e}")
           