"""
Message Translator Module
Handles language detection and translation
"""
import re
from deep_translator import GoogleTranslator


class MessageTranslator:
    """Handles message translation from Arabic to English"""
    
    def __init__(self, source='auto', target='en'):
        """
        Initialize translator
        
        Args:
            source: Source language (default: 'auto' for auto-detect)
            target: Target language (default: 'en' for English)
        """
        self.translator = GoogleTranslator(source=source, target=target)
        self.arabic_pattern = re.compile(r'[\u0600-\u06FF]')
    
    def detect_language(self, text):
        """
        Detect if text is Arabic or English
        
        Args:
            text: Text to analyze
            
        Returns:
            str: 'ar' for Arabic, 'en' for English
        """
        has_arabic = bool(self.arabic_pattern.search(text))
        return 'ar' if has_arabic else 'en'
    
    def translate(self, text, source_lang='ar', target_lang='en'):
        """
        Translate text from source to target language
        
        Args:
            text: Text to translate
            source_lang: Source language code
            target_lang: Target language code
            
        Returns:
            dict: Translation result with original, translated text, and metadata
        """
        if source_lang == 'en':
            return {
                'original': text,
                'translated': text,
                'source_lang': 'en',
                'needs_translation': False
            }
        
        try:
            translated_text = GoogleTranslator(source='ar', target='en').translate(text)
            
            return {
                'original': text,
                'translated': translated_text,
                'source_lang': source_lang,
                'needs_translation': True
            }
        except Exception as e:
            print(f"Translation error: {e}")
            return None