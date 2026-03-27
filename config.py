"""
Configuration Settings
Load from .env file
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration"""
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))
    
    # VirusTotal
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    
    # Model settings
    MODEL_PATH = os.getenv('MODEL_PATH', 'distilbert-smishing-final')
    MIN_WORD_LENGTH = int(os.getenv('MIN_WORD_LENGTH', 3))
    
    # LIME settings
    LIME_NUM_FEATURES = int(os.getenv('LIME_NUM_FEATURES', 15))
    LIME_NUM_SAMPLES = int(os.getenv('LIME_NUM_SAMPLES', 500))

    # SMS message limits 
    MIN_MESSAGE_LENGTH = 5           # Minimum characters
    MAX_MESSAGE_LENGTH = 1600        # ~10 concatenated SMS (160 × 10)
    SINGLE_SMS_LENGTH = 160          # Standard single SMS