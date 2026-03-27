"""
SmishGuard - SMS Phishing Detection System
Main Flask Application 
"""
import warnings
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv

# Import our classes
from translator import MessageTranslator
from virus_total import VirusTotalChecker
from detector import SmishingDetector
from config import Config

warnings.filterwarnings('ignore')

# Load environment variables
load_dotenv()

# Create Flask app
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize components
print("\n" + "="*60)
print("Starting SmishGuard System")
print("="*60)

translator = MessageTranslator()
print("Translator ready")

vt_checker = VirusTotalChecker(Config.VIRUSTOTAL_API_KEY)
print("VirusTotal checker ready")

detector = SmishingDetector()
print("Smishing detector ready")

print("="*60)
print("SmishGuard is ready!")
print("="*60 + "\n")


# =============================================================================
# PAGE ROUTES
# =============================================================================

@app.route('/')
def home():
    """Home page"""
    return render_template('index.html')


@app.route('/analysis')
def analysis():
    """Analysis page"""
    return render_template('analysis.html')


@app.route('/quiz')
def quiz():
    """Quiz page"""
    return render_template('quiz.html')


@app.route('/learn')
def learn():
    """Learning page"""
    return render_template('learn.html')


# =============================================================================
# API ROUTES
# =============================================================================

@app.route('/analyze', methods=['POST'])
def analyze_message():
    """Analyze message for smishing threats"""
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        include_lime = data.get('include_lime', True)
        
        # Validate input
        if not message:
            return jsonify({'error': 'Please enter a message to analyze'}), 400
        
        if len(message) < Config.MIN_MESSAGE_LENGTH:
            return jsonify({'error': f'Message must be at least {Config.MIN_MESSAGE_LENGTH} characters'}), 400
        
        if len(message) > Config.MAX_MESSAGE_LENGTH:
            return jsonify({'error': f'Message too long. SMS messages are typically under {Config.MAX_MESSAGE_LENGTH} characters ({int(Config.MAX_MESSAGE_LENGTH/160)} SMS parts)'}), 400
        
        print(f"\n{'='*60}")
        print("📨 NEW ANALYSIS")
        print(f"{'='*60}")
        print(f"Message: {message[:100]}...")
        print(f"Length: {len(message)} characters (~{len(message)//160 + 1} SMS)")
        
        # Step 1: Language detection and translation
        detected_lang = translator.detect_language(message)
        translation_result = None
        analysis_text = message
        
        if detected_lang == 'ar':
            print("Arabic detected - translating...")
            translation_result = translator.translate(message)
            if translation_result:
                analysis_text = translation_result['translated']
        
        # Step 2: URL scanning with validation
        urls = vt_checker.extract_urls(message)
        url_results = []
        validation_errors = []
        
        if urls:
            print(f"Scanning {len(urls)} URL(s)...")
            for url in urls:
                result = vt_checker.check_url(url)
                
                # Track validation errors separately
                if result.get('validation_failed'):
                    validation_errors.append({
                        'url': url,
                        'error': result.get('error')
                    })
                else:
                    url_results.append(result)
        
        # Step 3: AI analysis
        print("Running AI analysis...")
        analysis = detector.predict(
            analysis_text,
            include_lime=include_lime,
            url_scan_results=url_results
        )
        
        # Add metadata to response
        analysis['url_scan_results'] = url_results
        analysis['urls_found'] = len(urls)
        
        # Add validation errors if any
        if validation_errors:
            analysis['url_validation_errors'] = validation_errors
            analysis['validation_warning'] = f"{len(validation_errors)} URL(s) had invalid format and were not scanned"
        
        if translation_result:
            analysis['translation'] = translation_result
        
        # Print results (handle both normal and override cases)
        print(f"Result: {analysis['prediction'].upper()}")
        
        if analysis.get('url_override'):
            # VirusTotal override case - no confidence score
            print(f"   Detection: VirusTotal URL Analysis")
            print(f"   Harmful URLs: {analysis.get('harmful_url_details', {}).get('count', 0)}")
        else:
            # Normal AI prediction - has confidence
            confidence = analysis.get('confidence', 0)
            print(f"   Confidence: {confidence:.1%}")
            
        if validation_errors:
            print(f"   ⚠️  {len(validation_errors)} URL validation error(s)")
        print(f"{'='*60}\n")
        
        return jsonify(analysis)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Analysis failed'}), 500

# =============================================================================
# RUN APPLICATION
# =============================================================================

if __name__ == '__main__':
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    )