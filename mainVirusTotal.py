import os
import requests
import logging
import hashlib
import time
from flask import Flask, request, jsonify
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor
from static_analysis import perform_static_analysis

app = Flask(__name__)
CORS(app, resources={r"/scan": {"origins": "*"}})

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB
app.config['UPLOAD_FOLDER'] = '/tmp'

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

def generate_file_hash(file_path):
    """Generate SHA256 hash using memory-efficient chunks"""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Hash error: {e}")
        return None

def check_virustotal(file_hash):
    """VirusTotal API check with timeout"""
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10
        )
        if response.status_code == 200:
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return "malicious" if stats.get('malicious', 0) > 0 else "clean"
        return "error"
    except Exception as e:
        logger.error(f"VT check failed: {e}")
        return "error"

@app.route('/')
def health_check():
    return jsonify({"status": "active", "service": "Malware Scanner"})

@app.route('/scan', methods=['POST'])
def scan_file():
    start_time = time.time()
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({"error": "Invalid file"}), 400

    temp_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    try:
        file.save(temp_file_path)
        logger.info(f"Scanning: {file.filename}")

        # Parallel processing
        with ThreadPoolExecutor(max_workers=2) as executor:
            hash_future = executor.submit(generate_file_hash, temp_file_path)
            static_future = executor.submit(perform_static_analysis, temp_file_path)

            file_hash = hash_future.result(timeout=10)
            static_result = static_future.result(timeout=20)

            if not file_hash:
                return jsonify({"error": "Hash generation failed"}), 500

            vt_future = executor.submit(check_virustotal, file_hash)
            vt_result = vt_future.result(timeout=15)

        # Determine final verdict
        if vt_result == "malicious":
            final_verdict = "malicious"
        else:
            final_verdict = static_result.get("verdict", "clean")

        return jsonify({
            "verdict": final_verdict,
            "virustotal": vt_result,
            "indicators": static_result.get("indicators", []),
            "scan_time": round(time.time() - start_time, 2)
        })

    except TimeoutError:
        logger.warning("Scan timed out")
        return jsonify({"error": "Scan timeout"}), 504
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return jsonify({"error": "Processing error"}), 500
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
