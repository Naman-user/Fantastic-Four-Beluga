import os
import requests
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
from flask_cors import CORS

# Enable CORS for all routes
CORS(app)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Get API key from Replit secrets
VIRUSTOTAL_API_KEY = os.environ['VIRUSTOTAL_API_KEY']

@app.route('/')
def index():
    return jsonify({"status": "running", "service": "Malware Scanner"})

@app.route('/scan', methods=['POST'])
def scan_file():
    logger.debug("Received scan request")

    if 'file' not in request.files:
        logger.error("No file in request")
        return "error"

    file = request.files['file']
    if file.filename == '':
        logger.error("Empty filename")
        return "error"

    temp_file_path = os.path.join('/tmp', file.filename)
    try:
        file.save(temp_file_path)
        logger.debug(f"File saved: {temp_file_path}")

        vt_result = check_virustotal(temp_file_path)
        logger.debug(f"VirusTotal result: {vt_result}")

        return vt_result
    except Exception as e:
        logger.error(f"Error in scan_file: {str(e)}")
        return "error"
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            logger.debug(f"File deleted: {temp_file_path}")

def check_virustotal(file_path):
    """Check VirusTotal for known malware signatures."""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        try:
            response = requests.post(url, headers=headers, files=files)
            logger.debug(f"VirusTotal Response: {response.status_code}")

            if response.status_code == 200:
                vt_data = response.json()
                analysis_stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return "malicious" if analysis_stats.get("malicious", 0) > 0 else "clean"
            else:
                return "error"
        except requests.RequestException as e:
            logger.error(f"VirusTotal API error: {e}")
            return "error"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
