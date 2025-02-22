import os
import yara
import pefile
import hashlib
import zipfile
import rarfile
import logging
import tempfile
import shutil
from pathlib import Path
from typing import List, Tuple, Optional

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ArchiveScanner:
    def __init__(self, yara_rules_path: str):
        try:
            self.rules = yara.compile(filepath=yara_rules_path)
            self.temp_dir = tempfile.mkdtemp(prefix="scanner_")
            logger.info(f"Created temporary directory: {self.temp_dir}")
        except Exception as e:
            logger.error(f"Initialization error: {e}")
            raise

    def __del__(self):
        """Cleanup temporary files on object destruction"""
        try:
            if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

    def scan_file(self, file_path: str) -> None:
        """Main entry point for file scanning"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return

            logger.info(f"Starting scan of: {file_path}")
            file_type = self._get_file_type(file_path)
            
            if file_type == "zip":
                self._handle_zip(file_path)
            elif file_type == "rar":
                self._handle_rar(file_path)
            else:
                self._scan_single_file(file_path)
                
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")

    def _get_file_type(self, file_path: str) -> str:
        """Determine file type based on extension and magic numbers"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
            
            # Check ZIP signature
            if magic.startswith(b'PK\x03\x04'):
                return "zip"
            # Check RAR signature
            elif magic.startswith(b'Rar!'):
                return "rar"
            
            # Fallback to extension check
            ext = Path(file_path).suffix.lower()
            if ext == '.zip':
                return "zip"
            elif ext == '.rar':
                return "rar"
            
            return "unknown"
            
        except Exception as e:
            logger.error(f"Error determining file type: {e}")
            return "unknown"

    def _handle_zip(self, zip_path: str) -> None:
        """Handle ZIP archive extraction and scanning"""
        try:
            extract_dir = os.path.join(self.temp_dir, "zip_extract")
            os.makedirs(extract_dir, exist_ok=True)
            
            logger.info(f"Extracting ZIP file: {zip_path}")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # List all files before extraction
                file_list = zip_ref.namelist()
                logger.info(f"Files in ZIP: {file_list}")
                
                # Extract files
                zip_ref.extractall(extract_dir)
                
            # Scan each extracted file
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    logger.info(f"Scanning extracted file: {file_path}")
                    self._scan_single_file(file_path)
                    
        except zipfile.BadZipFile:
            logger.error(f"Invalid or corrupted ZIP file: {zip_path}")
        except Exception as e:
            logger.error(f"Error processing ZIP {zip_path}: {e}")

    def _handle_rar(self, rar_path: str) -> None:
        """Handle RAR archive extraction and scanning"""
        try:
            extract_dir = os.path.join(self.temp_dir, "rar_extract")
            os.makedirs(extract_dir, exist_ok=True)
            
            logger.info(f"Extracting RAR file: {rar_path}")
            with rarfile.RarFile(rar_path, 'r') as rar_ref:
                # List all files before extraction
                file_list = rar_ref.namelist()
                logger.info(f"Files in RAR: {file_list}")
                
                # Extract files
                rar_ref.extractall(extract_dir)
                
            # Scan each extracted file
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    logger.info(f"Scanning extracted file: {file_path}")
                    self._scan_single_file(file_path)
                    
        except rarfile.BadRarFile:
            logger.error(f"Invalid or corrupted RAR file: {rar_path}")
        except Exception as e:
            logger.error(f"Error processing RAR {rar_path}: {e}")

    def _scan_single_file(self, file_path: str) -> None:
        """Scan a single file with YARA rules"""
        try:
            matches = self.rules.match(file_path)
            if matches:
                logger.warning(f"YARA matches found in {file_path}:")
                for match in matches:
                    logger.warning(f"- Rule: {match.rule}")
            else:
                logger.info(f"No YARA matches in {file_path}")
                
            # Calculate and log file hash
            file_hash = self._calculate_hash(file_path)
            logger.info(f"File hash (SHA256): {file_hash}")
            
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash: {e}")
            return ""

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Archive and File Scanner")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--rules", help="Path to YARA rules file", 
                       default="packed_rules.yar")
    args = parser.parse_args()

    scanner = ArchiveScanner(args.rules)
    scanner.scan_file(args.file)

if __name__ == "__main__":
    main()