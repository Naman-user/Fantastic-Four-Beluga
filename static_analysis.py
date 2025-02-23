import os
import math
import subprocess
import pefile
import logging
import magic
from concurrent.futures import ThreadPoolExecutor
from oletools.olevba import VBA_Parser

logger = logging.getLogger(__name__)

# Analysis configuration
SUSPICIOUS_APIS = {
    "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory", "LoadLibrary",
    "WinExec", "ShellExecute", "InternetOpenUrl", "GetAsyncKeyState", "NtCreateThreadEx"
}

SUSPICIOUS_KEYWORDS = [
    "cmd.exe", "powershell", "whoami", "net user", "tasklist", "schtasks",
    "wget", "curl", "Invoke-WebRequest", "certutil", "ftp", "tftp",
    "nc.exe", "nmap", "reg add", "reg delete", "runonce", "startup",
    "autorun", "HKCU\\Software", "rundll32", "dllhost", "winlogon",
    "VirtualAlloc", "CreateRemoteThread", "Mimikatz", "keylogger",
    "payload", "reverse shell", "meterpreter", "stager"
]

def perform_static_analysis(file_path):
    """Optimized static analysis with parallel checks"""
    try:
        file_type = magic.from_file(file_path, mime=True)
        results = {}

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                "High entropy": executor.submit(check_entropy, file_path),
                "Suspicious strings": executor.submit(check_suspicious_strings, file_path),
                "Packed executable": executor.submit(check_packed, file_path),
                "Suspicious imports": executor.submit(check_pe_imports, file_path, file_type),
                "Office macros": executor.submit(check_office_macros, file_path),
                "XOR obfuscation": executor.submit(check_xor_obfuscation, file_path),
                "PDF issues": executor.submit(check_pdf, file_path, file_type),
            }

            for name, future in futures.items():
                try:
                    results[name] = future.result(timeout=5)
                except:
                    results[name] = False

        detected = [k for k, v in results.items() if v]
        return {
            "verdict": "malicious" if len(detected) >= 3 else "clean",
            "indicators": detected
        }
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return {"verdict": "error", "indicators": []}

# Analysis functions
def check_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read(102400)  # First 100KB for entropy check

        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in counts if c)
        return entropy > 7.5
    except:
        return False

def check_suspicious_strings(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read(1024000).decode('utf-8', errors='ignore').lower()

        return any(keyword.lower() in content for keyword in SUSPICIOUS_KEYWORDS)
    except:
        return False

def check_packed(file_path):
    try:
        result = subprocess.run(
            ["upx", "-t", file_path],
            capture_output=True,
            text=True,
            timeout=3
        )
        return "packed" in result.stdout.lower()
    except:
        return False

def check_pe_imports(file_path, file_type):
    if not file_type.startswith("application/x-dosexec"):
        return False
    try:
        pe = pefile.PE(file_path, fast_load=True)
        imports = {entry.name.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT for entry in entry.imports if entry.name}
        return any(api in imports for api in SUSPICIOUS_APIS)
    except:
        return False

def check_office_macros(file_path):
    try:
        with VBA_Parser(file_path) as parser:
            return parser.detect_vba_macros()
    except:
        return False

def check_xor_obfuscation(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read(512)

        for key in range(1, 256):
            if all(32 <= b ^ key <= 126 for b in data):
                return True
        return False
    except:
        return False

def check_pdf(file_path, file_type):
    if file_type != "application/pdf":
        return False
    try:
        pdfinfo = subprocess.run(
            ["pdfinfo", file_path],
            capture_output=True,
            text=True,
            timeout=3
        )
        encrypted = "Encrypted: yes" in pdfinfo.stdout

        pdfid = subprocess.run(
            ["pdfid", file_path],
            capture_output=True,
            text=True,
            timeout=3
        )
        scripts = "/JavaScript" in pdfid.stdout or "/JS" in pdfid.stdout

        return encrypted or scripts
    except:
        return False
