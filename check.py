import os
import yara
import pefile
import hashlib
import patoolib
import pyzipper
import zipfile
import rarfile
rarfile.UNRAR_TOOL = r"C:\Program Files\WinRAR\UnRAR.exe"
from PIL import Image

# ✅ Load YARA rules
YARA_RULES_PATH = "packed_rules.yar"
rules = yara.compile(filepath=YARA_RULES_PATH)

# ✅ Function to check if a file is packed using YARA
def is_packed_yara(file_path):
    matches = rules.match(file_path)
    return bool(matches), [match.rule for match in matches]

# ✅ Function to calculate file hash
def hash_file(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# ✅ Function to analyze PE file for packing
def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)

        # Check entropy
        entropies = [section.get_entropy() for section in pe.sections]
        high_entropy = any(e > 7.5 for e in entropies)

        # Check sections
        packed_sections = []
        for section in pe.sections:
            name = section.Name.decode().strip("\x00")
            entropy = section.get_entropy()
            if name.lower() in [".upx0", ".packed", ".text0"] or entropy > 7.5:
                packed_sections.append(name)

        return high_entropy or len(packed_sections) > 0, packed_sections
    except Exception:
        return False, []

# ✅ Function to unpack UPX files
def unpack_upx(file_path):
    unpacked_path = file_path.replace(".exe", "_unpacked.exe")
    os.system(f"upx -d {file_path} -o {unpacked_path}")
    return unpacked_path if os.path.exists(unpacked_path) else None

# ✅ Function to extract overlay data from PE files
def extract_overlay(file_path):
    try:
        pe = pefile.PE(file_path)
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset:
            with open(file_path, "rb") as f:
                f.seek(overlay_offset)
                overlay_data = f.read()
            dump_path = file_path + "_overlay.bin"
            with open(dump_path, "wb") as dump_file:
                dump_file.write(overlay_data)
            return dump_path
    except Exception:
        pass
    return None

# ✅ Function to extract high-entropy sections from PE files
def extract_high_entropy_sections(file_path):
    try:
        pe = pefile.PE(file_path)
        extracted_files = []
        for section in pe.sections:
            entropy = section.get_entropy()
            if entropy > 7.5:
                section_name = section.Name.decode().strip("\x00")
                dump_path = f"{section_name}.bin"
                with open(dump_path, "wb") as f:
                    f.write(section.get_data())
                extracted_files.append(dump_path)
        return extracted_files
    except Exception:
        return []

# ✅ Function to extract ZIP, RAR, and PNG files
def unpack_archive(file_path):
    extracted_files = []
    file_ext = file_path.lower().split(".")[-1]

    if file_ext == "zip":
        with zipfile.ZipFile(file_path, "r") as zip_ref:
            extract_path = file_path + "_extracted"
            zip_ref.extractall(extract_path)
            extracted_files = [os.path.join(extract_path, f) for f in os.listdir(extract_path)]

    elif file_ext == "rar":
        with rarfile.RarFile(file_path, "r") as rar_ref:
            extract_path = file_path + "_extracted"
            rar_ref.extractall(extract_path)
            extracted_files = [os.path.join(extract_path, f) for f in os.listdir(extract_path)]

    elif file_ext == "png":
        try:
            img = Image.open(file_path)
            metadata = img.info
            if "compressed" in metadata or "packed" in metadata:
                print(f"⚠️ PNG may be steganographically packed: {file_path}")
        except Exception:
            pass

    return extracted_files

# ✅ Function to scan a file
def scan_file(file_path):
    print(f"\n🔍 Scanning: {file_path}")

    # ✅ Step 1: Check if it's a packed archive (ZIP, RAR, PNG)
    extracted_files = unpack_archive(file_path)
    if extracted_files:
        print(f"✅ Unpacked archive: {file_path} ➝ {len(extracted_files)} files extracted")
        for f in extracted_files:
            scan_file(f)  # Scan extracted files
        return

    # ✅ Step 2: Check if the file is packed using YARA
    is_packed, matched_rules = is_packed_yara(file_path)
    if is_packed:
        print(f"⚠️ YARA Detected Packing: {matched_rules}")

    # ✅ Step 3: Analyze PE file (if applicable)
    is_pe_packed, packed_sections = analyze_pe(file_path)
    if is_pe_packed:
        print(f"⚠️ Suspicious PE Sections: {packed_sections}")

    # ✅ Step 4: Attempt to unpack UPX (if applicable)
    if "Packed_KnownPackers" in matched_rules:
        unpacked_file = unpack_upx(file_path)
        if unpacked_file:
            print(f"✅ UPX Unpacked: {unpacked_file}")
            scan_file(unpacked_file)  # Re-scan the unpacked file

    # ✅ Step 5: Extract overlay data
    overlay_file = extract_overlay(file_path)
    if overlay_file:
        print(f"✅ Extracted Overlay: {overlay_file}")
        scan_file(overlay_file)  # Scan extracted overlay

    # ✅ Step 6: Extract high-entropy sections
    high_entropy_files = extract_high_entropy_sections(file_path)
    if high_entropy_files:
        print(f"✅ Extracted High-Entropy Sections: {high_entropy_files}")
        for f in high_entropy_files:
            scan_file(f)  # Scan extracted sections

    print(f"✅ Scan Completed: {file_path}")

# ✅ Example Usage
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Static Unpacking and Analysis Tool")
    parser.add_argument("file", help="Path to the file to analyze")
    args = parser.parse_args()
    scan_file(args.file)
