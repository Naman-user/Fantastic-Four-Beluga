import os
import struct
from pathlib import Path

def get_file_signature(file_path):
    with open(file_path, 'rb') as f:
        # Read first 16 bytes to catch more signature types
        signature = f.read(16)
        return signature

def identify_file_type(file_path):
    """
    Identifies the type of file based on its signature and PE header (if applicable),
    regardless of file extension
    
    Args:
        file_path (str): Path to the file to analyze
        
    Returns:
        tuple: (actual_type, claimed_type) where claimed_type is based on extension
    """
    # Check if file exists
    if not os.path.exists(file_path):
        return "File does not exist.", "No file"
    
    try:
        # Get the file extension(s)
        path = Path(file_path)
        extensions = path.name.split('.')
        claimed_type = "No extension"
        if len(extensions) > 1:
            claimed_type = f"Extension{'s' if len(extensions) > 2 else ''}: " + ", ".join(ext for ext in extensions[1:])
        
        # Get the signature of the file
        signature = get_file_signature(file_path)
        
        # Dictionary of known file signatures
        file_signatures = {
            b'\x89PNG': "PNG image file",
            b'\xFF\xD8\xFF': "JPEG image file",
            b'GIF87a': "GIF image file",
            b'GIF89a': "GIF image file",
            b'%PDF': "PDF document",
            b'PK\x03\x04': "ZIP archive/Office document (DOCX/XLSX/PPTX)",
            b'\x25\x21': "PostScript file",
            b'ID3': "MP3 audio file",
            b'Exif': "TIFF image file",
            b'\x42\x4D': "BMP image file",
            b'\x7FELF': "Linux/Unix executable",
            b'Rar!\x1A\x07': "RAR archive",
            b'\x1F\x8B\x08': "GZIP archive",
            b'\x00\x00\x01\x00': "ICO icon file"
        }
        
        # Check common non-PE file signatures first
        for sig, file_type in file_signatures.items():
            if signature.startswith(sig):
                return file_type, claimed_type
        
        # Check if it's a PE file (starts with MZ)
        if signature.startswith(b'MZ'):
            with open(file_path, 'rb') as f:
                # Get the PE header offset from the DOS header
                f.seek(0x3C)
                pe_offset_bytes = f.read(4)
                pe_offset = struct.unpack('<I', pe_offset_bytes)[0]
                
                # Verify PE offset is within reasonable bounds
                file_size = os.path.getsize(file_path)
                if pe_offset > file_size:
                    return "Invalid PE file (corrupt PE offset)", claimed_type
                
                # Check PE signature
                f.seek(pe_offset)
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    return "Invalid PE file (missing PE signature)", claimed_type
                
                # Skip to characteristics (20 bytes from start of file header)
                f.seek(pe_offset + 22)
                characteristics = struct.unpack('<H', f.read(2))[0]
                
                # Analyze characteristics
                is_dll = bool(characteristics & 0x2000)  # IMAGE_FILE_DLL
                is_system = bool(characteristics & 0x1000)  # IMAGE_FILE_SYSTEM
                is_exe = bool(characteristics & 0x0002)  # IMAGE_FILE_EXECUTABLE_IMAGE
                
                # Determine file type based on characteristics
                if is_dll:
                    return "DLL (Dynamic Link Library) file", claimed_type
                elif is_system:
                    return "SYS (System Driver) file", claimed_type
                elif is_exe:
                    return "EXE (Executable) file", claimed_type
                else:
                    return f"PE file (characteristics: 0x{characteristics:04X})", claimed_type
        
        # Try to identify text files by checking for text content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                start = f.read(1024)  # Read first 1KB
                if all(ord(c) < 128 for c in start):
                    return "ASCII text file", claimed_type
        except UnicodeDecodeError:
            pass
        
        # If we get here, it's not a recognized file type
        return "Unknown binary file type", claimed_type
        
    except Exception as e:
        return f"Error analyzing file: {str(e)}", claimed_type

def analyze_file(file_path):
    """
    Analyze a file and print its details including actual vs claimed type
    
    Args:
        file_path (str): Path to the file to analyze
    """
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found")
        return
        
    actual_type, claimed_type = identify_file_type(file_path)
    file_size = os.path.getsize(file_path)
    
    print("File Analysis Results:")
    print(f"Path: {file_path}")
    print(f"Size: {file_size:,} bytes")
    print(f"Actual Type (based on content): {actual_type}")
    print(f"Claimed Type (based on extension): {claimed_type}")
    
    # Warn if there might be a mismatch
    if claimed_type != "No extension":
        claimed_lower = claimed_type.lower()
        actual_lower = actual_type.lower()
        if ("exe" in claimed_lower or "dll" in claimed_lower or "sys" in claimed_lower) and \
           not ("exe" in actual_lower or "dll" in actual_lower or "sys" in actual_lower):
            print("\nWARNING: File claims to be executable but signature suggests otherwise!")
        elif ("exe" in actual_lower or "dll" in actual_lower or "sys" in actual_lower) and \
             not ("exe" in claimed_lower or "dll" in claimed_lower or "sys" in claimed_lower):
            print("\nWARNING: File is executable but extension suggests otherwise!")

# Example usage
if __name__ == "__main__":
    # Test with a file that has double extension
    file_path = r"C:\Users\karti\Desktop\beluja\Malicious Links.txt"  # Replace with your file path
    analyze_file(file_path)