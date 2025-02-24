# Fantastic-Four-Beluga
1.)	This project addresses the Beluga cybersecurity challenge by providing a comprehensive solution that includes:

2.) Command to run the code:
Just open the webpage using github pages and upload the files you want to check
To check individual codes, run the script along with file name. 
1.)python script.py path/to/your/file
2.)python url_checker.py( add the file path in the code)
3.)python -c "from static_analysis import perform_static_analysis; print(perform_static_analysis('test.exe'))"
4.)python file_type.py <file-to-analyze>
5.)python mainVirusTotal.py curl -X POST -F "file=@test.exe" http://localhost:5000/scan

Note- All the dependencies are listed in dependencies.txt

3.)Repository Structure:
The repository is organized as follows:

1.)	check.py: Contains the ArchiveScanner class for scanning files and archives using YARA rules and integrating URL checking.
2.)	file_type_6.py: Module for identifying file types.
3.)	index.html: Frontend interface for user interactions.
4.)	mainVirusTotal.py: Main script for dynamic analysis using the VirusTotal API.
5.)	packed_rules.yar: YARA rules file for detecting malicious patterns.
6.)	static_analysis.py: Script for performing static analysis on files.
7.)	url_checker.py: Module for detecting phishing URLs within documents.

Note- Due to time constraints, all components of the page might not be integrated with each other. You can check individiual components using the method above

3.)Concise Summary of the Code
The Fantastic-Four-Beluga project is a purely static malware detection system that detects malicious files, packed executables, and phishing URLs without executing them.

Key Functionalities:

•	Static Analysis (static_analysis.py)
Identifies malicious patterns, obfuscation, and suspicious API calls.
Uses entropy checks, YARA rules, and PE header analysis to detect malware.
Extracts metadata to classify the file without running it.

•	File Type Detection (file_type_6.py)
Determines the real file type based on its signature, not just its extension.
Helps decide whether the file should undergo deeper static analysis.

•	Packed File Handling (check.py)
Extracts ZIP and RAR archives for deeper inspection.
Unpacks packed executables (e.g., UPX, MPRESS) to reveal hidden payloads.
Applies YARA rule-based scanning to detect known malware.

•	VirusTotal Hash-Based Check (mainVirusTotal.py)
Computes the file hash (SHA-256) and queries VirusTotal API.
Determines if the file matches known malware signatures without executing it.
If the hash is unknown, the system falls back on static analysis.

•	Phishing URL Detection (url_checker.py)
Extracts URLs from PDFs, TXT, and DOCX files.
Checks URLs against a list of high-risk domains, suspicious keywords, and shorteners.
Assigns a risk score to each URL to detect phishing attempts.

•	Web Interface (index.html)
Allows users to upload files for static analysis.
Displays results from YARA, VirusTotal hash check, and phishing URL detection.

•	Workflow (No Dynamic Analysis Used)
	✔ User uploads a file → Identify file type → Unpack if needed
	✔ Perform YARA rule-based scanning and metadata analysis
	✔ Compute SHA-256 → Query VirusTotal API for known malware hashes
	✔ Extract & scan URLs if applicable → Return final static analysis report

4.) Why This Works for the Problem Statement
✅ No file execution (only static analysis).
✅ VirusTotal is used for hash-based lookups only (no behavioural analysis).
✅ Malware detection is based on signatures, entropy, and unpacking techniques.
This ensures the system remains fully compliant with the problem statement while maintaining strong malware detection capabilities. 🚀

