# Fantastic-Four-Beluga
This project addresses the Beluga cybersecurity challenge by providing a comprehensive solution that includes:

Static Analysis: Scanning files for malicious patterns using YARA rules.
Analysis using API: Utilizing VirusTotal API for file scanning.
URL Analysis: Detecting phishing URLs within documents.

Repository Structure
The repository is organized as follows:

check.py: Contains the ArchiveScanner class for scanning files and archives using YARA rules and integrating URL checking.
file_type_6.py: Module for identifying file types.
index.html: Frontend interface for user interactions.
mainVirusTotal.py: Main script for dynamic analysis using the VirusTotal API.
packed_rules.yar: YARA rules file for detecting malicious patterns.
static_analysis.py: Script for performing static analysis on files.
url_checker.py: Module for detecting phishing URLs within documents.
README.md: This file, providing an overview and instructions.
