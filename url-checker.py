import re
import fitz
import docx
from urllib.parse import urlparse
from typing import Set, List, Tuple
import tldextract

class PhishingDetector:
    def __init__(self):
        # Expanded trusted domains (now includes common legitimate services)
        self.TRUSTED_DOMAINS = {
            "amazon": ["amazon.com", "amazon.co.uk", "aws.amazon.com"],
            "paypal": ["paypal.com", "paypal.me"],
            "google": ["google.com", "gmail.com", "youtube.com"],
            "facebook": ["facebook.com", "fb.com", "instagram.com"],
            "microsoft": ["microsoft.com", "live.com", "outlook.com"],
            "dropbox": ["dropbox.com"],
            "github": ["github.com"],
            "stackoverflow": ["stackoverflow.com"],
            "wikipedia": ["wikipedia.org"],
            "nytimes": ["nytimes.com"],
            "reddit": ["reddit.com"]
        }
        
        # Suspicious keywords in domain names
        self.SUSPICIOUS_KEYWORDS = {
            'security': 40,
            'login': 40,
            'signin': 40,
            'verify': 40,
            'account': 30,
            'update': 30,
            'confirm': 30,
            'secure': 30,
            'authenticate': 40,
            'wallet': 30,
            'payment': 30,
            'password': 50,
            'credential': 50,
            'bitcoin': 30,
            'crypto': 30,
            'prize': 40,
            'winner': 40,
            'free': 30,
            'deal': 20,
            'offer': 20,
            'special': 20,
            'limited': 20,
            'urgent': 30,
            'suspended': 40,
            'unusual': 30,
            'activity': 20,
            'verify': 40,
            'steal': 70,
            'malware': 90,
            'hack': 70,
            'phish': 90,
            'scam': 90,
            'evil': 80,
            'dangerous': 80,
            'fake': 80,
            'bad': 60,
            'ransom': 90
        }

        # Suspicious file extensions
        self.SUSPICIOUS_EXTENSIONS = {
            '.exe': 80,
            '.bat': 80,
            '.cmd': 80,
            '.msi': 70,
            '.dll': 60,
            '.scr': 90,
            '.app': 50,
            '.jar': 50,
            '.ps1': 70,
            '.vbs': 80,
            '.hta': 80
        }
        
        # Improved TLD categorization with risk scores
        self.TLD_CATEGORIES = {
            'high_risk': {
                'su': 80, 'ru': 60, 'cn': 60, 'tk': 70, 'top': 50,
                'xyz': 50, 'gq': 70, 'ml': 70, 'ga': 70, 'cf': 70,
                'pw': 60, 'cc': 50, 'tv': 40
            },
            'medium_risk': {
                'info': 30, 'biz': 30, 'pro': 20, 'site': 30,
                'online': 30, 'click': 40, 'link': 40
            }
        }
        
        self.URL_REGEX = re.compile(
            r'(?:(?:https?|ftp):\/\/)?'
            r'(?:[\w-]+\.)+[\w-]+(?:\/[^\s]*)?'
            r'(?:\?[^\s]*)?'
            r'(?:#[^\s]*)?',
            re.IGNORECASE
        )
        
        self.SHORTENERS = {
            "bit.ly": 30, "tinyurl.com": 30, "t.co": 30, "goo.gl": 30,
            "ow.ly": 30, "buff.ly": 30, "adf.ly": 40, "tiny.cc": 30,
            "is.gd": 30, "cli.gs": 30, "pic.twitter.com": 20
        }

    def analyze_url_components(self, url: str, domain: str, path: str) -> List[tuple]:
        """Analyze URL components for suspicious patterns."""
        risk_factors = []
        
        # Check domain length (very long domains are suspicious)
        if len(domain) > 30:
            risk_factors.append(('Unusually long domain name', 20))
            
        # Check for suspicious keywords in domain and path
        url_lower = url.lower()
        domain_lower = domain.lower()
        path_lower = path.lower()
        
        for keyword, score in self.SUSPICIOUS_KEYWORDS.items():
            if keyword in domain_lower:
                risk_factors.append((f'Suspicious keyword in domain: {keyword}', score))
            if keyword in path_lower:
                risk_factors.append((f'Suspicious keyword in path: {keyword}', score // 2))

        # Check for suspicious file extensions
        for ext, score in self.SUSPICIOUS_EXTENSIONS.items():
            if url_lower.endswith(ext):
                risk_factors.append((f'Suspicious file extension: {ext}', score))

        # Check for excessive subdomains
        subdomain_count = len(domain.split('.')) - 2
        if subdomain_count > 2:
            risk_factors.append(('Multiple suspicious subdomains', 30))

        # Check for numeric patterns in domain (common in phishing)
        if re.search(r'\d{4,}', domain):
            risk_factors.append(('Suspicious number pattern in domain', 30))

        # Check for character substitution (common in phishing)
        if re.search(r'[0o][a-zA-Z]', domain) or re.search(r'[a-zA-Z][0o]', domain):
            risk_factors.append(('Possible character substitution detected', 40))

        return risk_factors

    def analyze_url(self, url: str) -> dict:
        """Analyze URL with enhanced detection methods."""
        results = {
            'status': 'clean',
            'warnings': [],
            'risk_score': 0
        }
        # ✅ Check if URL contains HTTP/HTTPS
        if not url.startswith(('http://', 'https://')):
            results['warnings'].append('URL does not contain http or https')
            results['risk_score'] += 20
        
        return results
        # Basic URL cleaning and validation
        url = url.strip().lower()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            parsed_url = urlparse(url)
            domain_info = tldextract.extract(url)
            domain = f"{domain_info.domain}.{domain_info.suffix}"
            
            # Check if it's a trusted domain
            for brand, trusted_domains in self.TRUSTED_DOMAINS.items():
                if domain in trusted_domains:
                    return results

            # Check URL shorteners
            if domain in self.SHORTENERS:
                results['warnings'].append('URL shortener detected')
                results['risk_score'] += self.SHORTENERS[domain]

            # Check TLD risk
            if domain_info.suffix in self.TLD_CATEGORIES['high_risk']:
                results['warnings'].append('High-risk TLD detected')
                results['risk_score'] += self.TLD_CATEGORIES['high_risk'][domain_info.suffix]
            elif domain_info.suffix in self.TLD_CATEGORIES['medium_risk']:
                results['warnings'].append('Medium-risk TLD detected')
                results['risk_score'] += self.TLD_CATEGORIES['medium_risk'][domain_info.suffix]

            # Analyze URL components
            risk_factors = self.analyze_url_components(url, domain, parsed_url.path)
            for warning, score in risk_factors:
                results['warnings'].append(warning)
                results['risk_score'] += score

            # Check for brand impersonation
            for brand, trusted_domains in self.TRUSTED_DOMAINS.items():
                if brand in domain and domain not in trusted_domains:
                    if (
                        re.search(rf"{brand}\d", domain) or
                        re.search(rf"{brand}[_-]", domain) or
                        re.search(rf"{brand}.*?(security|login|verify|account)", domain)
                    ):
                        results['warnings'].append(f'Suspicious brand impersonation of {brand}')
                        results['risk_score'] += 70

            # Normalize risk score
            results['risk_score'] = min(100, results['risk_score'])

            # Final risk assessment
            if results['risk_score'] >= 70:
                results['status'] = 'high_risk'
            elif results['risk_score'] >= 40:
                results['status'] = 'medium_risk'
            elif results['risk_score'] > 0:
                results['status'] = 'low_risk'

            return results

        except Exception as e:
            return {'status': 'invalid', 'warnings': ['Invalid URL format'], 'risk_score': 100}

    # [Previous methods for document scanning remain the same]
    def extract_urls_from_text(self, text: str) -> Set[str]:
        return set(self.URL_REGEX.findall(text))

    def extract_pdf_links(self, pdf_doc) -> Set[str]:
        links = set()
        for page in pdf_doc:
            for link in page.get_links():
                if 'uri' in link:
                    links.add(link['uri'])
        return links

    def extract_docx_links(self, doc) -> Set[str]:
        links = set()
        for rel in doc.part.rels:
            if "hyperlink" in doc.part.rels[rel].reltype:
                links.add(doc.part.rels[rel].target_ref)
        return links

    def scan_document(self, file_path: str) -> List[dict]:
        extracted_urls = set()
        results = []

        try:
            if file_path.endswith('.txt'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    text = f.read()
                extracted_urls.update(self.extract_urls_from_text(text))
                    
            elif file_path.endswith('.pdf'):
                doc = fitz.open(file_path)
                text = ''
                for page in doc:
                    text += page.get_text()
                extracted_urls.update(self.extract_urls_from_text(text))
                extracted_urls.update(self.extract_pdf_links(doc))
                doc.close()
                
            elif file_path.endswith('.docx'):
                doc = docx.Document(file_path)
                text = '\n'.join(para.text for para in doc.paragraphs)
                extracted_urls.update(self.extract_urls_from_text(text))
                extracted_urls.update(self.extract_docx_links(doc))
            else:
                return [{'error': 'Unsupported file format'}]

            for url in extracted_urls:
                analysis = self.analyze_url(url)
                results.append({
                    'url': url,
                    **analysis
                })

            return results

        except Exception as e:
            return [{'error': f'Error processing file: {str(e)}'}]

def main():
    detector = PhishingDetector()
    file_path = r"C:\Users\karti\Desktop\Malicious Links.txt"  # Replace with your file path
    results = detector.scan_document(file_path)
    
    print("\n🔍 Scan Results:\n")
    for result in results:
        if 'error' in result:
            print(f"Error: {result['error']}")
            continue
            
        print(f"URL: {result['url']}")
        print(f"Status: {result['status'].upper()}")
        print(f"Risk Score: {result['risk_score']}/100")
        if result['warnings']:
            print("Warnings:")
            for warning in result['warnings']:
                print(f" - {warning}")
        print()

if __name__ == "__main__":
    main()