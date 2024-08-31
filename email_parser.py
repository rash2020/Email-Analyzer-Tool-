# email_analyzer/email_parser.py

import email
from email.policy import default
import re
import hashlib
from urllib.parse import urlparse, parse_qs, unquote
import webbrowser
import html

class EmailParser:
    def parse_email_content(self, content):
        return email.message_from_string(content, policy=default)

    def extract_headers(self, email_message):
        headers_info = {
            "From": self.sanitize(email_message.get("From", "")),
            "Display Name": self.extract_display_name(email_message.get("From", "")),
            "To": self.sanitize(email_message.get("To", "")),
            "CC": self.sanitize(email_message.get("Cc", "None")),
            "Timestamp": self.sanitize(email_message.get("Date", "")),
            "Reply-To": self.sanitize(email_message.get("Reply-To", "")),
            "Return-Path": self.sanitize(email_message.get("Return-Path", "")),
        }
        return headers_info

    def extract_received_lines(self, email_message):
        return email_message.get_all('Received', [])

    def format_received_line(self, line, index):
        formatted_line = f"**Hop {index + 1}**\n"
        parts = line.split(';')
        for part in parts:
            formatted_line += f"  - {self.sanitize(part.strip())}\n"
        return formatted_line

    def extract_x_headers(self, email_message):
        return {k: v for k, v in email_message.items() if k.lower().startswith("x-")}

    def extract_attachments(self, email_message):
        attachments_info = []
        if email_message.is_multipart():
            for part in email_message.iter_attachments():
                payload = part.get_payload(decode=True)
                attachment_info = {
                    "filename": self.sanitize(part.get_filename()),
                    "content_type": self.sanitize(part.get_content_type()),
                    "file_size": len(payload) / 1024,
                    "md5": hashlib.md5(payload).hexdigest(),
                    "sha1": hashlib.sha1(payload).hexdigest(),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
                attachments_info.append(attachment_info)
        return attachments_info

    def extract_urls(self, email_message):
        urls = []
        for part in email_message.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                content = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                urls.extend(re.findall(r"http[s]?://[^\s]+", content))
        return urls

    def parse_and_clean_url(self, url):
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        scheme = parsed_url.scheme
        port = parsed_url.port if parsed_url.port else ("443" if scheme == "https" else "80")
        query = parse_qs(parsed_url.query)

        if 'safelinks.protection.outlook.com' in domain:
            original_url = unquote(parse_qs(parsed_url.query).get('url', [url])[0])
            parsed_url = urlparse(original_url)
            domain = parsed_url.netloc
            path = parsed_url.path
            scheme = parsed_url.scheme
            query = parse_qs(parsed_url.query)

        formatted_query = self.format_query_string(query)
        phishing_warnings = self.detect_phishing(domain)
        return self.sanitize(domain), self.sanitize(path), scheme, port, formatted_query, phishing_warnings

    def format_query_string(self, query_dict):
        if not query_dict:
            return None
        return {self.sanitize(k): self.sanitize(v[0]) for k, v in query_dict.items()}

    def extract_display_name(self, from_header):
        match = re.search(r'(?P<name>.+?)\s<.*>', from_header)
        return match.group('name').strip() if match else self.sanitize(from_header)

    def extract_body(self, email_message):
        plain_body = ""
        html_body = ""

        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain" and not plain_body:
                    plain_body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                elif content_type == "text/html" and not html_body:
                    html_body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
        else:
            content_type = email_message.get_content_type()
            if content_type == "text/plain":
                plain_body = email_message.get_payload(decode=True).decode("utf-8", errors="ignore")
            elif content_type == "text/html":
                html_body = email_message.get_payload(decode=True).decode("utf-8", errors="ignore")

        if plain_body:
            return plain_body
        elif html_body:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html_body, "html.parser")
                return soup.get_text()
            except ImportError:
                return "HTML content detected, but BeautifulSoup is not installed. Please install it for better viewing.\n" + html_body
        else:
            return "No body content found or unable to decode content."

    def sanitize(self, text):
        return html.escape(text).replace("&amp;", "&").replace("&quot;", '"')

    def detect_phishing(self, domain):
        warnings = []
        if domain.endswith(('.ru', '.cn', '.xyz', '.tk', '.ml')):
            warnings.append(f"Suspicious top-level domain ({domain.split('.')[-1]})")
        if re.search(r'[0-9]{4,}', domain):
            warnings.append("Suspicious use of numbers in domain")
        if '-' in domain:
            warnings.append("Suspicious use of hyphens in domain")
        if len(domain) > 30:
            warnings.append("Unusually long domain name")
        if domain.startswith('xn--'):
            warnings.append("Domain uses Punycode, possible homograph attack")
        
        return ", ".join(warnings) if warnings else None

    def generate_virustotal_url(self, identifier):
        return f"https://www.virustotal.com/gui/search/{self.sanitize(identifier)}"

    def open_url(self, url):
        webbrowser.open(self.sanitize(url))

