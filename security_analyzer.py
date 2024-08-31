# email_analyzer/security_analyzer.py

import re
from whois import whois

class SecurityAnalyzer:
    def analyze_spf(self, spf_header):
        if "pass" in spf_header.lower():
            return "PASS", spf_header
        elif "fail" in spf_header.lower():
            return "FAIL", spf_header
        else:
            return "NEUTRAL", spf_header

    def analyze_dkim(self, dkim_header):
        if dkim_header != "None":
            if "pass" in dkim_header.lower():
                return "PASS", dkim_header
            elif "fail" in dkim_header.lower():
                return "FAIL", dkim_header
            else:
                return "NEUTRAL", dkim_header
        return "None", "No DKIM signature found."

    def analyze_dmarc(self, dmarc_header):
        if "dmarc=pass" in dmarc_header.lower():
            return "PASS", dmarc_header
        elif "dmarc=fail" in dmarc_header.lower():
            return "FAIL", dmarc_header
        else:
            return "NEUTRAL", dmarc_header

    def extract_originating_ip(self, email_message):
        originating_ip = "Unknown"
        received_headers = email_message.get_all('Received', [])

        for header in received_headers:
            ip_match = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', header)
            if ip_match:
                originating_ip = ip_match.group(1)
                break

        return originating_ip

    def extract_rdns(self, email_message):
        rdns = "Unknown"
        received_headers = email_message.get_all('Received', [])

        for header in received_headers:
            rdns_match = re.search(r'by\s+(\S+)\s+with', header)
            if rdns_match:
                rdns = rdns_match.group(1)
                break

        return rdns

    def generate_security_results(self, email_message):
        spf_result, spf_details = self.analyze_spf(email_message.get("Received-SPF", "None"))
        dkim_result, dkim_details = self.analyze_dkim(email_message.get("DKIM-Signature", "None"))
        dmarc_result, dmarc_details = self.analyze_dmarc(email_message.get("Authentication-Results", "None"))

        security_result = (
            f"**SPF Result:** {spf_result}\n"
            f"**Originating IP:** {self.extract_originating_ip(email_message)}\n"
            f"**rDNS:** {self.extract_rdns(email_message)}\n"
            f"**Return-Path domain:** {email_message.get('Return-Path', 'Unknown')}\n"
            f"**SPF Details:** {spf_details}\n\n"
            f"**DKIM Result:** {dkim_result}\n"
            f"**Verification(s):** {dkim_details}\n"
            f"**Selector:** {self.extract_dkim_selector(email_message.get('DKIM-Signature', ''))}\n"
            f"**Signing domain:** {self.extract_dkim_domain(email_message.get('DKIM-Signature', ''))}\n"
            f"**Algorithm:** rsa-sha256\n"
            f"**Verification:** {dkim_result}\n\n"
            f"**DMARC Result:** {dmarc_result}\n"
            f"**From domain:** {self.extract_from_domain(email_message)}\n"
            f"**DMARC Details:** {dmarc_details}\n"
        )

        return self.format_security_output(security_result)

    def format_security_output(self, result):
        formatted_result = ""
        for line in result.split("\n"):
            if "Result:" in line:
                formatted_result += f"\n\n{line}\n" + "-" * 50 + "\n"
            else:
                formatted_result += f"{line}\n"
        return formatted_result

    def extract_dkim_selector(self, dkim_header):
        match = re.search(r's=([^;]+)', dkim_header)
        return match.group(1) if match else "Unknown"

    def extract_dkim_domain(self, dkim_header):
        match = re.search(r'd=([^;]+)', dkim_header)
        return match.group(1) if match else "Unknown"

    def extract_from_domain(self, email_message):
        from_address = email_message.get("From", "")
        return from_address.split('@')[-1] if '@' in from_address else "Unknown"

    def analyze_threat_intelligence(self, urls):
        threat_intel_info = ""
        for url in urls:
            domain = url.split("//")[-1].split("/")[0]
            threat_intel_info += f"**Domain:** {domain}\n"
            threat_intel_info += "Reputation: Visit websites like VirusTotal, AbuseIPDB, or Whois.com for manual checks.\n"
            whois_result = self.perform_whois_lookup(domain)
            if whois_result:
                threat_intel_info += f"**WHOIS Information:**\n{whois_result}\n"
            else:
                threat_intel_info += "**WHOIS Information:** No data available\n"
            threat_intel_info += "-"*50 + "\n"
        return threat_intel_info

    def perform_whois_lookup(self, domain):
        try:
            whois_data = whois(domain)
            return "\n".join([f"{key}: {value}" for key, value in whois_data.items() if value])
        except Exception as e:
            return f"Error retrieving WHOIS data: {str(e)}"
