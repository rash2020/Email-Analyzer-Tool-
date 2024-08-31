# Email Analyzer Tool

## Overview

The Email Analyzer Tool is a Python-based application designed to analyze `.eml` files. It provides functionalities to load, parse, and extract useful information from email files, such as headers, attachments, URLs, and security-related details. Additionally, the tool can generate reports based on the analyzed email content.

## Features

- **Email Loading**: Load email files in `.eml` format.
- **Email Parsing**: Parse email content, extract headers, received lines, x-headers, attachments, and URLs.
- **Security Analysis**: Perform security analysis on email components such as SPF, DKIM, and DMARC.
- **Threat Intelligence**: Analyze URLs for potential threats.
- **Report Generation**: Generate PDF or text reports summarizing the analysis.

## Components

### 1. `email_loader.py`
This module provides the functionality to load email files.

- `EmailLoader`: A class responsible for reading the content of an email file.

### 2. `email_parser.py`
This module is responsible for parsing the loaded email content and extracting relevant information.

- `EmailParser`: A class that provides methods to:
  - Parse email content into a structured format.
  - Extract headers, received lines, x-headers, attachments, and URLs.
  - Perform URL cleaning and phishing detection.
  - Extract the body of the email in plain text or HTML format.

### 3. `security_analyzer.py`
This module provides tools for analyzing the security aspects of an email, such as SPF, DKIM, and DMARC.

- `SecurityAnalyzer`: A class that offers methods to:
  - Analyze SPF, DKIM, and DMARC headers.
  - Extract the originating IP and rDNS from the email.
  - Provide threat intelligence based on the URLs found in the email.

### 4. `report_generator.py`
This module is used to generate reports in PDF or text format.

- `ReportGenerator`: A class that provides methods to generate detailed reports of the email analysis.

### 5. `main.py`
This is the main application file that initializes the GUI and handles the overall workflow.

- `EmailAnalyzerApp`: A class that sets up the main GUI, handles file loading, email analysis, and report generation.

## Dependencies

- Python 3.x
- `tkinter`: For the GUI.
- `fpdf`: For generating PDF reports.
- `whois`: For performing WHOIS lookups in threat intelligence.
- `BeautifulSoup`: For parsing HTML content within emails (optional but recommended).

## Installation

To use this tool, clone the repository and install the required dependencies using pip:

```bash
git clone https://github.com/rash2020/Email-Analyzer-Tool-.git
cd Email-Analyzer-Tool-
pip install -r requirements.txt
```

## Installation
Usage
Run the main application:

```bash
python main.py
```

Use the GUI to load .eml files, analyze them, and generate reports.  

## License   

This project is licensed under the MIT License - see the LICENSE file for details.

