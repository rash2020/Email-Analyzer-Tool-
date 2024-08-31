# email_analyzer/main.py

from tkinter import Tk
from email_loader import EmailLoader
from email_parser import EmailParser
from security_analyzer import SecurityAnalyzer
from report_generator import ReportGenerator
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import threading

class EmailAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Analyzer Tool")
        self.root.geometry("1200x800")

        self.raw_email_content = ""

        self.email_loader = EmailLoader()
        self.email_parser = EmailParser()
        self.security_analyzer = SecurityAnalyzer()
        self.report_generator = ReportGenerator()

        self.create_main_frame()
        self.create_control_panel()
        self.add_app_info()
        self.create_tabs()

    def create_main_frame(self):
        self.main_frame = tk.Frame(self.root, bg="#f0f0f0")
        self.main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.title_label = tk.Label(self.main_frame, text="Email Analyzer Tool", font=("Arial", 16, "bold"), bg="#f0f0f0")
        self.title_label.grid(row=0, column=0, columnspan=4, pady=10, sticky="ew")

    def create_control_panel(self):
        self.control_panel_frame = tk.Frame(self.main_frame, bg="#f0f0f0")
        self.control_panel_frame.grid(row=1, column=0, columnspan=4, pady=5, sticky="ew")

        self.load_button = tk.Button(self.control_panel_frame, text="Load Email File", command=self.load_email_file, bg="#007BFF", fg="black", padx=10, pady=5, font=("Arial", 10, "bold"))
        self.load_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.analyze_button = tk.Button(self.control_panel_frame, text="Analyze Email", command=self.analyze_email, bg="#28a745", fg="black", padx=10, pady=5, font=("Arial", 10, "bold"))
        self.analyze_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.report_button = tk.Button(self.control_panel_frame, text="Generate Report", command=self.generate_report, bg="#17a2b8", fg="black", padx=10, pady=5, font=("Arial", 10, "bold"))
        self.report_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        self.progress = ttk.Progressbar(self.control_panel_frame, orient='horizontal', length=400, mode='indeterminate')
        self.progress.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        self.status_label = tk.Label(self.control_panel_frame, text="", font=("Arial", 10), bg="#f0f0f0", fg="red")
        self.status_label.grid(row=1, column=0, columnspan=4, pady=5, sticky="ew")

    def add_app_info(self):
        self.info_label = tk.Label(self.main_frame, text="This tool allows you to load and analyze .eml files, extract headers, attachments, and URLs, and generate a detailed report.",
                                   font=("Arial", 12), bg="#f0f0f0", fg="#333")
        self.info_label.grid(row=2, column=0, columnspan=4, pady=(5, 0), padx=10, sticky="ew")

    def create_tabs(self):
        self.notebook = ttk.Notebook(self.main_frame)
        self.tab_headers = tk.Text(self.notebook, wrap=tk.WORD)
        self.tab_received_lines = tk.Text(self.notebook, wrap=tk.WORD)
        self.tab_x_headers = tk.Text(self.notebook, wrap=tk.WORD)
        self.tab_security = tk.Text(self.notebook, wrap=tk.WORD)
        self.tab_attachments = tk.Text(self.notebook, wrap=tk.WORD)
        self.tab_urls = tk.Text(self.notebook, wrap=tk.WORD)
        self.tab_threat_intel = tk.Text(self.notebook, wrap=tk.WORD)
        self.tab_body = tk.Text(self.notebook, wrap=tk.WORD)

        self.notebook.add(self.tab_headers, text='Headers')
        self.notebook.add(self.tab_received_lines, text='Received Lines')
        self.notebook.add(self.tab_x_headers, text='X-Headers')
        self.notebook.add(self.tab_security, text='Security')
        self.notebook.add(self.tab_attachments, text='Attachments')
        self.notebook.add(self.tab_urls, text='Message URLs')
        self.notebook.add(self.tab_threat_intel, text='Threat Intelligence')
        self.notebook.add(self.tab_body, text='Body')

        self.notebook.grid(row=3, column=0, columnspan=4, pady=(0, 10), padx=10, sticky="nsew")

        self.main_frame.grid_rowconfigure(3, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

    def load_email_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Email files", "*.eml"), ("All files", "*.*")])
        if file_path:
            self.progress.start()
            threading.Thread(target=self._load_email_content, args=(file_path,)).start()

    def _load_email_content(self, file_path):
        try:
            self.raw_email_content = self.email_loader.load_email_file(file_path)
            messagebox.showinfo("File Loaded", "Email file has been loaded successfully.")
        except FileNotFoundError:
            messagebox.showerror("Error", "File not found. Please select a valid file.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load email file: {e}")
        finally:
            self.progress.stop()

    def analyze_email(self):
        if not self.raw_email_content:
            self.status_label.config(text="Please load an email file first.", fg="red")
            return
        self.progress.start()
        threading.Thread(target=self._perform_analysis).start()

    def _perform_analysis(self):
        try:
            self._clear_tabs()
            email_message = self.email_parser.parse_email_content(self.raw_email_content)

            self._display_headers(email_message)
            self._display_received_lines(email_message)
            self._display_x_headers(email_message)
            self._display_security_results(email_message)
            self._display_attachments(email_message)
            urls = self.email_parser.extract_urls(email_message)
            self._display_urls(urls)
            self._analyze_threat_intelligence(urls)
            self._display_body(email_message)

            self.root.after(100, lambda: self.status_label.config(text="Email analysis is complete.", fg="green"))
        except Exception as e:
            self.root.after(100, lambda: self.status_label.config(text=f"Failed to analyze email: {e}", fg="red"))
        finally:
            self.progress.stop()

    def _clear_tabs(self):
        for tab in [self.tab_received_lines, self.tab_x_headers, self.tab_security, self.tab_attachments, self.tab_urls, self.tab_threat_intel, self.tab_body]:
            tab.delete("1.0", "end")

    def _display_headers(self, email_message):
        headers_info = self.email_parser.extract_headers(email_message)
        header_text = "\n".join([f"{label}: {value}" for label, value in headers_info.items()])
        self.tab_headers.insert("1.0", header_text)

    def _display_received_lines(self, email_message):
        received_lines = self.email_parser.extract_received_lines(email_message)
        for i, line in enumerate(received_lines):
            formatted_line = self.email_parser.format_received_line(line, i)
            self.tab_received_lines.insert("end", formatted_line + "\n")

    def _display_x_headers(self, email_message):
        x_headers = self.email_parser.extract_x_headers(email_message)
        for k, v in x_headers.items():
            self.tab_x_headers.insert("end", f"**{k}:** {v}\n\n")

    def _display_attachments(self, email_message):
        attachments_info = self.email_parser.extract_attachments(email_message)
        for i, attachment in enumerate(attachments_info, start=1):
            self.tab_attachments.insert("end", f"**Attachment {i}:**\n")
            self.tab_attachments.insert("end", f"**File name:** {attachment['filename']}\n")
            self.tab_attachments.insert("end", f"**File type:** {attachment['content_type']}\n")
            self.tab_attachments.insert("end", f"**File size:** {attachment['file_size']} KB\n")
            self.tab_attachments.insert("end", f"**MD5:** {attachment['md5']}\n")
            self.tab_attachments.insert("end", f"**SHA-1:** {attachment['sha1']}\n")
            self.tab_attachments.insert("end", f"**SHA-256:** {attachment['sha256']}\n")
            vt_button = tk.Button(self.tab_attachments, text="Check on VirusTotal",
                                  command=lambda url=self.email_parser.generate_virustotal_url(attachment['md5']): self.email_parser.open_url(url),
                                  bg="#6c757d", fg="white", padx=5, pady=2)
            self.tab_attachments.window_create("end", window=vt_button)
            self.tab_attachments.insert("end", "\n\n")

    def _display_urls(self, urls):
        for url in urls:
            domain, path, scheme, port, query, phishing_warnings = self.email_parser.parse_and_clean_url(url)
            self.tab_urls.insert("end", f"**Domain:** {domain}\n")
            self.tab_urls.insert("end", f"**Path:** {path}\n")
            self.tab_urls.insert("end", f"**Scheme:** {scheme}\n")
            self.tab_urls.insert("end", f"**Port:** {port}\n")
            if query:
                self.tab_urls.insert("end", f"**Query:** {query}\n")
            self.tab_urls.insert("end", f"**URL:** {url}\n")
            if phishing_warnings:
                self.tab_urls.insert("end", f"**Phishing Warnings:** {phishing_warnings}\n")
            self.tab_urls.insert("end", "\n")

    def _display_security_results(self, email_message):
        security_result = self.security_analyzer.generate_security_results(email_message)
        self.tab_security.insert("1.0", security_result)

    def _display_body(self, email_message):
        self.tab_body.delete("1.0", "end")
        body_content = self.email_parser.extract_body(email_message)
        self.tab_body.insert("1.0", body_content)
        self.tab_body.yview_moveto(0)

    def _analyze_threat_intelligence(self, urls):
        threat_intel_info = self.security_analyzer.analyze_threat_intelligence(urls)
        self.tab_threat_intel.insert("1.0", threat_intel_info)

    def generate_report(self):
        if not self.raw_email_content:
            messagebox.showwarning("Warning", "Please analyze an email first.")
            return

        report_filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf"), ("Text files", "*.txt")])
        if not report_filename:
            return

        try:
            if report_filename.endswith(".pdf"):
                self.report_generator.create_pdf_report(report_filename, self)
            else:
                self.report_generator.create_text_report(report_filename, self)
            messagebox.showinfo("Report Generated", f"Report has been saved as {report_filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {e}")


if __name__ == "__main__":
    root = Tk()
    app = EmailAnalyzerApp(root)
    root.mainloop()
