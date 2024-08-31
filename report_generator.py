from fpdf import FPDF

class ReportGenerator:
    def create_pdf_report(self, filename, app):
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        # Title
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="Email Analysis Report", ln=True, align='C')
        pdf.ln(10)

        # Section: Headers
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, txt="Headers", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, txt=app.tab_headers.get("1.0", "end-1c"))
        pdf.ln(5)

        # Section: Received Lines
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, txt="Received Lines", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, txt=app.tab_received_lines.get("1.0", "end-1c"))
        pdf.ln(5)

        # Section: X-Headers
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, txt="X-Headers", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, txt=app.tab_x_headers.get("1.0", "end-1c"))
        pdf.ln(5)

        # Section: Security
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, txt="Security", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, txt=app.tab_security.get("1.0", "end-1c"))
        pdf.ln(5)

        # Section: Attachments
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, txt="Attachments", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, txt=app.tab_attachments.get("1.0", "end-1c"))
        pdf.ln(5)

        # Section: Message URLs
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, txt="Message URLs", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, txt=app.tab_urls.get("1.0", "end-1c"))
        pdf.ln(5)

        # Section: Threat Intelligence
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, txt="Threat Intelligence", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, txt=app.tab_threat_intel.get("1.0", "end-1c"))
        pdf.ln(5)

        # Section: Body
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, txt="Body", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, txt=app.tab_body.get("1.0", "end-1c"))
        
        # Output the PDF to a file
        pdf.output(filename)

    def create_text_report(self, filename, app):
        with open(filename, "w", encoding="utf-8") as file:
            file.write("Email Analysis Report\n")
            file.write("="*40 + "\n\n")

            file.write("Headers\n")
            file.write(app.tab_headers.get("1.0", "end-1c") + "\n\n")

            file.write("Received Lines\n")
            file.write(app.tab_received_lines.get("1.0", "end-1c") + "\n\n")

            file.write("X-Headers\n")
            file.write(app.tab_x_headers.get("1.0", "end-1c") + "\n\n")

            file.write("Security\n")
            file.write(app.tab_security.get("1.0", "end-1c") + "\n\n")

            file.write("Attachments\n")
            file.write(app.tab_attachments.get("1.0", "end-1c") + "\n\n")

            file.write("Message URLs\n")
            file.write(app.tab_urls.get("1.0", "end-1c") + "\n\n")

            file.write("Threat Intelligence\n")
            file.write(app.tab_threat_intel.get("1.0", "end-1c") + "\n\n")

            file.write("Body\n")
            file.write(app.tab_body.get("1.0", "end-1c") + "\n")
