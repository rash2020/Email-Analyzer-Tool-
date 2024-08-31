# email_analyzer/email_loader.py

class EmailLoader:
    def load_email_file(self, file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            return file.read()
