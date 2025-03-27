**PII Recon** is a Python GUI application built with Tkinter that leverages Microsoft Presidio Analyzer to scan files and folders for Personally Identifiable Information (PII). The application supports a wide range of file types from plain text and PDFs to images and common office documents—and allows you to add custom regex-based recognizers for additional PII patterns.

## Features

- **Presidio Integration:**  
  Uses Presidio's built-in AnalyzerEngine to detect PII entities such as names, phone numbers, email addresses, credit cards, etc.

- **Custom Recognizers:**  
  Easily add your own regex-based recognizers (for example, Aadhaar, PAN, GST) via the GUI.

- **Multi-Mode File Scanning:**  
  Select a single file, multiple files, or an entire folder (with recursive scanning) for analysis.

- **Wide File Type Support:**  
  Scans a variety of files including:  
  - Text files: `.txt`, `.csv`, `.json`, `.log`, `.xml`, `.html`, `.md`, etc.  
  - Code files: `.py`, `.java`, `.js`, `.ini`, etc.  
  - PDFs: `.pdf`  
  - Images: `.png`, `.jpg`, `.jpeg`, `.bmp`, `.tiff` (using OCR with EasyOCR)  
  - Office Documents: `.docx`, `.xlsx`, `.xls`, `.pptx` (and a note for `.ppt` conversion)

- **Line-by-Line Analysis:**  
  Extracts text from files line-by-line and analyzes each line for PII.

- **Live Progress & Logging:**  
  Features a progress bar and real-time log updates while scanning.

- **Export Results:**  
  Export your scan results to CSV or Excel for further review or processing.

## How It Can Be Useful

This application can help you:
- **Perform Data Privacy Audits:**  
  Quickly locate sensitive data within a large number of files.

- **Ensure Regulatory Compliance:**  
  Identify and mitigate the risk of exposing personal data in accordance with regulations such as GDPR or HIPAA.

- **Enhance Data Security:**  
  Find accidental leaks of sensitive PII in your organization’s document repository.

## Installation

### Prerequisites
- **Python 3.6+**

### Required Libraries

Install the required libraries using the provided `requirements.txt` file. Simply run:
pip install -r requirements.txt
