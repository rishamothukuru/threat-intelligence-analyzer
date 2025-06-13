# Threat Intelligence Aggregator + Analyzer

A beginner-friendly Python script that collects basic threat data from public APIs like VirusTotal and AbuseIPDB to identify common cyber threats.  
It parses API responses and displays relevant threat info in a simple format.

## Features
- Collects threat data from VirusTotal and AbuseIPDB APIs  
- Parses and displays data cleanly  
- Easy to extend and customize

## Tech Used
- Python  
- Requests library  
- JSON parsing

## Usage
1. Add your API keys to the `.env` file  
2. Run the script:  
   ```bash
   python3 threat_analyzer.py
