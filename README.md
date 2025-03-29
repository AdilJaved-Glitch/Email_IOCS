# Email IOC Extractor

## Overview
The Email IOC Extractor is a Python tool designed to extract Indicators of Compromise (IOCs) from email files. It analyzes email headers and body content to extract IP addresses, URLs, email addresses, domains, Bitcoin addresses, and cryptographic hashes. Additionally, it extracts email attachments and generates their hash values.

## Features
- Extracts and defangs various IOCs:
  - IP addresses
  - URLs
  - Email addresses
  - Domains
  - Bitcoin addresses
  - MD5, SHA1, and SHA256 hashes
- Extracts email headers
- Extracts attachment metadata and calculates file hashes
- Outputs results in a clear and readable format

## Prerequisites
- Python 3.x

## Installation
Clone this repository and navigate to the project directory:
```bash
git clone https://github.com/yourusername/email-ioc-extractor.git
cd email-ioc-extractor
```

## Usage
Run the script with an email file:
```bash
python eiocs.py <email_file>
```
Example:
```bash
python eiocs.py sample_email.eml
```

## Output Example
```
Extracted Headers:
Date: Mon, 25 Mar 2024 12:34:56 +0000
Subject: Important Update
From: attacker@example.com

Extracted IOCs:
Ips:
  - 192[.]168[.]1[.]1
Urls:
  - hxxp://malicious[.]com/phishing
Emails:
  - attacker[@]example[.]com
Domains:
  - malicious[.]com

Extracted Attachments:
Filename: invoice.pdf
  MD5: 1a79a4d60de6718e8e5b326e338ae533
  SHA1: 356a192b7913b04c54574d18c28d46e6395428ab
  SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

## Contribution
Feel free to contribute by submitting issues or pull requests!
