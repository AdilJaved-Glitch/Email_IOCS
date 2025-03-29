import re
import sys
import hashlib
import ipaddress
from email.parser import BytesParser

def read_file(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
    parser = BytesParser()
    return parser.parsebytes(content)

def extract_iocs(email_message):
    iocs = {
        "ips": set(),
        "urls": set(),
        "emails": set(),
        "domains": set(),
        "btc_addresses": set(),
        "hashes": set()
    }
    
    patterns = {
        "ip": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "url": r'https?:\/\/(?:[\w\-]+\.)+[a-z]{2,}(?:\/[\w\-\.\/?%&=]*)?',
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "domain": r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        "btc": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "hash": r'\b[a-fA-F0-9]{32,64}\b'
    }
    
    for header_name, header_value in email_message.items():
        iocs["ips"].update(re.findall(patterns["ip"], header_value))
        iocs["emails"].update(re.findall(patterns["email"], header_value))
    
    for part in email_message.walk():
        if part.get_content_type() in ["text/plain", "text/html"]:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8", errors="ignore")
            
            for key, pattern in patterns.items():
                iocs.setdefault(key + "s", set()).update(re.findall(pattern, payload))
    
    iocs["ips"] = list(set([ip for ip in iocs["ips"] if validate_ip(ip)]))
    return iocs

def validate_ip(ip):
    try:
        return bool(ipaddress.ip_address(ip))
    except ValueError:
        return False

def defang(text):
    return text.replace(".", "[.]").replace("http", "hxxp")

def extract_headers(email_message):
    headers_to_extract = ["Date", "Subject", "To", "From", "Reply-To", "Return-Path", "Message-ID"]
    return {key: email_message[key] for key in headers_to_extract if key in email_message}

def extract_attachments(email_message):
    attachments = []
    for part in email_message.walk():
        if part.get_content_maintype() == 'multipart' or not part.get_filename():
            continue
        
        filename = part.get_filename()
        data = part.get_payload(decode=True)
        attachments.append({
            "filename": filename,
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()
        })
    return attachments

def main(file_path):
    email_message = read_file(file_path)
    iocs = extract_iocs(email_message)
    headers = extract_headers(email_message)
    attachments = extract_attachments(email_message)
    
    print("\nExtracted Headers:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    
    print("\nExtracted IOCs:")
    for key, values in iocs.items():
        print(f"{key.capitalize()}: ")
        for value in values:
            print(f"  - {defang(value)}")
    
    if attachments:
        print("\nExtracted Attachments:")
        for attachment in attachments:
            print(f"Filename: {attachment['filename']}")
            print(f"  MD5: {attachment['md5']}")
            print(f"  SHA1: {attachment['sha1']}")
            print(f"  SHA256: {attachment['sha256']}")

def usage():
    print(f"Usage: python {sys.argv[0]} <file_path>")
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    main(sys.argv[1])
