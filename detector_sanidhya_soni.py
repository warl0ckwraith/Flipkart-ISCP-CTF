#!/usr/bin/env python3

"""
Author: Sanidhya Soni [sanidhyasoni02@gmail.com]
"""

import csv
import json
import re
import sys

class PIIDetectorMasker:
    def __init__(self):
        # --- Regular Expressions ---
        self.phone_regex = re.compile(r'(?:\+91[-\s]?|91[-\s]?|\(0\))?\d{10}\b')
        self.aadhar_regex = re.compile(r'\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{12})\b')
        self.passport_regex = re.compile(r'\b[A-Z]\d{7}\b')
        self.upi_regex = re.compile(r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9]+\b')
        self.email_regex = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}\b')
        self.full_name_regex = re.compile(r'^[A-Za-z]+\s+[A-Za-z]+.*$')

        self.address_indicators = {
            'street', 'road', 'rd', 'st', 'avenue', 'ave', 'lane', 'ln', 'block', 
            'apt', 'apartment', 'floor', 'building', 'house', 'complex', 'nagar', 
            'colony', 'society', 'vihar', 'enclave', 'sector', 'phase', 'chawl', 
            'marg', 'bagh', 'gali', 'galli', 'chowk', 'layout', 'puram', 'puri', 
            'wadi', 'wada', 'pada', 'village', 'gram', 'gaon'
        }
        
        self.standalone_rules = [
            {'type': 'email', 'detector': self.is_email, 'masker': self.mask_email},
            {'type': 'upi', 'detector': self.is_upi_id, 'masker': self.mask_upi},
            {'type': 'phone', 'detector': self.phone_regex.search, 'masker': self.mask_phone},
            {'type': 'passport', 'detector': self.passport_regex.match, 'masker': self.mask_passport},
        ]


        self.raw_string_rules = [
            (self.email_regex, self.is_email, self.mask_email),
            (self.upi_regex, self.is_upi_id, self.mask_upi),
            (self.aadhar_regex, lambda s: len(re.sub(r'\D', '', s)) == 12, self.mask_aadhar),
            (self.phone_regex, lambda s: True, self.mask_phone),
            (self.passport_regex, lambda s: True, self.mask_passport),
        ]

    def is_upi_id(self, value):
        return bool(self.upi_regex.match(value))

    def is_email(self, value):
        return bool(self.email_regex.match(value))

    def is_full_name(self, value):
        if not isinstance(value, str):
            return False
        words = value.strip().split()
        return len(words) >= 2 and all(word.replace('.', '').isalpha() for word in words if word)

    def is_address(self, value):
        if not isinstance(value, str):
            return False
        value_lower = value.lower()
        words = value.split()
        if len(words) < 3:
            return False
        has_indicator = any(indicator in value_lower for indicator in self.address_indicators)
        has_numbers = any(char.isdigit() for char in value)
        return (has_indicator and has_numbers) or (has_numbers and ',' in value and len(words) >= 4)

    def _mask_username_part(self, username):
        return 'XX' if len(username) <= 2 else username[:2] + 'X' * (len(username) - 2)

    def mask_phone(self, phone_str):
        digits = re.sub(r'\D', '', phone_str)
        if len(digits) >= 10:
            core_digits = digits[-10:]
            return f"{core_digits[:2]}XXXXXX{core_digits[-2:]}"
        return phone_str

    def mask_email(self, email_str):
        if '@' not in email_str:
            return email_str
        username, domain = email_str.split('@', 1)
        return f"{self._mask_username_part(username)}@{domain}"

    def mask_upi(self, upi_str):
        if '@' not in upi_str:
            return upi_str
        username, handle = upi_str.split('@', 1)
        return f"{self._mask_username_part(username)}@{handle}"

    def mask_aadhar(self, aadhar_str):
        digits = re.sub(r'\D', '', aadhar_str)
        if len(digits) == 12:
            masked_middle = 'XXXX'
            if ' ' in aadhar_str:
                return f"{digits[:4]} {masked_middle} {digits[-4:]}"
            if '-' in aadhar_str:
                return f"{digits[:4]}-{masked_middle}-{digits[-4:]}"
            return f"{digits[:4]}{masked_middle}{digits[-4:]}"
        return aadhar_str

    def mask_passport(self, passport_str):
        return passport_str[0] + 'XXX' + passport_str[4:] if len(passport_str) == 8 else passport_str

    def mask_name(self, name_str):
        words = name_str.strip().split()
        masked_words = [word[0].upper() + 'X' * (len(word) - 1) if len(word) > 1 else 'X' for word in words]
        return ' '.join(masked_words)

    def detect_standalone_pii(self, key, value):
        if not isinstance(value, str):
            return False, None, value
        value = value.strip()
        
        for rule in self.standalone_rules:
            if rule['detector'](value):
                return True, rule['type'], rule['masker'](value)

        if len(re.sub(r'\D', '', value)) == 12:
            return True, 'aadhar', self.mask_aadhar(value)
        
        return False, None, value

    def detect_combinatorial_elements(self, data):
        combinatorial_elements = {}
        for key, value in data.items():
            if not isinstance(value, str):
                continue
            
            key_lower = key.lower()
            value = value.strip()
            
            if 'name' in key_lower and self.is_full_name(value):
                combinatorial_elements['name'] = {'key': key, 'original': value, 'masked': self.mask_name(value)}
            elif key_lower == 'first_name' and 'last_name' in data and isinstance(data.get('last_name'), str):
                last_name = data.get('last_name', '').strip()
                if last_name:
                    combinatorial_elements['name_combo'] = {
                        'keys': ['first_name', 'last_name'],
                        'original': f"{value} {last_name}",
                        'masked_first': self.mask_name(value),
                        'masked_last': self.mask_name(last_name)
                    }
            elif self.is_email(value):
                combinatorial_elements['email'] = {'key': key, 'original': value, 'masked': self.mask_email(value)}
            elif self.is_address(value):
                combinatorial_elements['address'] = {'key': key, 'original': value, 'masked': '[REDACTED_ADDRESS]'}
            elif key_lower in ['ip_address', 'ip']:
                combinatorial_elements['ip_address'] = {'key': key, 'original': value, 'masked': '[REDACTED_IP]'}
            elif key_lower in ['device_id', 'device_identifier']:
                combinatorial_elements['device_id'] = {'key': key, 'original': value, 'masked': '[REDACTED_DEVICE_ID]'}
        
        return combinatorial_elements

    def process_json_string(self, json_str):
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:

            original_json = json_str
            for regex, checker, masker in self.raw_string_rules:
                matches_to_replace = {m for m in regex.findall(json_str) if checker(m)}
                for match in matches_to_replace:
                    json_str = json_str.replace(match, masker(match))
            return json_str, original_json != json_str

        masked_data = data.copy()
        standalone_pii_found = False
        
        for key, value in data.items():
            is_pii, _, masked_value = self.detect_standalone_pii(key, value)
            if is_pii:
                masked_data[key] = masked_value
                standalone_pii_found = True
        
        combinatorial_elements = self.detect_combinatorial_elements(data)
        combinatorial_pii_found = len(combinatorial_elements) >= 2
        
        if combinatorial_pii_found:
            for element_type, element_data in combinatorial_elements.items():
                if element_type == 'name_combo':
                    masked_data['first_name'] = element_data['masked_first']
                    masked_data['last_name'] = element_data['masked_last']
                else:
                    masked_data[element_data['key']] = element_data['masked']
        
        return json.dumps(masked_data), standalone_pii_found or combinatorial_pii_found

    def process_csv_file(self, input_file, output_file):
        try:
            with open(input_file, 'r', newline='', encoding='utf-8') as infile, \
                 open(output_file, 'w', newline='', encoding='utf-8') as outfile:
                
                reader = csv.reader(infile)
                writer = csv.writer(outfile)

                try:
                    header = next(reader)
                except StopIteration:
                    print("Error: Input file is empty", file=sys.stderr)
                    return False
                
                if len(header) < 2:
                    print("Error: Input file must have at least 2 columns (record_id, data_json)", file=sys.stderr)
                    return False
                
                writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])
                
                for row_num, row in enumerate(reader, start=2):
                    if len(row) < 2:
                        print(f"Warning: Skipping row {row_num} - insufficient columns", file=sys.stderr)
                        continue
                    
                    masked_json, is_pii = self.process_json_string(row[1])
                    writer.writerow([row[0], masked_json, is_pii])
                
                return True
                
        except FileNotFoundError:
            print(f"Error: Input file '{input_file}' not found", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Error processing file: {e}", file=sys.stderr)
            return False

    def print_summary(self, output_file):
        print("Processing complete.")
        print(f"Output file generated: {output_file}")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} iscp_pii_dataset.csv", file=sys.stderr)
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = "redacted_output_sanidhya_soni.csv"
    detector = PIIDetectorMasker()
    
    if detector.process_csv_file(input_file, output_file):
        detector.print_summary(output_file)
    else:
        print("Processing failed. Please check the input file and try again.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
