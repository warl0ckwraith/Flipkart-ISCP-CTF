## What It Does
Built for Flipkart ISCP CTF Challenge, this script cleans sensitive data from a CSV file.

It reads a file where each row contains a JSON string and carefully scans this data for **Personally Identifiable Information (PII)** like:

- Phone numbers  
- Aadhar and Passport numbers  
- UPI IDs  
- Combinations of names, emails, and physical addresses that, when together, can identify a person  

After scanning, it generates a new, clean CSV file.  
In this file:
- All the sensitive information is masked (e.g., `98XXXXXX21` or `JXXX DXX`)  
- A new column `is_pii` tells you if we found anything sensitive in that row  

---

## How to Run It
You just need **Python 3** installed. Run the script from your terminal, passing the input CSV file as an argument.

```bash
python3 detector_sanidhya_soni.py iscp_pii_dataset.csv
```

## Deployment Plan

Check the file [Deployment.md](Deployment.md) for the deployment plan.

