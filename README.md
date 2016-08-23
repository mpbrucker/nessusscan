# Nessus Scan Tools
Tools to automate running a Nessus scan in AWS.
## ScanTest.py
Automates the creating and launching of the Nessus scan.
Required arguments:
- **email:** The e-mail to which the scan results will be sent.
- **scanner_ip:** The IP address/port of the machine performing the scan. 
- **--sender:** The e-mail from which to send the scan results.
- **--smtp:** The SMTP server to use.
- **--credentials:** The path to the credentials file.  Default is ./credentials.csv
The credentials file should be a comma-separated one-line file with the format <apiKey>,<apiSecret>
