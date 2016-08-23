#! /usr/local/bin/python
# ----------------------------------------------------------------------------------------------
#   Nessus Scan Launch API Python Wrapper
#   Utilizes the Nessus API to create and launch a basic network scan on a list of hosts.
# ----------------------------------------------------------------------------------------------

import requests
import json
import time
import argparse
from datetime import date
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import email.utils
import boto3
import csv
import logging
logging.basicConfig(level=logging.INFO)



ignored_instances = ['']


#   These args are used to define custom e-mail recipients, as well as the IP address for scanning.
def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('email', help='The E-mail address to send the results to')
    parser.add_argument('scanner_ip',
                        help='The IP address and port of the machine to connect to in order to scan.')
    parser.add_argument('sender', help='The sender e-mail address')
    parser.add_argument('smtp', help='The SMTP server for sending the e-mail')
    parser.add_argument('-c', '--credentials',
                        help='The path to the file containing API creds', default='./credentials.csv')
    parser.add_argument('region', help='The AWS region to connect to.')

    return_args = parser.parse_args()
    return return_args


def get_request_data(targets):
    data = {
        # This UUID is the UUID of the 'Basic Network Scan' template.
        'uuid': '731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65',
        'settings': {
            'description': 'A simple scan to run on AWS instances',
            'launch': 'ON_DEMAND',
            'scanner_id': '1',
            'name': 'AWS Instance Scan',
            'text_targets': targets,
            'folder_id': '45',
            'enabled': 'false'
        }
    }
    return data


#   Returns the list of scans as parsed from the JSON.
def get_scans(head, ip):
    scan_ip = ip + 'scans'
    print scan_ip
    list_scans = requests.get(scan_ip, headers=head, verify=False)
    scans = json.loads(list_scans.text)
    return scans['scans']


#   Returns the list of private IP addresses for EC2 instances in our VPC
def get_targets(conn):
    targets_list = []
    print 'Getting instances.'
    all_instances = conn.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    # all_instances = conn.instances.all()
    # for x in all_instances:
    #     print x.instance_name
    for inst in all_instances:
        for tag in inst.tags:
            if tag['Key'] == 'Name':
                inst_name = tag['Value']
        if inst_name not in ignored_instances:
            targets_list.append(inst.private_ip_address)
            print inst_name
    all_targets = ', '.join(targets_list)
    print all_targets
    return all_targets


def perform_scan(wait, args, conn):
    scan_ip = 'https://' + args.scanner_ip + '/'
    alert_email = args.email
    targets = get_targets(conn)
    try:
        with open(args.credentials, 'rb') as csvfile:
            csv_read = csv.reader(csvfile)
            for row in csv_read:
                api_creds = 'accessKey=' + row[0] + '; secretKey=' + row[1]
    except IOError:
        print 'Cannot find API keys file.  Exiting.'
        exit()
    req_headers = {'Content-type': 'application/json', 'Accept': 'text/plain', 'X-APIKeys': api_creds}

    #   Searches to see if our scan already exists; otherwise, builds a new scan.
    for scan in get_scans(req_headers, scan_ip):
        test_scan_name = scan['name']
        if test_scan_name == 'AWS Instance Scan':
            print 'Scan already exists, launching...'
            break
    else:
        request_data = get_request_data(targets)
        launchreq = requests.post(scan_ip + 'scans', headers=req_headers, json=request_data, verify=False).text
        if 'error' in json.loads(launchreq):
            print 'Error in creating scan, exiting...'
            print launchreq
            exit()

    # Builds the URI to call the API endpoint of the scan we want
    scan_uri = None
    for scan_list in get_scans(req_headers, scan_ip):
        scan_name = scan_list['name']
        if scan_name == 'AWS Instance Scan':
            scan_id = scan_list['id']
            scan_uri = scan_ip + 'scans/' + str(scan_id)

    #   If our scan isn't already running, launch it.
    scan_status = json.loads(requests.get(scan_uri, headers=req_headers, verify=False).text)['info']['status']
    if scan_status != 'running':
        launch_url = scan_uri + '/launch'
        requests.post(launch_url, headers=req_headers, verify=False)

    #   Wait until the scan is complete.
    for n in range(wait):
        updatescans = get_scans(req_headers, scan_ip)
        scan = None
        for update in updatescans:
            if update['id'] == scan_id:
                scan = update
        if scan['status'] == 'completed':
            break
        elif scan['status'] == 'stopped' or scan['status'] == 'cancelled':
            print 'Scan stopped unexpectedly.  Exiting...'
            exit()
        print 'Scan in progress, waiting...'
        time.sleep(60)
    print 'Scan complete, downloading results...'

    #   Getting the results of a scan is based on the scan history.  Gets the history ID of the last-run scan.
    scan_hist = requests.get(scan_uri, headers=req_headers, verify=False)
    hist_json = json.loads(scan_hist.text)
    hist_id = hist_json['history'][-1]['history_id']

    #   Builds the URI for the export API endpoint and requests the data export
    export_uri = scan_uri + '/export?history_id=' + str(hist_id)
    export_scan = requests.post(export_uri, headers=req_headers,
                                json={
                                        'format': 'html',
                                        'chapters': 'vuln_hosts_summary;vuln_by_host;remediations'
                                }, verify=False)
    result = json.loads(export_scan.text)
    file_id = result['file']

    #   Waits until the export of the scan result is ready to download.
    while True:
        filestatus = requests.get(scan_uri + '/export/' + str(file_id) + '/status', verify=False, headers=req_headers)
        status = json.loads(filestatus.text)
        if status['status'] == 'ready':
            break
        elif status['status'] == 'error':
            print 'Error in exporting.'
            exit()
        print 'status: ' + status['status']
        time.sleep(10)

    #   Download the HTML results file
    get_res_url = scan_uri + '/export/' + str(file_id) + '/download'
    get_res = requests.get(get_res_url, headers=req_headers, verify=False).text

    cur_date = date.today()

    #   Builds the subject/body of the message.
    msg = MIMEMultipart()
    body = 'Nessus scan results for ' + str(cur_date)
    msg['To'] = email.utils.formataddr(('Security', alert_email))
    msg['From'] = email.utils.formataddr(('Nessus Scan Alerts', args.sender))
    msg['Subject'] = 'Nessus Scan Results ' + str(cur_date)
    msg.attach(MIMEText(body, 'plain'))

    #   Attaches the HTML attachment to the e-mail.
    output = get_res.encode('utf8')
    part = MIMEText(output)
    part.add_header('Content-Disposition', 'attachment; filename= %s' % ('nessus-' + str(cur_date) + '.html'))
    msg.attach(part)

    #   Sends the e-mail.
    smtp_obj = smtplib.SMTP(args.smtp, 25)
    smtp_obj.sendmail(args.sender, alert_email, msg.as_string())
    smtp_obj.quit()

if __name__ == '__main__':
    inst_args = parse()
    connect = boto3.resource('ec2', region_name=inst_args.region)
    perform_scan(90, inst_args, connect)


