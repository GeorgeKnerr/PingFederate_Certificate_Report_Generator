#!/usr/bin/env python3

import logging
import logging.handlers
import requests
from requests.auth import HTTPBasicAuth
import json
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime
import argparse
import getpass
import signal
import os
import sys

ca_cert_file = '<path_to_ca_certificate_pem_file>'
todays_data_time = datetime.datetime.now()
data_sorted = []
data_sorted_csv = "Days_to_Expire,Expires,SerialNumber,Common Name,Organizational Unit,Organization,Locality,State,Country,Connection_Name\n"
right_now = datetime.datetime.now()
file_time = right_now.strftime("%Y%m%d-%H%M%S")
todays_datetime_stamp = right_now.strftime("%m-%d-%Y %H:%M:%S")

def check_ca_cert_file():
    if not os.path.isfile(ca_cert_file):
        print(f"Error: CA certificate file not found at {ca_cert_file}")
        print("Please check the path and ensure the file exists.")
        sys.exit(1)

def handle_sigint(signal, frame):
    print("\nPassword prompt interrupted. Exiting...")
    exit(0)

def retrieve_pingfed_credentials():
    global pingfederate_password
    signal.signal(signal.SIGINT, handle_sigint)
    try:
        while True:
            pingfederate_password = getpass.getpass(f"Enter the {pingfederate_username} password: ")
            if pingfederate_password:
                break
            else:
                print("Password cannot be empty. Please try again.")
    except EOFError:
        print("\nPassword prompt interrupted. Exiting...")
        exit(0)

def parse_args():
    parser = argparse.ArgumentParser(
        description="PingFederate Certificate Expiration Report Generator",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "cert_type",
        choices=["signing", "sslserver", "ca", "sp"],
        help="Certificate type to report on:\n"
             "  signing   - SSO signing certificates\n"
             "  sslserver - SSL server certificates\n"
             "  ca        - CA certificates\n"
             "  sp        - SP connection certificates"
    )
    parser.add_argument(
        "pingfederate_url",
        help="PingFederate API URL\n"
             "Example: https://<PingFed Admin URL>:9999/pf-admin-api/v1/"
    )
    parser.add_argument(
        "pingfederate_username",
        help="PingFederate API username"
    )
    parser.add_argument(
        "admin_email",
        help="One or more comma-separated admin email addresses"
    )
    parser.add_argument(
        "output_type",
        choices=["both", "text", "csv"],
        help="Type of file attachment(s) to include in the email:\n"
             "  both - Include both text and CSV attachments\n"
             "  text - Include only the text attachment\n"
             "  csv  - Include only the CSV attachment"
    )

    args = parser.parse_args()

    # Make the parsed arguments globally available
    global cert_type, pingfederate_url, pingfederate_username, admin_email, output_type
    cert_type = args.cert_type
    pingfederate_url = args.pingfederate_url
    pingfederate_username = args.pingfederate_username
    admin_email = args.admin_email
    output_type = args.output_type

def get_subject_endpoint(cert_type):
    # Make the parsed arguments globally available
    global subject, pingfederate_endpoint
    if cert_type == "signing":
        pingfederate_endpoint = "keyPairs/signing"
    elif cert_type == "sslserver":
        pingfederate_endpoint = "keyPairs/sslServer"
    elif cert_type == "ca":
        pingfederate_endpoint = "certificates/ca"
    elif cert_type == "sp":
        pingfederate_endpoint = "idp/spConnections"
    
    subject = "PingFederate " + cert_type.upper() + " Certificates Expiration Report (" + todays_datetime_stamp + ")"

def get_certificates():
    """
    Retrieves a list of certificates from PingFederate using the PF Admin API.

    Returns:
    A tuple containing a list of certificate dictionaries and a requests Session object.
    """
    certificates = []
    session = requests.Session()
    session.auth = HTTPBasicAuth(pingfederate_username, pingfederate_password)
    session.headers.update({'X-XSRF-Header': 'PingFederate'})
    session.verify = ca_cert_file

    try:
        response = session.get(pingfederate_url + pingfederate_endpoint)
        response.raise_for_status()
        certificates = response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to retrieve certificates: {e}")
        raise SystemExit(e)
    
    # Assign a variable the dictionary certificates key and values in pretty format
    pretty_certificates = json.dumps(certificates, indent=4, sort_keys=True)

    # Process certificates based on cert_type
    if cert_type == "sp":
        data_sorted = process_sp_connections(certificates)
    else:
        # Sort dictionary data by expires
        data_sorted = sorted(certificates['items'], key=lambda k: k['expires'])

    # Add days_to_expire to each certificate
    todays_date = datetime.datetime.utcnow()
    for item in data_sorted:
        expires = datetime.datetime.fromisoformat(item['expires'].rstrip('Z'))
        days_to_expire = (expires - todays_date).days
        item['days_to_expire'] = days_to_expire

    return data_sorted, pretty_certificates

def process_sp_connections(sp_connections):
    """
    Process SP connections to extract certificate information.
    """
    certificates = []
    for connection in sp_connections['items']:
        for cert in connection['credentials']['certs']:
            cert_info = cert['certView']
            cert_info['connection_name'] = connection['name']
            certificates.append(cert_info)
    
    return sorted(certificates, key=lambda k: k['expires'])

def create_html_body(data_sorted, subject):
        # Add the HTML body of the message
        html_body = r''''\
        <html>
          <head>
            <style>
              h1 {
                text-align: center;
                font-size: 30px;
                font-family: Arial, sans-serif;
                border-bottom: 2px solid #333;
                padding-bottom: 10px;
              }
            </style>
          </head>
        '''
        html_body += f"""\
          <body>
            <h1>{subject}</h1>
            <table style="border-collapse: collapse; border: 1px solid black;">
              <thead>
                <tr style="border: 1px solid black;">
                  <th style="padding: 3px;border: 1px solid black;">Days_to_Expire</th>
                  <th style="padding: 3px;border: 1px solid black;">Expires</th>
                  <th style="padding: 3px;border: 1px solid black;">Serial Number</th>
                  <th style="padding: 3px;border: 1px solid black;">Subject DN</th>
                  <th style="padding: 3px;border: 1px solid black;">Status</th>
                  <th style="padding: 3px;border: 1px solid black;">Connection Name</th>
                </tr>
              </thead>
              <tbody>
        """
        for item in data_sorted:
            html_body += f"""\
                <tr style="border: 1px solid black;">
                  <td style="text-align:center;padding: 3px;border: 1px solid black;">{item['days_to_expire']}</td>
                  <td style="padding: 3px;border: 1px solid black;">{item['expires']}</td>
                  <td style="padding: 3px;border: 1px solid black;">{item['serialNumber']}</td>
                  <td style="padding: 3px;border: 1px solid black;">{item['subjectDN']}</td>
                  <td style="padding: 3px;border: 1px solid black;">{item['status']}</td>
                  <td style="padding: 3px;border: 1px solid black;">{item.get('connection_name', 'N/A')}</td>
                </tr>
            """
        html_body += """\
              </tbody>
            </table>
          </body>
        </html>
        """
        return html_body

def email_report(to, subject, html_body,
                  pretty_certificates, csv_certificates, cert_type, sendmail_path='/usr/sbin/sendmail'):
    try:
        # Create the message object
        message = MIMEMultipart()
        message['To'] = to
        message['Subject'] = subject

        # Add the body of the message
        message.attach(MIMEText(html_body, 'html'))

        # Add attachments based on output_type
        if output_type in ['both', 'text']:
            pretty_attachment = MIMEText(pretty_certificates, _subtype='plain')
            pretty_attachment.add_header('content-disposition', 'attachment', filename=f"{file_time}_{cert_type}_certificates.txt")
            message.attach(pretty_attachment)

        if output_type in ['both', 'csv']:
            csv_attachment = MIMEText(csv_certificates, _subtype='csv')
            csv_attachment.add_header('content-disposition', 'attachment', filename=f"{file_time}_{cert_type}_certificates.csv")
            message.attach(csv_attachment)

        # Send the message with verbose logging to stdout
        with subprocess.Popen([sendmail_path, '-t', '-oi'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as p:
            mta_output, mta_error = p.communicate(message.as_bytes())
            if mta_output:
              print(f"Sendmail output:\n{mta_output.decode('utf-8')}")
            if mta_error:
                print(f"Sendmail error:\n{mta_error.decode('utf-8')}")

        return True
    except Exception as e:
        # Chain the original exception to the new exception
        raise Exception(f"Error sending email: {e}") from e

# Main execution
if __name__ == "__main__":
    check_ca_cert_file()
    parse_args()
    retrieve_pingfed_credentials()
    get_subject_endpoint(cert_type)
    data_sorted, pretty_certificates = get_certificates()

    for item in data_sorted:
        connection_name = item.get('connection_name', 'N/A')
        data_sorted_csv += f"{item['days_to_expire']},{item['expires']},{item['serialNumber']},{item['subjectDN']},{item['status']},{connection_name}\n"

    html_body = create_html_body(data_sorted, subject)
    csv_certificates = data_sorted_csv
    sendmail_path = "/usr/sbin/sendmail"

    email_report(to=admin_email, subject=subject, html_body=html_body, pretty_certificates=pretty_certificates,
                  csv_certificates=csv_certificates, cert_type=cert_type, sendmail_path=sendmail_path)

    print(f"Certificate expiration report for {cert_type} has been generated and sent to {admin_email}.")