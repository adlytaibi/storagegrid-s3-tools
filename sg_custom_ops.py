#!/usr/bin/env python3
#
# sg_custom_ops.py - StorageGRID custom S3 operations
#
# Author:   Adly Taibi
# Created:  2026-01-28
# Modified: 2026-05-06
#

import argparse
import base64
import configparser
import getpass
import hmac
import os
import sys
import xml.etree.ElementTree as ET
from hashlib import sha1
import datetime
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(SCRIPT_DIR, 'sg_custom_ops.conf')

REQUESTS = {
    'usage':                 '/?x-ntap-sg-usage',
    'consistency':           '/fabricpool?x-ntap-sg-consistency',
    'metadata-notification': '/fabricpool?x-ntap-sg-metadata-notification',
    'lastaccesstime':        '/fabricpool?x-ntap-sg-lastaccesstime',
}

def load_config(path):
    cfg = configparser.ConfigParser()
    cfg.read(path)
    if 'credentials' not in cfg:
        return {}
    return dict(cfg['credentials'])

def prompt_interactive(field, secret=False):
    if secret:
        return getpass.getpass(f"{field}: ")
    return input(f"{field}: ")

def resolve_credentials(args):
    """Resolve credentials from CLI args > config file > interactive prompt."""
    creds = {}

    # Layer 1: config file defaults
    config_path = args.config or DEFAULT_CONFIG
    if os.path.isfile(config_path):
        creds.update(load_config(config_path))

    # Layer 2: CLI args override
    if args.endpoint:
        creds['endpoint'] = args.endpoint
    if args.access_key:
        creds['access_key'] = args.access_key
    if args.secret_key:
        creds['secret_key'] = args.secret_key

    # Layer 3: prompt for anything still missing
    for field, secret in [('endpoint', False), ('access_key', False), ('secret_key', True)]:
        if field not in creds or not creds[field]:
            creds[field] = prompt_interactive(field, secret=secret)

    return creds['endpoint'], creds['access_key'], creds['secret_key']

def make_request(endpoint, access_key, secret_key, request_path):
    access_key_encoded = access_key.encode("UTF-8")
    secret_key_encoded = secret_key.encode("UTF-8")
    my_date = datetime.datetime.utcnow().strftime("%a, %d %h %Y %T +0000")
    query_loc = request_path.find('?')
    string_to_sign = f"GET\n\n\n{my_date}\n{request_path[:query_loc]}".encode("UTF-8")
    signature = base64.b64encode(
        hmac.new(secret_key_encoded, string_to_sign, sha1).digest()
    ).strip()
    headers = {
        'Authorization': f"AWS {access_key_encoded.decode()}:{signature.decode()}",
        'Date': f"{my_date}",
    }
    url = f"{endpoint}{request_path}"
    response = requests.get(url, headers=headers, verify=False, timeout=10)
    body = response.content.decode('UTF-8')
    print(f"Endpoint: {url}\n")
    try:
        root = ET.fromstring(body)
        format_xml(root)
    except ET.ParseError:
        print(body)

def humanize_bytes(n):
    for unit in ('B', 'KB', 'MB', 'GB', 'TB', 'PB'):
        if abs(n) < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} EB"

def strip_ns(tag):
    """Remove XML namespace prefix."""
    return tag.split('}', 1)[-1] if '}' in tag else tag

def format_xml(root):
    tag = strip_ns(root.tag)
    if tag == 'UsageResult':
        format_usage(root)
    elif tag in ('ConsistencyResult', 'MetadataNotificationResult',
                 'LastAccessTimeResult'):
        format_key_value(root)
    else:
        format_key_value(root)

def format_usage(root):
    calc_time = root.find('.//{*}CalculationTime')
    obj_count = root.find('.//{*}ObjectCount')
    data_bytes = root.find('.//{*}DataBytes')

    if calc_time is not None:
        print(f"Calculated:    {calc_time.text}")

    # Find top-level ObjectCount/DataBytes (direct children)
    ns = ''
    if '}' in root.tag:
        ns = root.tag.split('}')[0] + '}'
    top_obj = root.find(f'{ns}ObjectCount')
    top_data = root.find(f'{ns}DataBytes')
    if top_obj is not None:
        print(f"Total Objects: {int(top_obj.text):,}")
    if top_data is not None:
        raw = int(top_data.text)
        print(f"Total Size:    {humanize_bytes(raw)} ({raw:,} bytes)")

    buckets = root.findall('.//{*}Bucket')
    if buckets:
        print(f"\n{'Bucket':<30} {'Objects':>10} {'Size':>12}")
        print('-' * 54)
        for b in buckets:
            name = b.find('{*}Name').text
            count = int(b.find('{*}ObjectCount').text)
            size = int(b.find('{*}DataBytes').text)
            print(f"{name:<30} {count:>10,} {humanize_bytes(size):>12}")

def format_key_value(root):
    if len(root) == 0 and root.text:
        # Single-element response (e.g. <Consistency>value</Consistency>)
        print(f"{strip_ns(root.tag)}: {root.text}")
        return
    for child in root:
        tag = strip_ns(child.tag)
        label = ' '.join(
            w.capitalize() for w in
            ''.join(' ' + c if c.isupper() else c for c in tag).split()
        )
        print(f"{label + ':':<25} {child.text}")

def main():
    parser = argparse.ArgumentParser(
        description='StorageGRID custom S3 operations',
        epilog=f'Config file format (INI, default {DEFAULT_CONFIG}):\n'
               '  [credentials]\n'
               '  endpoint = https://host:10444\n'
               '  access_key = ...\n'
               '  secret_key = ...\n',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('-c', '--config', help=f'config file path (default: {DEFAULT_CONFIG})')
    parser.add_argument('-e', '--endpoint', help='StorageGRID S3 endpoint URL')
    parser.add_argument('-a', '--access-key', help='S3 access key')
    parser.add_argument('-s', '--secret-key', help='S3 secret key')
    parser.add_argument('-r', '--request', default='usage',
                        choices=REQUESTS.keys(),
                        help='operation to perform (default: usage)')
    args = parser.parse_args()

    endpoint, access_key, secret_key = resolve_credentials(args)
    request_path = REQUESTS[args.request]
    make_request(endpoint, access_key, secret_key, request_path)

if __name__ == '__main__':
    main()
