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
from hashlib import sha1, sha256
import datetime
import requests
from urllib.parse import urlparse, quote
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

    region = creds.get('region', 'us-east-1')
    return creds['endpoint'], creds['access_key'], creds['secret_key'], region

def _sign_v2(access_key, secret_key, request_path, host):
    """AWS Signature Version 2 (legacy)."""
    my_date = datetime.datetime.utcnow().strftime("%a, %d %h %Y %T +0000")
    query_loc = request_path.find('?')
    string_to_sign = f"GET\n\n\n{my_date}\n{request_path[:query_loc]}".encode("UTF-8")
    signature = base64.b64encode(
        hmac.new(secret_key.encode("UTF-8"), string_to_sign, sha1).digest()
    ).strip()
    return {
        'Authorization': f"AWS {access_key}:{signature.decode()}",
        'Date': my_date,
    }

def _sign_v4(access_key, secret_key, region, request_path, host):
    """AWS Signature Version 4."""
    now = datetime.datetime.utcnow()
    datestamp = now.strftime('%Y%m%d')
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    service = 's3'
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"

    # Split path and query string
    query_loc = request_path.find('?')
    if query_loc >= 0:
        canonical_uri = quote(request_path[:query_loc], safe='/')
        raw_qs = request_path[query_loc + 1:]
        qs_pairs = sorted(p.split('=', 1) if '=' in p else (p, '')
                          for p in raw_qs.split('&'))
        canonical_querystring = '&'.join(
            f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in qs_pairs
        )
    else:
        canonical_uri = quote(request_path, safe='/')
        canonical_querystring = ''

    payload_hash = sha256(b'').hexdigest()
    signed_headers = 'host;x-amz-content-sha256;x-amz-date'
    canonical_headers = (
        f"host:{host}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )

    canonical_request = (
        f"GET\n{canonical_uri}\n{canonical_querystring}\n"
        f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )

    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
        f"{sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    def _hmac_sha256(key, msg):
        return hmac.new(key, msg.encode('utf-8'), sha256).digest()

    signing_key = _hmac_sha256(
        _hmac_sha256(
            _hmac_sha256(
                _hmac_sha256(f"AWS4{secret_key}".encode('utf-8'), datestamp),
                region),
            service),
        'aws4_request')

    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), sha256).hexdigest()

    return {
        'Authorization': (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
        'x-amz-date': amz_date,
        'x-amz-content-sha256': payload_hash,
    }

def make_request(endpoint, access_key, secret_key, request_path,
                 sig_version='v4', region='us-east-1'):
    parsed = urlparse(endpoint)
    host = parsed.netloc

    if sig_version == 'v2':
        headers = _sign_v2(access_key, secret_key, request_path, host)
    else:
        headers = _sign_v4(access_key, secret_key, region, request_path, host)

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
    parser.add_argument('--sig-version', default='v4', choices=['v2', 'v4'],
                        help='AWS signature version (default: v4)')
    parser.add_argument('--region', help='AWS region for SigV4 (default: us-east-1)')
    args = parser.parse_args()

    endpoint, access_key, secret_key, region = resolve_credentials(args)
    if args.region:
        region = args.region
    request_path = REQUESTS[args.request]
    make_request(endpoint, access_key, secret_key, request_path,
                 sig_version=args.sig_version, region=region)

if __name__ == '__main__':
    main()
