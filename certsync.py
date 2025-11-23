"""
certsync.py

This program fetches up to date X.509 certificate and private key from OPNsense firewall
with ACME client for synchronisation with local systems. The fetched certificate is then
bundled with the intermediate certificate chain. For now only Let's Encrypt certificates are
supported.

The program relies on OPNSense API https://docs.opnsense.org/development/how-tos/api.html
and requires API keys to be configured in OPNsense.

License: https://bigtimelicense.com/versions/2.0.2

Copyright 2025 by Paweł Krawczyk https://krvtz.net
"""

import argparse
import filecmp
import os.path
import shutil
import tempfile
from typing import Dict
import sys
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

KEY: str = os.environ.get("OPNSENSE_KEY")
SECRET: str = os.environ.get("OPNSENSE_SECRET")
API: str = os.environ.get("OPNSENSE_API")
VERIFY: bool = os.environ.get("OPNSENSE_VERIFY", "true").lower() == "true"

if not all((KEY, SECRET, API)):
    raise Exception("OPNSENSE_KEY, OPNSENSE_SECRET and OPNSENSE_API environment variables must be set")

SEARCH_API: str = f"{API}/api/trust/cert/search/"

# https://letsencrypt.org/certificates/
ANCHORS = {
    # Root
    'ISRG Root X1': 'https://letsencrypt.org/certs/isrgrootx1.pem',
    'ISRG Root X2': 'https://letsencrypt.org/certs/isrgrootx2.pem',
    'Root YE': 'https://letsencrypt.org/certs/gen-y/root-ye.pem',
    'Root YR': 'https://letsencrypt.org/certs/gen-y/root-yr.pem',
    # Intermediate
    'E7': 'https://letsencrypt.org/certs/2024/e7.pem',
    'E8': 'https://letsencrypt.org/certs/2024/e8.pem',
    'R12': 'https://letsencrypt.org/certs/2024/r12.pem',
    'R13': 'https://letsencrypt.org/certs/2024/r13.pem',
}


def sync_file(path: str, content: str) -> bool:
    """
    Checks if the file at path differs from the content, and if so, overwrites the file with the new content.
    Returns true if the file was updated, false otherwise.

    :param path:
    :param content:
    :return:
    """
    (t, p) = tempfile.mkstemp(suffix=".new")
    with os.fdopen(t, 'w') as tmp:
        tmp.write(content)
        tmp.close()

    write: bool = False

    # check if old private key file exists
    if not os.path.isfile(path):
        write = True
    else:
        # compare against the newly written private key
        if not filecmp.cmp(path, p):
            write = True

    if write:
        # overwrite old key with new key
        shutil.move(p, path)
        return True

    os.remove(p)
    return False


def get_issuer(issuer: str):
    try:
        url = ANCHORS[issuer]
    except KeyError:
        raise Exception(f"Unknown issuer: {issuer}")
    r = requests.get(url)
    if r.ok:
        return r.text
    else:
        raise Exception(f"Failed to fetch issuer {issuer}: {r.status_code}")


cli = argparse.ArgumentParser()
cli.add_argument("common_name", help="Common name of the certificate to fetch")
cli.add_argument("private_key", nargs="?", help="Private key file to write")
cli.add_argument("certificate", nargs="?", help="Certificate file to write")
args = cli.parse_args()

print(f"Using OPNsense: {SEARCH_API}")
print(f"Fetching certificate for {args.common_name}")

r = requests.get(SEARCH_API, auth=(KEY, SECRET), verify=VERIFY)
if not r.ok:
    raise Exception(f"Failed to access OPNSense API: {r.status_code}: {r.reason}")

certs: Dict = r.json()
exit_code : int = 0

for cert in certs['rows']:

    if args.common_name == cert['commonname']:
        print(f"Found {args.common_name}, fetching certificate and key")

        crt_payload = cert['crt_payload']
        prv_payload = cert['prv_payload']

        if args.private_key:
            print(f"Syncing private key {args.private_key}... ", end="")
            if sync_file(args.private_key, prv_payload):
                print("UPDATED")
                exit_code = 1
            else:
                print("unchanged")

        if args.certificate:
            print(f"Checking certificate issuer... ", end="")
            cert = x509.load_pem_x509_certificate(crt_payload.encode(), default_backend())
            issuer: str = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            print(issuer)
            print("Building certificate bundle...")
            if issuer in ANCHORS:
                issuer = get_issuer(issuer)
                bundle = crt_payload + issuer
                print(f"Syncing certificate bundle file {args.certificate}... ", end="")
                if sync_file(args.certificate, bundle):
                    print("UPDATED")
                    exit_code = 1
                else:
                    print("unchanged")
            else:
                raise Exception(f"Unknown issuer: {issuer}")

        break

sys.exit(exit_code)