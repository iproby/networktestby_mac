"""Verified HTTPS also works in bundles without an installed Python CA directory."""
import os
import ssl

import certifi


def https_context():
    context = ssl.create_default_context()
    # Honor explicit enterprise/custom trust settings. Some macOS Python builds
    # refer to a Python installation path that is absent on a clean native install.
    if not (os.environ.get('SSL_CERT_FILE') or os.environ.get('SSL_CERT_DIR')) and not context.cert_store_stats()['x509_ca']:
        context.load_verify_locations(cafile=certifi.where())
    return context
