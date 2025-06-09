# https://stackoverflow.com/questions/7689941/how-can-i-retrieve-the-tls-ssl-peer-certificate-of-a-remote-host-using-python

import ssl
import socket
import OpenSSL
from pprint import pprint
from datetime import datetime


def get_certificate(host, port=443, timeout=10):
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


certificate = get_certificate('https://gsl.noaa.gov')
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)

result = {
    'subject': dict(x509.get_subject().get_components()),
    'issuer': dict(x509.get_issuer().get_components()),
    'serialNumber': x509.get_serial_number(),
    'version': x509.get_version(),
    'notBefore': datetime.strptime(x509.get_notBefore(), '%Y%m%d%H%M%SZ'),
    'notAfter': datetime.strptime(x509.get_notAfter(), '%Y%m%d%H%M%SZ'),
}

extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
extension_data = {e.get_short_name(): str(e) for e in extensions}
result.update(extension_data)
pprint(result)

