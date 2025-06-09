import os
from OpenSSL import crypto
from cryptography.x509 import load_pem_x509_certificate

bundle = "/opt/ssop/logindotgov/certs/demopy/bundle.pem"
private = "/opt/ssop/logindotgov/certs/demopy/private.pem"
public = "/opt/ssop/logindotgov/certs/demopy/public.crt"

with open(bundle) as bdl:
    bdl_str = bdl.read()
with open(private) as prv:
    private_str = prv.read()
with open(public) as pub:
    public_str = pub.read()
 
bdl_str = bdl_str.encode()
bdl_obj = load_pem_x509_certificate(bdl_str)

bundle_public_key = bdl_obj.public_key()  
print("bundle public_key: " + str(bundle_public_key))

#private_key = cert_obj.private_key()
#print("private_key: " + str(private_key))

