import cryptography
from cryptography.hazmat.backends import default_backend
from cert_gen import gen_msg_cert

"""
Utility file to play around with generating rando certs with whatever odd values you want 
"""

def main():
    passphrase = b'hackerman'
    cert_root_path = "certs/"
    ca_cert = f"{cert_root_path}/ca_certs/hmCA.pem"
    ca_key = f"{cert_root_path}/ca_certs/hmCA.key"

    output_path = "/path/to/some/dir"

    # default subject values
    subject = {
        "C": "US",
        "ST": "Washington",
        "L": "Seattle",
        "O": "Friendly Company LLC",
        "CN": "legit.friendly.company.com",
    }

    # testing cert gen with blank values. You have to override validation in the crypto lib while debugging but it works
    subject = {
        "C": "",
        "ST": "",
        "L": "",
        "O": "",
        "OU": "",
        "CN": "",
    }

    san_hosts = [
        "some-domain.com",
        "*.some-domain.com",
        "www.some-domain.com",
    ]

    # example SAN hosts for cPanel hosted domains
    # san_hosts = [
    #     "some-domain.com",
    #     "cpanel.some-domain.com",
    #     "cpcalendars.some-domain.com",
    #     "cpcontacts.some-domain.com",
    #     "mail.some-domain.com",
    #     "webdisk.some-domain.com",
    #     "webmail.some-domain.com",
    #     "autoconfig.some-domain.com",
    #     "autodiscover.some-domain.com",
    # ]

    with open(ca_cert, 'rb') as handle:
        ca_cert_bytes = handle.read()
        ca_cert = cryptography.x509.load_pem_x509_certificate(ca_cert_bytes, backend=default_backend)
    with open(ca_key, 'rb') as handle:
        ca_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(handle.read(), password=passphrase)

    gen_msg_cert(output_path, ca_cert, ca_key, subject, san_hosts=san_hosts, validity_end=10)


if __name__ == '__main__':
    main()
