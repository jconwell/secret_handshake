import random
import string
from datetime import datetime, timedelta
from pathlib import Path
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
import asn1


"""
x509 extension documentation
https://www.openssl.org/docs/man1.0.2/man5/x509v3_config.html

I'm using nsComment, a deprecated extension to hold the message and an unknown extension OID to hold
the data payload.   

ASN.1 encoding: https://www.w3.org/Protocols/HTTP-NG/asn1.html

Example of creating an unrecognized extension
https://stackoverflow.com/questions/63809920/add-an-arbitrary-deprecated-extension-to-a-certificate-using-python-cryptography
https://github.com/pyca/cryptography/blob/3367c18bf2e71639843e38498f5ad2159835122d/tests/x509/test_x509.py#L3327

Data Exfiltration Key Size Performance Note:
During data exfiltration I'm getting about 
- 1.5 mb/sec with a 1024 bit key
- 0.4 mb/sec with a 2048 bit key
- slow-as-shit mb/sec with a 4096 bit key
"""


class Colors:
    # colors     = '\033[m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    PURPLE = '\033[35m'
    CYAN = '\033[36m'
    LIGHT_GREY = '\033[37m'
    GREY = '\033[90m'
    LIGHT_RED = '\033[91m'
    LIGHT_GREEN = '\033[92m'
    LIGHT_YELLOW = '\033[93m'
    LIGHT_BLUE = '\033[94m'
    LIGHT_PURPLE = '\033[95m'
    LIGHT_CYAN = '\033[96m'
    WHITE = '\033[97m'
    # formatting
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    ITALICS = '\033[3m'


def gen_msg_cert(cert_root_path, ca_cert, ca_key, subject, validity_end=80, msg=None, data=None, san_hosts=None):
    """ Generate a msg cert, signed by the root cert """

    data_len = 0
    if data:
        data_len = len(data)
    print(f"{Colors.LIGHT_PURPLE}Generating x509 cert with message '{msg}', data payload length {data_len}{Colors.ENDC}")

    cert_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    cert_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, subject["C"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject["ST"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, subject["L"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject["O"]),
        x509.NameAttribute(NameOID.COMMON_NAME, subject["CN"]),
    ])

    if san_hosts is None:
        san_hosts = get_san_hosts(subject['CN'])

    builder = (x509.CertificateBuilder()
               .subject_name(cert_subject)
               .issuer_name(ca_cert.subject)
               .public_key(cert_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(datetime.utcnow() - timedelta(days=10))
               .not_valid_after(datetime.utcnow() + timedelta(days=validity_end))
               .add_extension(get_san_ext(san_hosts), critical=False))

    if msg:
        builder = builder.add_extension(get_msg_ext(msg), critical=False)

    if data:
        builder = builder.add_extension(get_payload_ext(data), critical=False)

    cert = builder.sign(ca_key, hashes.SHA256(), default_backend())

    letters = string.ascii_lowercase
    cert_file = "".join([letters[random.randrange(0, len(letters))] for _ in range(random.randrange(10, 16))])
    msg_cert_path = f"{cert_root_path}/{cert_file}.pem"
    with open(msg_cert_path, 'wb') as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))

    msg_key_path = f"{cert_root_path}/{cert_file}.key"
    with open(msg_key_path, 'wb') as handle:
        handle.write(cert_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    return msg_cert_path, msg_key_path


def get_san_hosts(host):
    """ Create SAN list based on the host and a wildcard """
    return [host, f"*.{host}"]


def get_san_ext(hosts):
    """ Generate a SAN extension based on a host list """
    return x509.SubjectAlternativeName([x509.DNSName(host) for host in hosts])


def get_msg_ext(msg):
    """ Generate an nsComment extension to hold the message payload """
    encoder = asn1.Encoder()
    encoder.start()
    encoder.write(msg, nr=asn1.Numbers.IA5String)
    return x509.UnrecognizedExtension(
        x509.ObjectIdentifier("2.16.840.1.113730.1.13"),
        encoder.output())


def get_payload_ext(data_blob):
    """ Generate an unknown extension to hold the data payload """
    # add a data blob if needed
    if isinstance(data_blob, str):
        data_blob = data_blob.encode().hex()
    # elif isinstance(data_blob, bytes):
    #     data_blob = data_blob.hex().encode()
    encoder = asn1.Encoder()
    encoder.start()
    encoder.write(data_blob)
    return x509.UnrecognizedExtension(
        x509.ObjectIdentifier("1.2.643.5.1.8.666"),
        encoder.output())


def get_cert_msg(cert, bytes_2_text=True):
    """ Pull the message and data payload out of the cert """
    msg = None
    msg_data = None
    msg_data_len = 0
    for ext in cert.extensions:
        if ext.oid.dotted_string == "2.16.840.1.113730.1.13":
            # parse out the msg
            decoder = asn1.Decoder()
            decoder.start(ext.value.value)
            msg = decoder.read()
            msg = msg[1]
        elif ext.oid.dotted_string == "2.5.29.14":
            # get data bytes
            msg_data = ext.value.digest
        elif ext.oid.dotted_string == "1.2.643.5.1.8.666":
            # get data bytes
            decoder = asn1.Decoder()
            decoder.start(ext.value.value)
            msg_data = decoder.read()
            msg_data = msg_data[1]
            if bytes_2_text:
                msg_data = bytes.fromhex(msg_data).decode()
            msg_data_len = len(msg_data)
    if msg is None:
        print(f"{Colors.RED}WARN: no client msg found: {cert.extensions}{Colors.ENDC}")
    print(f"{Colors.LIGHT_PURPLE}Parsed x509 cert with message '{msg}', data payload length {msg_data_len}{Colors.ENDC}")
    return msg, msg_data


def init_cert_gen(gen_cert_path, ca_cert_path, ca_key_path, passphrase):
    Path(gen_cert_path).mkdir(parents=True, exist_ok=True)
    with open(ca_cert_path, 'rb') as handle:
        ca_cert_bytes = handle.read()
        ca_cert = cryptography.x509.load_pem_x509_certificate(ca_cert_bytes, backend=default_backend)
    with open(ca_key_path, 'rb') as handle:
        ca_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(handle.read(), password=passphrase)
    return ca_key, ca_cert
