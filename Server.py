import socket
import ssl
import threading
import os
import hashlib

SERVER_IP = "0.0.0.0"
TCP_PORT = 5003
CHUNK_SIZE = 1024

CERT = "server.crt"
KEY = "server.key"


def get_hash(filename):
    h = hashlib.sha256()
    with open(filename, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()


def udp_transfer(filename, offset, client_ip, client_port):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    with open(filename, "rb") as f:
        f.seek(offset)
        seq = offset // CHUNK_SIZE

        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            packet = f"{seq}|".encode() + chunk

            while True:
                udp_sock.sendto(packet, (client_ip, client_port))

                try:
                    udp_sock.settimeout(1)
                    ack, addr = udp_sock.recvfrom(1024)

                    if addr[0] != client_ip:
                        continue

                    if ack.decode() == f"ACK {seq}":
                        break

                except socket.timeout:
                    print(f"[UDP] resend {seq}")

            seq += 1

    udp_sock.sendto(b"END", (client_ip, client_port))
    udp_sock.close()


def handle_client(conn, addr):
    print(f"[TCP] Connected {addr}")

    try:
        data = conn.recv(1024).decode()
        cmd, filename, offset = data.split()
        offset = int(offset)

        if not os.path.exists(filename):
            conn.send(b"ERROR")
            return

        filesize = os.path.getsize(filename)
        filehash = get_hash(filename)

        udp_port = int(conn.recv(1024).decode())

        meta = f"META {filesize} {filehash}"
        conn.send(meta.encode())

        udp_transfer(filename, offset, addr[0], udp_port)

    finally:
        conn.close()
        print(f"[TCP] Closed {addr}")


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT, keyfile=KEY)
context.minimum_version = ssl.TLSVersion.TLSv1_2  # Enforce TLS 1.2+

tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sock.bind((SERVER_IP, TCP_PORT))
tcp_sock.listen(5)

print(f"[SERVER] listening on {TCP_PORT}")

while True:
    client_sock, addr = tcp_sock.accept()
    secure_conn = context.wrap_socket(client_sock, server_side=True)

    threading.Thread(
        target=handle_client,
        args=(secure_conn, addr),
        daemon=True
    ).start()