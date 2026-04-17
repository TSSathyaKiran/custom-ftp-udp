import socket
import ssl
import os
import hashlib

SERVER_IP = "192.168.0.118"
TCP_PORT = 5003
CHUNK_SIZE = 1024

CERT = "server.crt"  # Server's certificate for verification


def get_hash(filename):
    h = hashlib.sha256()
    with open(filename, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()


filename = input("enter filename: ")

offset = 0
if os.path.exists(filename):
    offset = os.path.getsize(filename)
    print(f"[CLIENT] continue from {offset}")


context = ssl.create_default_context()
context.load_verify_locations(CERT)   # Verify server against known cert
context.check_hostname = False
context.verify_mode = ssl.CERT_REQUIRED   # FIXED: was CERT_NONE
context.minimum_version = ssl.TLSVersion.TLSv1_2  # Enforce TLS 1.2+

tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
secure_sock = context.wrap_socket(tcp_sock)

secure_sock.connect((SERVER_IP, TCP_PORT))

secure_sock.send(f"GET {filename} {offset}".encode())


udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(("0.0.0.0", 0))

udp_port = udp_sock.getsockname()[1]
secure_sock.send(str(udp_port).encode())


meta = secure_sock.recv(1024).decode()
if meta == "ERROR":
    print("File not found")
    exit()

_, filesize, server_hash = meta.split()

mode = "ab" if offset > 0 else "wb"

with open(filename, mode) as f:
    expected_seq = offset // CHUNK_SIZE

    while True:
        packet, addr = udp_sock.recvfrom(CHUNK_SIZE + 50)

        if packet == b"END":
            print("[CLIENT] Done")
            break

        seq_str, chunk = packet.split(b"|", 1)
        seq = int(seq_str.decode())

        if seq == expected_seq:
            f.write(chunk)
            expected_seq += 1

        udp_sock.sendto(f"ACK {seq}".encode(), addr)


udp_sock.close()
secure_sock.close()

local_hash = get_hash(filename)

print("Server:", server_hash)
print("Local :", local_hash)

if local_hash == server_hash:
    print("[CLIENT] ok")
else:
    print("[CLIENT] corrupted")