import pickle
import socket

from Crypto.Signature import pkcs1_15

import utils
from structs import *

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256


req = "memo"
data = "take cis3319 class this morning"

def encrypt_server_ca_registration_request(dc: ServerCARegistrationRequest) -> bytes:
    serialized = pickle.dumps(dc)
    print("Serialized ServerCARegistrationRequest: " + serialized.hex())
    key = RSA.import_key(utils.Constants.PK_CA)
    cipher = PKCS1_OAEP.new(key)
    ct = cipher.encrypt(serialized)
    print("Encrypted ServerCARegistrationRequest: " + ct.hex())
    return ct

def decrypt_server_ca_registration_response(b: bytes, tmp_key: bytes) -> ServerCARegistrationResponse:
    cipher = DES.new(tmp_key, DES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(b), DES.block_size)
    print("Decrypted (but still serialized) ServerCARegistrationResponse: " + decrypted.hex())
    deserialized_res = pickle.loads(decrypted)
    print(dc_to_string(deserialized_res))
    # now ensure that the hash created from CERT_S_SERIALIZED can be verified
    pk = RSA.import_key(utils.Constants.PK_CA)
    h = SHA256.new(deserialized_res.CERT_S_SERIALIZED)
    try:
        pkcs1_15.new(pk).verify(h, deserialized_res.CERT_S_SIGNATURE)
        print("CERT_S_SIGNATURE matches!")
    except (ValueError, TypeError):
        raise Exception("CERT_S_SIGNATURE is invalid!")
    deserialized_cert = pickle.loads(deserialized_res.CERT_S_SERIALIZED)
    deserialized_res.CERT_S = deserialized_cert
    print(dc_to_string(deserialized_res))
    return deserialized_res

if __name__ == '__main__':
    # read key from file
    with open("ca_public.pem", "rb") as f:
        utils.Constants.PK_CA = f.read()

    # start server
    ca_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ca_sock.connect(('localhost', utils.Constants.PORT_CA))
    print("Server started and connected to CA. Generating registration request...")

    # send request to CA
    ca_request = ServerCARegistrationRequest(K_TMP1=utils.gen_key(8), ID_S=utils.Constants.ID_S,TS1=utils.get_time_stamp())
    print(dc_to_string(ca_request))
    ciphertext = encrypt_server_ca_registration_request(ca_request)
    ca_sock.send(ciphertext)
    print("Sent ServerCARegistrationRequest! Waiting for response...\n\n")

    # TODO: receive response (including cert) from CA and decrypt. verify cert authenticity
    recv = ca_sock.recv(4096)
    print("Received encrypted/serialized ServerCARegistrationResponse: " + recv.hex())
    server_ca_registration_response = decrypt_server_ca_registration_response(recv, ca_request.K_TMP1)

    # TODO: receive request from client

    # TODO: send response to client with PK_S, CERT_S, and TS4

    # TODO: receive from client (encrypted with RSA PK_S) K_TMP2, ID_C, IP_C, PORT_C, and TS5

    # TODO: send to client (encrypted with DES K_TMP2) K_SESS, LIFETIME_SESS, ID_C, TS6

    # TODO: receive from client (encrypted with DES K_SESS) req, TS7

    # TODO: send to client (encrypted with DES K_SESS) data. TS8