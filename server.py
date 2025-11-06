import pickle
import socket

from Crypto.Signature import pkcs1_15

import utils
from basic_socket import BasicSocket
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

def decrypt_client_server_reqeust2(b: bytes, rsa_key: bytes) -> ClientServerRequest2:
    serialized = PKCS1_OAEP.new(RSA.import_key(rsa_key)).decrypt(b)
    print("Serialized ClientServerRequest2: " + serialized.hex())
    dc = pickle.loads(serialized)
    print(dc_to_string(dc))
    return dc


def encrypt_client_server_response2(dc: ClientServerResponse2, tmp_key: bytes) -> bytes:
    serialized = pickle.dumps(dc)
    print("Serialized ClientServerResponse2: " + serialized.hex())
    cipher = DES.new(tmp_key, DES.MODE_ECB)
    encrypted = cipher.encrypt(pad(serialized, DES.block_size))
    print("Encrypted ClientServerResponse2: " + encrypted.hex())
    return encrypted

def decrypt_service_request(b: bytes, key: bytes) -> ServiceRequest:
    decrypted = unpad(DES.new(key, DES.MODE_ECB).decrypt(b), DES.block_size)
    print("Decrypted (but still serialized) ServiceRequest: " + decrypted.hex())
    dc = pickle.loads(decrypted)
    print(dc_to_string(dc))
    return dc

def encrypt_service_response(dc: ServiceResponse, key: bytes) -> bytes:
    serialized = pickle.dumps(dc)
    print("Serialized ServiceResponse: " + serialized.hex())
    encrypted = DES.new(key, DES.MODE_ECB).encrypt(pad(serialized, DES.block_size))
    print("Encrypted ServiceResponse: " + encrypted.hex())
    return encrypted

if __name__ == '__main__':
    # read key from file
    with open("ca_public.pem", "rb") as f:
        utils.Constants.PK_CA = f.read()

    # start server
    ca_sock = BasicSocket("localhost", utils.Constants.PORT_CA)
    ca_sock.connect()
    print("Server started and connected to CA. Generating registration request...")

    # send request to CA
    ca_request = ServerCARegistrationRequest(K_TMP1=utils.gen_key(8), ID_S=utils.Constants.ID_S,TS1=utils.get_time_stamp())
    print(dc_to_string(ca_request))
    ciphertext = encrypt_server_ca_registration_request(ca_request)
    ca_sock.send(ciphertext)
    print("Sent ServerCARegistrationRequest! Waiting for response...\n\n")

    # receive response (including cert) from CA and decrypt. verify cert authenticity
    recv = ca_sock.recv(4096)
    print("Received encrypted/serialized ServerCARegistrationResponse: " + recv.hex())
    server_ca_registration_response = decrypt_server_ca_registration_response(recv, ca_request.K_TMP1)
    print("Finished with server CA registration handshake. Waiting for client to connect...\n\n")

    # receive request from client
    client_sock = BasicSocket("localhost", utils.Constants.PORT_CLIENT)
    client_sock.listen()
    print("Client connected to server. Waiting for client request...")
    msg = client_sock.recv(4096)
    print("Received ClientServerReqeust1: " + msg.hex())
    client_server_req1 = pickle.loads(msg)
    print(dc_to_string(client_server_req1))

    # send response to client with PK_S, CERT_S, and TS4
    res1_dc = ClientServerResponse1(
        PK_S=server_ca_registration_response.PK_S,
        CERT_S=None,
        CERT_S_SERIALIZED=server_ca_registration_response.CERT_S_SERIALIZED,
        CERT_S_SIGNATURE=server_ca_registration_response.CERT_S_SIGNATURE,
        TS4=utils.get_time_stamp())
    print(dc_to_string(res1_dc))
    res1_serialized = pickle.dumps(res1_dc)
    print("Serialized ClientServerResponse1: " + res1_serialized.hex())
    client_sock.send(res1_serialized)
    print("Sent ClientServerResponse1. Waiting for response...\n\n")

    # receive and decrypt ClientServerRequest2
    recv = client_sock.recv(4096)
    print("Received ClientServerRequest2: " + recv.hex())
    client_server_req2 = decrypt_client_server_reqeust2(recv, server_ca_registration_response.SK_S)

    # send ClientServerResponse2 back
    print("Generating ClientServerResponse2...")
    res2_dc = ClientServerResponse2(K_SESS=utils.gen_key(8), LIFETIME=utils.Constants.LIFETIME_SESS, ID_C=utils.Constants.ID_C, TS6=utils.get_time_stamp())
    print(dc_to_string(res2_dc))
    res2_encrypted = encrypt_client_server_response2(res2_dc, client_server_req2.K_TMP2)
    client_sock.send(res2_encrypted)
    print("Sent ClientServerResponse2. Client Registration complete! Waiting for service request...\n\n")

    # receive from client ServiceRequest
    recv = client_sock.recv(4096)
    print("Received encrypted ServiceRequest: " + recv.hex())
    service_request = decrypt_service_request(recv, res2_dc.K_SESS)
    # ensure TS is good
    if (utils.get_time_stamp() - service_request.TS7) > utils.Constants.LIFETIME_SESS:
        raise Exception("K_SESS is expired!")

    # send to client ServiceResponse
    print("Generating ServiceResponse...")
    service_response = ServiceResponse(DATA=data, TS8=utils.get_time_stamp()) # in prod wed probably use a map to fetch data from reqs (and maybe not use ECB but ya know)
    print(dc_to_string(service_response))
    encrypted_service_response = encrypt_service_response(service_response, res2_dc.K_SESS)
    client_sock.send(encrypted_service_response)
    print("Sent ServiceResponse. Finished!")