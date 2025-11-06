import pickle

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Util.Padding import unpad, pad

from basic_socket import BasicSocket
import utils
from structs import *

def verify_res1(b: bytes) -> ClientServerResponse1:
    client_server_res1 = pickle.loads(b)
    print(dc_to_string(client_server_res1))
    pk = RSA.import_key(utils.Constants.PK_CA)
    h = SHA256.new(client_server_res1.CERT_S_SERIALIZED)
    try:
        pkcs1_15.new(pk).verify(h, client_server_res1.CERT_S_SIGNATURE)
        print("CERT_S_SIGNATURE matches!")
    except (ValueError, TypeError):
        raise Exception("CERT_S_SIGNATURE is invalid!")
    deserialized_cert = pickle.loads(client_server_res1.CERT_S_SERIALIZED)
    client_server_res1.CERT_S = deserialized_cert
    print(dc_to_string(client_server_res1))
    return client_server_res1

def encrypt_req2(req: ClientServerRequest2, rsa_key: bytes) -> bytes:
    serialized_req = pickle.dumps(req)
    print("Serialized ClientServerRequest2: " + serialized_req.hex())
    ct = (PKCS1_OAEP.new(RSA.import_key(rsa_key)).encrypt(serialized_req))
    print("Encrypted ClientServerRequest2: " + ct.hex())
    return ct

def decrypt_client_server_response2(b: bytes, tmp_key: bytes) -> ClientServerResponse2:
    decrypted = unpad(DES.new(tmp_key, DES.MODE_ECB).decrypt(b), DES.block_size)
    print("Decrypted ClientServerResponse2: " + decrypted.hex())
    dc = pickle.loads(decrypted)
    print(dc_to_string(dc))
    return dc

def encrypt_service_request(dc: ServiceRequest, key: bytes) -> bytes:
    serialized_dc = pickle.dumps(dc)
    print("Serialized ServiceRequest: " + serialized_dc.hex())
    encrypted = DES.new(key, DES.MODE_ECB).encrypt(pad(serialized_dc, DES.block_size))
    print("Encrypted ServiceRequest: " + encrypted.hex())
    return encrypted

def decrypt_service_response(b: bytes, key: bytes) -> ServiceResponse:
    decrypted = unpad(DES.new(key, DES.MODE_ECB).decrypt(b), DES.block_size)
    print("Decrypted ServiceResponse2: " + decrypted.hex())
    dc = pickle.loads(decrypted)
    print(dc_to_string(dc))
    return dc

req = "memo"

if __name__ == "__main__":
    with open("ca_public.pem", "rb") as f:
        utils.Constants.PK_CA = f.read()

    client_sock = BasicSocket('localhost', utils.Constants.PORT_CLIENT)
    client_sock.connect()
    print("Client connected to server. Generating request...")

    # send to server ClientServerRequest1 object
    client_server_request1 = ClientServerRequest1(ID_S=utils.Constants.ID_S, TS3=utils.get_time_stamp())
    print(dc_to_string(client_server_request1))
    serialized = pickle.dumps(client_server_request1)
    print("Serialized ClientServerRequest1: " + serialized.hex())
    client_sock.send(serialized)
    print("Sent ClientServerRequest1! Waiting on response...\n\n")

    # receive ClientServerResponse1
    recv = client_sock.recv()
    print("Received ClientServerResponse1: " + recv.hex())
    res1_dc = verify_res1(recv)
    print("Generating ClientServerRequest2...\n\n")

    # generate and send ClientServerRequest2 encrypted with RSA PK_S
    req2 = ClientServerRequest2(
        K_TMP2=utils.gen_key(8),
        ID_C=utils.Constants.ID_C,
        IP_C='localhost',
        PORT_C=utils.Constants.PORT_CLIENT,
        TS5=utils.get_time_stamp()
    )
    print(dc_to_string(req2))
    cipher_text = encrypt_req2(req2, res1_dc.PK_S)
    client_sock.send(cipher_text)
    print("Sent ClientRequest2! Waiting on response...\n\n")

    # receive ClientSeverResponse2
    recv = client_sock.recv()
    print("Received ClientServerResponse2: " + recv.hex())
    res2_dc = decrypt_client_server_response2(recv, req2.K_TMP2)

    # send to server ServiceRequest
    print("Generating ServiceRequest...")
    service_request = ServiceRequest(REQ=req, TS7=utils.get_time_stamp())
    print(dc_to_string(service_request))
    encrypted_service_reqeust = encrypt_service_request(service_request, res2_dc.K_SESS)
    client_sock.send(encrypted_service_reqeust)
    print("Sent ServiceRequest! Waiting on response...\n\n")

    # receive from server ServiceRequest
    recv = client_sock.recv()
    print("Received encrypted ServiceResponse: " + recv.hex())
    service_response = decrypt_service_response(recv, res2_dc.K_SESS)
    if (utils.get_time_stamp() - service_response.TS8) > utils.Constants.LIFETIME_SESS:
        raise Exception("K_SESS is expired!")
    print("Finished PKI-based authentication! Got data of:\n\t" + service_response.DATA)