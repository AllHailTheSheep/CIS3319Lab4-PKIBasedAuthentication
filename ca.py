from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

from basic_socket import BasicSocket
import utils
from structs import *

SK_CA: bytes

def encrypt_and_sign_server_ca_registration_response(dc: ServerCARegistrationResponse, tmp_key: bytes) -> bytes:
    cert = dc.CERT_S
    dc.CERT_S = None
    serialized_cert = serialize_struct(cert)
    print("Serialized CERT_S: " + serialized_cert.hex())
    cert_hash = SHA256.new(serialized_cert)
    print("CERT_S SHA256 hash: " + cert_hash.hexdigest())
    key = RSA.importKey(SK_CA)
    cert_signature = pkcs1_15.new(key).sign(cert_hash)
    print("CERT_S_SIGNATURE: " + cert_signature.hex())
    dc.CERT_S_SERIALIZED = serialized_cert
    dc.CERT_S_SIGNATURE = cert_signature
    print(dc_to_string(dc))
    serialized_res = serialize_struct(dc)
    print("Serialized ServerCARegistrationResponse: " + serialized_res.hex())
    cipher = DES.new(tmp_key, DES.MODE_ECB)
    ct = cipher.encrypt(pad(serialized_res, DES.block_size))
    print("Encrypted ServerCARegistrationResponse: " + ct.hex())
    return ct

def decrypt_server_ca_registration_request(b: bytes) -> ServerCARegistrationRequest:
    key = RSA.importKey(SK_CA)
    cipher = PKCS1_OAEP.new(key)
    decrypted = cipher.decrypt(b)
    print("Decrypted (but still serialized) ServerCARegistrationRequest: " + decrypted.hex())
    deserialized = deserialize_server_ca_registration_request(decrypted)
    print(dc_to_string(deserialized))
    return deserialized

if __name__ == '__main__':
    # CA will be run first, and therefore needs to generate CA's public key and secret key first. we write it to file
    # for other files to read it (python lacks shared memory).
    rsa_key = utils.gen_rsa_key()
    with open("ca_public.pem", "wb") as f:
        f.write(rsa_key.public_key().export_key())
    SK_CA = rsa_key.export_key()
    utils.Constants.PK_CA = rsa_key.public_key().export_key()
    print("Generated RSA keypair. Private key is:\n\t" + SK_CA.hex() + "\nPublic key is:\n\t" + utils.Constants.PK_CA.hex() + "\n\n")

    # start server
    ca = BasicSocket('localhost', utils.Constants.PORT_CA)
    ca.listen()
    print("CA server is listening on " + ca.addr + ":" + str(ca.port) + ". Waiting for registration request...\n\n")

    # receive registration request from application server
    recv_bytes = ca.recv()
    print("Received encrypted/serialized ServerCARegistrationRequest: " + recv_bytes.hex())
    server_ca_registration_request = decrypt_server_ca_registration_request(recv_bytes)
    print("\n")

    # check ID_S with value in constants
    if server_ca_registration_request.ID_S != utils.Constants.ID_S:
        raise Exception("ServerCARegistrationRequest ID mismatch!")
    print("ServerCARegistrationRequest ID matches! Generating response...")

    # generate ServerCARegistrationResponse
    server_rsa = utils.gen_rsa_key()
    print("Generated RSA keypair for server. Private key is:\n\t" + server_rsa.export_key().hex() + "\nPublic key is:\n\t" + server_rsa.public_key().export_key().hex() + "\n")
    server_cert = ServerCert(ID_S=utils.Constants.ID_S, ID_CA=utils.Constants.ID_CA, PK_S=server_rsa.public_key().export_key())
    print(dc_to_string(server_cert))
    server_ca_registration_response = ServerCARegistrationResponse(PK_S=server_rsa.public_key().export_key(), SK_S=server_rsa.export_key(), CERT_S=server_cert, CERT_S_SERIALIZED=None, CERT_S_SIGNATURE=None, ID_S=utils.Constants.ID_S, TS2=utils.get_time_stamp())
    print(dc_to_string(server_ca_registration_response))
    msg = encrypt_and_sign_server_ca_registration_response(server_ca_registration_response, server_ca_registration_request.K_TMP1)
    ca.send(msg)
    print("ServerCARegistrationResponse sent!\n\n")
