from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from basic_socket import BasicSocket
import utils
from structs import *

SK_CA: bytes

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



    # TODO: check ID_S with value in Constants. if correct, generate response (format as follows)
    # Encrypted with DES K_TMP1
    #   PK_S
    #   SK_S
    #   CERT_S
    #   ID_S
    #   TS2

    # CERT is signed with SK_CA
    #   ID_S
    #   ID_CA
    #   PK_S

    # TODO: serialize and finalize (encrypt/sign) response. send.