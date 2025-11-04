import socket
from utils import Constants, get_time_stamp, gen_key
from basic_socket import BasicSocket
from structs import ServerCARegistrationRequest, serialize_struct, dc_to_string

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


req = "memo"
data = "take cis3319 class this morning"

def encrypt_server_ca_registration_request(dc: ServerCARegistrationRequest) -> bytes:
    serialized = serialize_struct(dc)
    print("Serialized ServerCARegistrationRequest: " + serialized.hex())
    key = RSA.import_key(Constants.PK_CA)
    cipher = PKCS1_OAEP.new(key)
    ct = cipher.encrypt(serialized)
    return ct


if __name__ == '__main__':
    ca_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ca_sock.connect(('localhost', Constants.PORT_CA))
    print("Server started and connected to CA. Generating registration request...")

    # send request to CA
    ca_request = ServerCARegistrationRequest(K_TMP1=gen_key(8), ID_S=Constants.ID_S,TS1=get_time_stamp())
    print(dc_to_string(ca_request))
    ciphertext = encrypt_server_ca_registration_request(ca_request)
    ca_sock.send(ciphertext)


    # TODO: receive response (including cert) from CA and decrypt. verify cert authenticity

    # TODO: receive request from client

    # TODO: send response to client with PK_S, CERT_S, and TS4

    # TODO: receive from client (encrypted with RSA PK_S) K_TMP2, ID_C, IP_C, PORT_C, and TS5

    # TODO: send to client (encrypted with DES K_TMP2) K_SESS, LIFETIME_SESS, ID_C, TS6

    # TODO: receive from client (encrypted with DES K_SESS) req, TS7

    # TODO: send to client (encrypted with DES K_SESS) data. TS8