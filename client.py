import pickle

from basic_socket import BasicSocket
import utils
from structs import *

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

    # TODO: receive PK_S, CERT_S, TS4


    # TODO: send K_TMP2 to server along with other info (format in server.py) encrypted with RSA PK_S

    # TODO: receive from server (DES K_TMP2) message with K_SESS (see server.py for format)

    # TODO: send to client (DES K_SESS) req, TS7

    # TODO: receive from server (DES K_SESS) data, TS8