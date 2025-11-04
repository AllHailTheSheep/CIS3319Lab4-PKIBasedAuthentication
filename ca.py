from basic_socket import BasicSocket
from utils import Constants

if __name__ == '__main__':
    # TODO: CA will be run first, and therefore needs to generate CA's public key and secret key first, and put it in the constants class.

    ca = BasicSocket('127.0.0.1', Constants.PORT_CA)
    ca.listen()
    print("CA server is listening on " + ca.addr + ":" + str(ca.port) + ". Waiting for registration request...\n")
    # TODO: receive registration request from appliction, encrypted with PK_CA RSA key.
    #   Will contain K_TMP1, ID_S, and TS1


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