from basic_socket import BasicSocket
import utils

if __name__ == "__main__":
    with open("ca_public.pem", "rb") as f:
        utils.Constants.PK_CA = f.read()

    client_sock = BasicSocket('localhost', utils.Constants.PORT_CA)
    client_sock.connect()

    # TODO: send to server ID, TS3

    # TODO: receive PK_S, CERT_S, TS4

    # TODO: send K_TMP2 to server along with other info (format in server.py) encrypted with RSA PK_S

    # TODO: receive from server (DES K_TMP2) message with K_SESS (see server.py for format)

    # TODO: send to client (DES K_SESS) req, TS7

    # TODO: receive from server (DES K_SESS) data, TS8