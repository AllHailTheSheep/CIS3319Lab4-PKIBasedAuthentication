# Info available to all classes if needed
import os
import time


class Constants:
    ID_CA = "ID-CA"
    ID_S = "ID-Server"
    ID_C = "ID-Client"

    PORT_CA = 9999
    PORT_CLIENT = 9998

    PK_CA = b'CA_P_KEY'


def get_time_stamp():
    return int(time.time())


def gen_key(size) -> bytes:
    return os.urandom(size)