from base64 import b64encode
from dataclasses import dataclass, fields
import utils

@dataclass
class ServerCARegistrationRequest:
    K_TMP1: bytes
    ID_S: str
    TS1: int

@dataclass
class ServerCert:
    ID_S: str
    ID_CA: str
    PK_S: bytes

@dataclass
class ServerCARegistrationResponse:
    PK_S: bytes
    SK_S: bytes
    CERT_S: ServerCert
    CERT_S_SERIALIZED: bytes
    CERT_S_SIGNATURE: bytes
    ID_S: str
    TS2: int

def deserialize_server_ca_registration_request(s: bytes) -> ServerCARegistrationRequest:
    parts = s.split(utils.Constants.DELIM)
    K_TMP1 = parts[0]
    ID_S = parts[1].decode('utf-8')
    TS1 = int.from_bytes(parts[2], "little")
    return ServerCARegistrationRequest(K_TMP1=K_TMP1, ID_S=ID_S, TS1=TS1)

def deserialize_server_cert(s: bytes) -> ServerCert:
    parts = s.split(utils.Constants.DELIM)
    ID_S = parts[0].decode('utf-8')
    ID_CA = parts[1].decode('utf-8')
    PK_S = parts[2]
    return ServerCert(ID_S=ID_S, ID_CA=ID_CA, PK_S=PK_S)

def deserialize_server_ca_registration_response(s: bytes) -> ServerCARegistrationResponse:
    parts = s.split(utils.Constants.DELIM)
    PK_S = parts[0]
    SK_S = parts[1]
    CERT_S = None
    CERT_S_SERIALIZED = parts[2] # TODO: this fails and sets CERT_S_SERIALIZED = 49442d536572766572 (I.E., ID_S form inside cert) as we are splitting on a serialized object delimed by same seperator.
    # Solution: either serialize substructs on different byte or try using pickle.dumps and pickle.load
    CERT_S_SIGNATURE = parts[3]
    ID_S = parts[4].decode('utf-8')
    TS1 = int.from_bytes(parts[5], "little")
    return ServerCARegistrationResponse(PK_S=PK_S, SK_S=SK_S, CERT_S=CERT_S, CERT_S_SERIALIZED=CERT_S_SERIALIZED, CERT_S_SIGNATURE=CERT_S_SIGNATURE, ID_S=ID_S, TS2=TS1)


# serializes an arbitrary dataclass
def serialize_struct(dc) -> bytes:
    parts = []
    for f in fields(dc):
        val = getattr(dc, f.name)
        if isinstance(val, bytes):
            parts.append(val)
        elif isinstance(val, str):
            parts.append(val.encode("utf-8"))
        elif isinstance(val, int):
            parts.append(val.to_bytes(32, "little"))
    return b"||".join(parts)

# formats an arbitrary dataclass to string and returns it
def dc_to_string(dc) -> str:
    res = type(dc).__name__ + ":"
    for f in fields(dc):
        res += "\n\t" + f.name + ": "
        if isinstance(getattr(dc, f.name), bytes):
            res += getattr(dc, f.name).hex()
        else:
            res += repr(getattr(dc, f.name))
    res += "\n"
    return res