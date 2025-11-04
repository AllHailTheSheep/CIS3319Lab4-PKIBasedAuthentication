from base64 import b64encode
from dataclasses import dataclass, fields
import utils

@dataclass
class ServerCARegistrationRequest:
    K_TMP1: bytes
    ID_S: str
    TS1: int

def deserialize_server_ca_registration_request(s: bytes) -> ServerCARegistrationRequest:
    parts = s.split(utils.Constants.DELIM)
    K_TMP1 = parts[0]
    ID_S = parts[1].decode('utf-8')
    TS1 = int.from_bytes(parts[2], "little")
    return ServerCARegistrationRequest(K_TMP1=K_TMP1, ID_S=ID_S, TS1=TS1)

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