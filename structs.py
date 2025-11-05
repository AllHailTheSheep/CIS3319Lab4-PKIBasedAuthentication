from dataclasses import dataclass, fields

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