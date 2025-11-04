from base64 import b64encode
from dataclasses import dataclass, fields

@dataclass
class ServerCARegistrationRequest:
    K_TMP1: bytes
    ID_S: str
    TS1: int


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