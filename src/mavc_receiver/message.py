import struct
from dataclasses import dataclass


@dataclass
class Message:
    msg_type: int
    value: float

    STRUCT = struct.Struct("!If")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        msg_type, value = cls.STRUCT.unpack(data)
        return cls(msg_type, value)

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.msg_type, self.value)
