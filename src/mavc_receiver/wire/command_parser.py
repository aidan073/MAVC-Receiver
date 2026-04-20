from ..enum import Endian
from .parser import IParser
from .command import Command

import struct

_EXPECTED_COMMAND_MAGIC = 0x073CD


class CommandParser(IParser):
    """
    Encodes and decodes Command instances to/from raw bytes.
    """

    def __init__(
        self,
        sender_endian: Endian = Endian.LITTLE,
        receiver_endian: Endian = Endian.LITTLE,
    ) -> None:
        """
        Args:
            sender_endian (Endian): Byte order of the sender. Defaults to Endian.LITTLE.
            receiver_endian (Endian): Desired byte order to use when encoding. Defaults to Endian.LITTLE.
        """
        self.sender_endian = sender_endian
        self.receiver_endian = receiver_endian
        self._decoder_struct = struct.Struct(f"{self.sender_endian.value}HBIdfffffffB")
        self._encoder_struct = struct.Struct(f"{self.receiver_endian.value}HBIdfffffff")

    @staticmethod
    def _compute_checksum(data: bytes) -> int:
        """XOR of every byte in data."""
        result = 0
        for byte in data:
            result ^= byte
        return result

    def encode(self, msg: Command) -> bytes:
        """
        Serialize msg to bytes, computes checksum.

        Args:
            msg (Command): The Command dataclass instance to encode.
        """
        payload = self._encoder_struct.pack(
            msg.magic,
            msg.version,
            msg.sequence_id,
            msg.timestamp,
            *msg.palm_position,
            *msg.palm_orientation,
            msg.grip_amount,
        )
        checksum = self._compute_checksum(payload)
        return payload + struct.pack(f"{self.receiver_endian.value}B", checksum)

    def decode(self, data: bytes) -> Command:
        """
        Deserialize data into a Command instance.
        """
        expected_size = self._decoder_struct.size
        if len(data) != expected_size:
            raise ValueError(f"Expected {expected_size} bytes, got {len(data)}.")

        # Verify checksum over everything except the final byte
        computed = self._compute_checksum(data[:-1])
        received = data[-1]
        if computed != received:
            raise ValueError(
                f"Checksum mismatch: computed 0x{computed:02X}, "
                f"received 0x{received:02X}."
            )

        (
            magic,
            version,
            sequence_id,
            timestamp,
            px,
            py,
            pz,
            ox,
            oy,
            oz,
            grip_amount,
            checksum,
        ) = self._decoder_struct.unpack(data)

        if magic != _EXPECTED_COMMAND_MAGIC:
            raise ValueError(
                f"Magic mismatch: expected 0x{_EXPECTED_COMMAND_MAGIC:X}, got 0x{magic:X}."
            )

        return Command(
            magic=magic,
            version=version,
            sequence_id=sequence_id,
            timestamp=timestamp,
            palm_position=(px, py, pz),
            palm_orientation=(ox, oy, oz),
            grip_amount=grip_amount,
            checksum=checksum,
        )
