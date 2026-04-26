from dataclasses import dataclass

from typing import Optional


@dataclass
class Command:
    """
    Robot command transmitted as a binary payload.

    Fields
    ------
    magic : int (UInt16)
        Fixed header identifier (0x073CD) used by the receiver to
        confirm that this is a valid, recognized packet and not stray bytes.

    version : int (UInt8)
        Protocol version number. Allows receiver to select the correct
        decode path if the schema evolves over time.

    sequence_id : int (UInt32)
        Incrementing counter assigned by the sender. The
        receiver can use it to detect dropped or reordered packets.

    timestamp : float (Float64)
        Unix epoch time (seconds) at which the message was created,
        stored as a 64-bit IEEE-754 double for sub-millisecond precision.

    palm_position : tuple[float, float, float]  (Float32 x 3)
        3-D position of the palm (x, y, z) as normalized units relative to the
        tracking origin. (e.g. (.90, .90, .90) would imply 90% of max reach along all axes)

    palm_orientation : tuple[float, float, float]  (Float32 x 3)
        Euler angles (roll, pitch, yaw) of the palm in radians.

    grip_amount : float (Float32)
        Normalized hand-closed ammount in the range [0.0, 1.0],
        where 0.0 is fully open and 1.0 is fully closed.

    checksum : int (UInt8)
        XOR checksum computed over all preceding bytes in the packet.
        The receiver recomputes this value and discards the packet if
        the values do not match, providing lightweight corruption detection.
    """

    magic: int  # UInt16
    version: int  # UInt8
    sequence_id: int  # UInt32
    timestamp: float  # Float64
    palm_position: tuple[float, float, float]  # Float32[3]
    palm_orientation: tuple[float, float, float]  # Float32[3]
    grip_amount: float  # Float32
    checksum: Optional[int] = None  # UInt8

    def __repr__(self) -> str:
        checksum_s = "None" if self.checksum is None else f"0x{self.checksum:02X}"
        return (
            "Command(\n"
            f"  magic=0x{self.magic:04X},\n"
            f"  version={self.version},\n"
            f"  sequence_id={self.sequence_id},\n"
            f"  timestamp={self.timestamp!r},\n"
            f"  palm_position={self.palm_position!r},\n"
            f"  palm_orientation={self.palm_orientation!r},\n"
            f"  grip_amount={self.grip_amount!r},\n"
            f"  checksum={checksum_s},\n"
            ")"
        )
