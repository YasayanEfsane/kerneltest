#!/usr/bin/env python3
"""
decode_ioctl.py - Windows IOCTL code decoder for ObsidianClock.sys

Decodes raw IOCTL codes into their component fields using the CTL_CODE format.
"""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class IoctlDecode:
    """Decoded IOCTL structure."""
    raw_code: int
    device_type: int
    access: int
    function: int
    method: int
    semantic_name: str
    access_name: str
    method_name: str


# Known ObsidianClock IOCTLs
KNOWN_IOCTLS: Dict[int, str] = {
    0x8337E404: "IOCTL_OC_CREATE_SESSION",
    0x8337E409: "IOCTL_OC_SUBMIT_POLICY",
    0x8337E40E: "IOCTL_OC_GET_COUNTERS",
    0x8337E410: "IOCTL_OC_CLOSE_SESSION",
}

# Access field names
ACCESS_NAMES: Dict[int, str] = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_ACCESS | FILE_WRITE_ACCESS",
}

# Method field names
METHOD_NAMES: Dict[int, str] = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}


def decode_ioctl(raw_code: int) -> IoctlDecode:
    """
    Decode a Windows IOCTL code using CTL_CODE format.
    
    CTL_CODE(DeviceType, Function, Method, Access) = 
        (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
    
    Args:
        raw_code: Raw IOCTL code as 32-bit integer
        
    Returns:
        IoctlDecode with all fields extracted
        
    Raises:
        ValueError: If raw_code is not a valid 32-bit value
    """
    if not (0 <= raw_code <= 0xFFFFFFFF):
        raise ValueError(f"IOCTL code must be 32-bit: {raw_code:#x}")
    
    # Extract fields per CTL_CODE layout
    device_type = (raw_code >> 16) & 0xFFFF
    access = (raw_code >> 14) & 0x03
    function = (raw_code >> 2) & 0xFFF
    method = raw_code & 0x03
    
    # Get semantic name if known
    semantic_name = KNOWN_IOCTLS.get(raw_code, f"UNKNOWN_IOCTL_{raw_code:08X}")
    
    # Get field names
    access_name = ACCESS_NAMES.get(access, f"UNKNOWN_ACCESS_{access}")
    method_name = METHOD_NAMES.get(method, f"UNKNOWN_METHOD_{method}")
    
    return IoctlDecode(
        raw_code=raw_code,
        device_type=device_type,
        access=access,
        function=function,
        method=method,
        semantic_name=semantic_name,
        access_name=access_name,
        method_name=method_name,
    )


def format_decode(decode: IoctlDecode) -> str:
    """Format decoded IOCTL as human-readable string."""
    lines = [
        f"IOCTL Decode Report",
        f"==================",
        f"",
        f"Raw Code:       0x{decode.raw_code:08X}",
        f"Binary:         {decode.raw_code:032b}",
        f"",
        f"Device Type:    0x{decode.device_type:04X} ({decode.device_type})",
        f"Access:         0x{decode.access:01X} ({decode.access_name})",
        f"Function:       0x{decode.function:03X} ({decode.function})",
        f"Method:         0x{decode.method:01X} ({decode.method_name})",
        f"",
        f"Semantic Name:  {decode.semantic_name}",
        f"",
        f"Field Layout:",
        f"  bits 16-31: DeviceType  = 0x{decode.device_type:04X}",
        f"  bits 14-15: Access      = 0x{decode.access:01X}",
        f"  bits 2-13:  Function    = 0x{decode.function:03X}",
        f"  bits 0-1:   Method      = 0x{decode.method:01X}",
    ]
    return "\n".join(lines)


def main():
    """Decode all known ObsidianClock IOCTLs."""
    print("=" * 60)
    print("ObsidianClock.sys IOCTL Decoder")
    print("=" * 60)
    print()
    
    for code in sorted(KNOWN_IOCTLS.keys()):
        decode = decode_ioctl(code)
        print(format_decode(decode))
        print("-" * 60)
        print()


if __name__ == "__main__":
    main()
