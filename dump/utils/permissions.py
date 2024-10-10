import ctypes
import logging

logger = logging.getLogger(__name__)


def get_permissions(protect: int) -> str:
    """Convert protection flags to readable permissions."""
    permissions = []
    if protect & 0x100:  # PAGE_EXECUTE
        permissions.append("EXECUTE")
    if protect & 0x200:  # PAGE_EXECUTE_READ
        permissions.append("EXECUTE_READ")
    if protect & 0x400:  # PAGE_EXECUTE_READWRITE
        permissions.append("EXECUTE_READWRITE")
    if protect & 0x800:  # PAGE_EXECUTE_WRITECOPY
        permissions.append("EXECUTE_WRITECOPY")
    if protect & 0x4:  # PAGE_READONLY
        permissions.append("READONLY")
    if protect & 0x2:  # PAGE_READWRITE
        permissions.append("READWRITE")
    if protect & 0x1:  # PAGE_WRITECOPY
        permissions.append("WRITECOPY")
    if not permissions:
        permissions.append("UNKNOWN")
    return "|".join(permissions)