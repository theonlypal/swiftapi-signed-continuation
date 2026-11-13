"""Sealed Linux memory descriptors carry private runtime credentials."""
import fcntl
import os
import platform
import stat
from .core import validate_key


def validate_descriptor(descriptor):
    if platform.system() != 'Linux' or type(descriptor) is not int or descriptor < 3:
        raise ValueError('Private descriptor requires Linux and a nonstandard descriptor')
    info=os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=256
            or info.st_mode & 0o077 or info.st_nlink!=0):
        raise ValueError('Private descriptor must be anonymous, bounded and owner-only')
    required=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
    if fcntl.fcntl(descriptor,fcntl.F_GET_SEALS)&required != required:
        raise ValueError('Private descriptor must be sealed against changes')
    return info.st_size


def read_descriptor(descriptor):
    size=validate_descriptor(descriptor)
    value=os.pread(descriptor,size,0).decode('ascii').strip()
    validate_key(value)
    return value


def read_signing_seed(descriptor):
    size=validate_descriptor(descriptor)
    if size!=32:raise ValueError('Runtime signing seed is exactly 32 bytes')
    return os.pread(descriptor,size,0)
