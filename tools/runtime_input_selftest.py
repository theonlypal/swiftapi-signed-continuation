"""Linux anonymous descriptors carry synthetic private input without persistent files."""
import fcntl
import json
import os
from swiftapi_native_service.runtime_input import read_descriptor, read_signing_seed


def sealed_descriptor(name, raw):
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, required)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def main():
    key = 'swiftapi_live_' + '1' * 64
    seed = bytes(range(32))
    descriptors = []
    try:
        descriptors.append(sealed_descriptor('synthetic-authority-input', key.encode('ascii')))
        descriptors.append(sealed_descriptor('synthetic-signature-input', seed))
        assert read_descriptor(descriptors[0]) == key
        assert read_signing_seed(descriptors[1]) == seed
        denied = 0
        for descriptor in descriptors:
            try:
                os.pwrite(descriptor, b'x', 0)
            except PermissionError:
                denied += 1
        assert denied == 2
        print(json.dumps({'status': 'PASS', 'input_kind': 'SYNTHETIC',
                          'descriptors_verified': 2, 'write_denials': denied,
                          'persistent_private_files': 0, 'authority_requests': 0}))
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


if __name__ == '__main__':
    main()
