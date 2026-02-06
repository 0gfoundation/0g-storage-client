from enum import Enum
import random


class AccessControlOps(Enum):
    GRANT_ADMIN_ROLE = 0x00
    RENOUNCE_ADMIN_ROLE = 0x01
    SET_KEY_TO_SPECIAL = 0x10
    SET_KEY_TO_NORMAL = 0x11
    GRANT_WRITER_ROLE = 0x20
    REVOKE_WRITER_ROLE = 0x21
    RENOUNCE_WRITER_ROLE = 0x22
    GRANT_SPECIAL_WRITER_ROLE = 0x30
    REVOKE_SPECIAL_WRITER_ROLE = 0x31
    RENOUNCE_SPECIAL_WRITER_ROLE = 0x32

    @staticmethod
    def grant_admin_role(stream_id, address):
        return [AccessControlOps.GRANT_ADMIN_ROLE, stream_id, to_address(address)]

    @staticmethod
    def renounce_admin_role(stream_id):
        return [AccessControlOps.RENOUNCE_ADMIN_ROLE, stream_id]

    @staticmethod
    def set_key_to_special(stream_id, key):
        return [AccessControlOps.SET_KEY_TO_SPECIAL, stream_id, key]

    @staticmethod
    def set_key_to_normal(stream_id, key):
        return [AccessControlOps.SET_KEY_TO_NORMAL, stream_id, key]

    @staticmethod
    def grant_writer_role(stream_id, address):
        return [AccessControlOps.GRANT_WRITER_ROLE, stream_id, to_address(address)]

    @staticmethod
    def revoke_writer_role(stream_id, address):
        return [AccessControlOps.REVOKE_WRITER_ROLE, stream_id, to_address(address)]

    @staticmethod
    def renounce_writer_role(stream_id):
        return [AccessControlOps.RENOUNCE_WRITER_ROLE, stream_id]

    @staticmethod
    def grant_special_writer_role(stream_id, key, address):
        return [
            AccessControlOps.GRANT_SPECIAL_WRITER_ROLE,
            stream_id,
            key,
            to_address(address),
        ]

    @staticmethod
    def revoke_special_writer_role(stream_id, key, address):
        return [
            AccessControlOps.REVOKE_SPECIAL_WRITER_ROLE,
            stream_id,
            key,
            to_address(address),
        ]

    @staticmethod
    def renounce_special_writer_role(stream_id, key):
        return [AccessControlOps.RENOUNCE_SPECIAL_WRITER_ROLE, stream_id, key]


op_with_key = [
    AccessControlOps.SET_KEY_TO_SPECIAL,
    AccessControlOps.SET_KEY_TO_NORMAL,
    AccessControlOps.GRANT_SPECIAL_WRITER_ROLE,
    AccessControlOps.REVOKE_SPECIAL_WRITER_ROLE,
    AccessControlOps.RENOUNCE_SPECIAL_WRITER_ROLE,
]

op_with_address = [
    AccessControlOps.GRANT_ADMIN_ROLE,
    AccessControlOps.GRANT_WRITER_ROLE,
    AccessControlOps.REVOKE_WRITER_ROLE,
    AccessControlOps.GRANT_SPECIAL_WRITER_ROLE,
    AccessControlOps.REVOKE_SPECIAL_WRITER_ROLE,
]


MAX_STREAM_ID = 100
MAX_DATA_LENGTH = 256 * 1024 * 4
MIN_DATA_LENGTH = 10
MAX_U64 = (1 << 64) - 1
MAX_KEY_LEN = 2000

STREAM_DOMAIN = bytes.fromhex(
    "df2ff3bb0af36c6384e6206552a4ed807f6f6a26e7d0aa6bff772ddc9d4307aa"
)


def with_prefix(x):
    x = x.lower()
    if not x.startswith("0x"):
        x = "0x" + x
    return x


def pad(x, l):
    ans = hex(x)[2:]
    return "0" * (l - len(ans)) + ans


def to_address(x):
    if x.startswith("0x"):
        return x[2:]
    return x


def to_stream_id(x):
    return pad(x, 64)


def to_key_with_size(x):
    size = pad(len(x) // 2, 6)
    return size + x


def rand_key():
    len = random.randrange(1, MAX_KEY_LEN)
    if len % 2 == 1:
        len += 1
    return "".join([hex(random.randrange(16))[2:] for i in range(len)])


def rand_write(stream_id=None, key=None, size=None):
    return [
        (
            to_stream_id(random.randrange(0, MAX_STREAM_ID))
            if stream_id is None
            else stream_id
        ),
        rand_key() if key is None else key,
        random.randrange(MIN_DATA_LENGTH, MAX_DATA_LENGTH) if size is None else size,
    ]


def is_access_control_permission_denied(x):
    if x is None:
        return False
    return x.startswith("AccessControlPermissionDenied")


def is_write_permission_denied(x):
    if x is None:
        return False
    return x.startswith("WritePermissionDenied")


# reads: array of [stream_id, key]
# writes: array of [stream_id, key, data_length]


def create_kv_data(version, reads, writes, access_controls):
    # version
    data = bytes.fromhex(pad(version, 16))
    tags = []
    # read set
    data += bytes.fromhex(pad(len(reads), 8))
    for read in reads:
        data += bytes.fromhex(read[0])
        data += bytes.fromhex(to_key_with_size(read[1]))
    # write set
    data += bytes.fromhex(pad(len(writes), 8))
    # write set meta
    for write in writes:
        data += bytes.fromhex(write[0])
        data += bytes.fromhex(to_key_with_size(write[1]))
        data += bytes.fromhex(pad(write[2], 16))
        tags.append(write[0])
        if len(write) == 3:
            write_data = random.randbytes(write[2])
            write.append(write_data)
    # write data
    for write in writes:
        data += write[3]
    # access controls
    data += bytes.fromhex(pad(len(access_controls), 8))
    for ac in access_controls:
        k = 0
        # type
        data += bytes.fromhex(pad(ac[k].value, 2))
        k += 1
        # stream_id
        tags.append(ac[k])
        data += bytes.fromhex(ac[k])
        k += 1
        # key
        if ac[0] in op_with_key:
            data += bytes.fromhex(to_key_with_size(ac[k]))
            k += 1
        # address
        if ac[0] in op_with_address:
            data += bytes.fromhex(ac[k])
            k += 1
    tags = list(set(tags))
    tags = sorted(tags)
    tags = STREAM_DOMAIN + bytes.fromhex("".join(tags))
    return data, tags
