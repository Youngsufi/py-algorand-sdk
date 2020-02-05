import decimal
import base64
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
import base64
import msgpack
from collections import OrderedDict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from . import transaction, error, auction, constants


def microalgos_to_algos(microalgos):
    """
    Convert microalgos to algos.

    Args:
        microalgos (int): how many microalgos

    Returns:
        int or decimal: how many algos
    """
    return decimal.Decimal(microalgos)/constants.microalgos_to_algos_ratio


def algos_to_microalgos(algos):
    """
    Convert algos to microalgos.

    Args:
        algos (int or decimal): how many algos

    Returns:
        int: how many microalgos
    """
    return round(algos*constants.microalgos_to_algos_ratio)


def sign_bytes(to_sign, private_key):
    """
    Sign arbitrary bytes after prepending with "MX" for domain separation.

    Args:
        to_sign (bytes): bytes to sign

    Returns:
        str: base64 signature
    """
    to_sign = constants.bytes_prefix + to_sign
    private_key = base64.b64decode(private_key)
    signing_key = SigningKey(private_key[:constants.key_len_bytes])
    signed = signing_key.sign(to_sign)
    signature = base64.b64encode(signed.signature).decode()
    return signature


def verify_bytes(message, signature, public_key):
    """
    Verify the signature of a message that was prepended with "MX" for domain
    separation.

    Args:
        message (bytes): message that was signed, without prefix
        signature (str): base64 signature
        public_key (str): base32 address

    Returns:
        bool: whether or not the signature is valid
    """
    verify_key = VerifyKey(decode_address(public_key))
    prefixed_message = constants.bytes_prefix + message
    try:
        verify_key.verify(prefixed_message, base64.b64decode(signature))
        return True
    except BadSignatureError:
        return False


def public_key_from_private_key(private_key):
    """
    Return the address for the private key.

    Args:
        private_key (str): private key of the account in base64

    Returns:
        str: address of the account
    """
    pk = base64.b64decode(private_key)[constants.key_len_bytes:]
    address = encode_address(pk)
    return address


def generate_account():
    """
    Generate an account.

    Returns:
        (str, str): private key, account address
    """
    sk = SigningKey.generate()
    vk = sk.verify_key
    a = encode_address(vk.encode())
    private_key = base64.b64encode(sk.encode() + vk.encode()).decode()
    return private_key, a


def msgpack_encode(obj):
    """
    Encode the object using canonical msgpack.

    Args:
        obj (Object): object to be encoded

    Returns:
        str: msgpack encoded object

    Note:
        Canonical Msgpack: maps must contain keys in lexicographic order; maps
        must omit key-value pairs where the value is a zero-value; positive
        integer values must be encoded as "unsigned" in msgpack, regardless of
        whether the value space is semantically signed or unsigned; integer
        values must be represented in the shortest possible encoding; binary
        arrays must be represented using the "bin" format family (that is, use
        the most recent version of msgpack rather than the older msgpack
        version that had no "bin" family).
    """
    d = obj
    if not isinstance(obj, dict):
        d = obj.dictify()
    od = sort_dict_recursively(d)
    return base64.b64encode(msgpack.packb(od, use_bin_type=True)).decode()


def sort_dict_recursively(d):
    od = OrderedDict()
    for k, v in sorted(d.items()):
        if isinstance(v, dict):
            od[k] = sort_dict_recursively(v)
        else:
            od[k] = v
    return od


def msgpack_decode(enc):
    """
    Decode a msgpack encoded object from a string.

    Args:
        enc (str): string to be decoded

    Returns:
        Object: decoded object
    """
    decoded = enc
    if not isinstance(enc, dict):
        decoded = msgpack.unpackb(base64.b64decode(enc), raw=False)
    if "type" in decoded:
        return transaction.Transaction.undictify(decoded)
    if "l" in decoded:
        return transaction.LogicSig.undictify(decoded)
    if "msig" in decoded:
        return transaction.MultisigTransaction.undictify(decoded)
    if "lsig" in decoded:
        return transaction.LogicSigTransaction.undictify(decoded)
    if "sig" in decoded:
        return transaction.SignedTransaction.undictify(decoded)
    if "txn" in decoded:
        return transaction.Transaction.undictify(decoded["txn"])
    if "subsig" in decoded:
        return transaction.Multisig.undictify(decoded)
    if "txlist" in decoded:
        return transaction.TxGroup.undictify(decoded)
    if "t" in decoded:
        return auction.NoteField.undictify(decoded)
    if "bid" in decoded:
        return auction.SignedBid.undictify(decoded)
    if "auc" in decoded:
        return auction.Bid.undictify(decoded)


def is_valid_address(addr):
    """
    Check if the string address is a valid Algorand address.

    Args:
        addr (str): base32 address

    Returns:
        bool: whether or not the address is valid
    """
    if not isinstance(addr, str):
        return False
    if not len(_undo_padding(addr)) == constants.address_len:
        return False
    try:
        decoded = decode_address(addr)
        if isinstance(decoded, str):
            return False
        return True
    except:
        return False


def decode_address(addr):
    """
    Decode a string address into its address bytes and checksum.

    Args:
        addr (str): base32 address

    Returns:
        bytes: address decoded into bytes

    """
    if not addr:
        return addr
    if not len(addr) == constants.address_len:
        raise error.WrongKeyLengthError
    decoded = base64.b32decode(_correct_padding(addr))
    addr = decoded[:-constants.check_sum_len_bytes]
    expected_checksum = decoded[-constants.check_sum_len_bytes:]
    chksum = _checksum(addr)

    if chksum == expected_checksum:
        return addr
    else:
        raise error.WrongChecksumError


def encode_address(addr_bytes):
    """
    Encode a byte address into a string composed of the encoded bytes and the
    checksum.

    Args:
        addr_bytes (bytes): address in bytes

    Returns:
        str: base32 encoded address
    """
    if not addr_bytes:
        return addr_bytes
    if not len(addr_bytes) == constants.key_len_bytes:
        raise error.WrongKeyBytesLengthError
    chksum = _checksum(addr_bytes)
    addr = base64.b32encode(addr_bytes+chksum)
    return _undo_padding(addr.decode())


def _checksum(addr):
    """
    Compute the checksum of size checkSumLenBytes for the address.

    Args:
        addr (bytes): address in bytes

    Returns:
        bytes: checksum of the address
    """
    return checksum(addr)[-constants.check_sum_len_bytes:]


def _correct_padding(a):
    if len(a) % 8 == 0:
        return a
    return a + "="*(8-len(a) % 8)


def _undo_padding(a):
    return a.strip("=")


def checksum(data):
    """
    Compute the checksum of arbitrary binary input.

    Args:
        data (bytes): data as bytes

    Returns:
        bytes: checksum of the data
    """
    chksum = hashes.Hash(hashes.SHA512_256(), default_backend())
    chksum.update(data)
    return chksum.finalize()


def write_to_file(objs, path, overwrite=True):
    """
    Write objects to a file.

    Args:
        objs (Object[]): list of encodable objects
        path (str): file to write to
        overwrite (bool): whether or not to overwrite what's already in the
            file; if False, transactions will be appended to the file

    Returns:
        bool: true if the transactions have been written to the file
    """

    f = None
    if overwrite:
        f = open(path, "wb")
    else:
        f = open(path, "ab")

    for obj in objs:
        if isinstance(obj, transaction.Transaction):
            f.write(base64.b64decode(msgpack_encode({"txn": obj.dictify()})))
        else:
            f.write(base64.b64decode(msgpack_encode(obj)))

    f.close()
    return True


def read_from_file(path):
    """
    Retrieve encoded objects from a file.

    Args:
        path (str): file to read from

    Returns:
        Object[]: list of objects
    """

    f = open(path, "rb")
    objs = []
    unp = msgpack.Unpacker(f, raw=False)
    for obj in unp:
        objs.append(msgpack_decode(obj))
    f.close()
    return objs
