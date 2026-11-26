import hashlib


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def legacy_fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # DevSkim: ignore DS126858
