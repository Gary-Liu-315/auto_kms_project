"""
key_object.py
Key object model with lifecycle state machine.
- Extended lifecycle includes COMPROMISED and REVOKED.
- to_row/from_row for DB persistence.
"""

import uuid
import datetime
from enum import Enum
from typing import Optional, Tuple


class KeyStatus(Enum):
    PRE_ACTIVE = "PRE-ACTIVE"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DEACTIVATED = "DEACTIVATED"
    REVOKED = "REVOKED"
    COMPROMISED = "COMPROMISED"
    DESTROYED = "DESTROYED"


class KeyType(Enum):
    AES_128 = "AES-128"
    AES_192 = "AES-192"
    AES_256 = "AES-256"
    HMAC_SHA256 = "HMAC-SHA256"
    HMAC_SHA384 = "HMAC-SHA384"
    HMAC_SHA512 = "HMAC-SHA512"
    RSA_2048 = "RSA-2048"
    RSA_3072 = "RSA-3072"
    RSA_4096 = "RSA-4096"
    ECC_P256 = "ECC-P256"
    ECC_P384 = "ECC-P384"
    ECC_P521 = "ECC-P521"
    ED25519 = "ED25519"


class KeyUsage(Enum):
    ENCRYPT = "ENCRYPT"
    DECRYPT = "DECRYPT"
    SIGN = "SIGN"
    VERIFY = "VERIFY"
    WRAP = "WRAP"
    UNWRAP = "UNWRAP"
    DERIVE = "DERIVE"
    MAC = "MAC"


class KeyObject:
    """
    Represents a key entry. encrypted_material stores encrypted private/symmetric material.
    For asymmetric keys, public_material may be stored as plaintext in memory for quick access.
    """

    def __init__(self, owner: str, key_type: KeyType, key_usage: KeyUsage, key_id: Optional[str] = None):
        self.key_id = key_id or str(uuid.uuid4())
        self.owner = owner
        self.key_type = key_type
        self.key_usage = key_usage
        self.status = KeyStatus.PRE_ACTIVE
        self.created_at = datetime.datetime.utcnow().isoformat()
        self.updated_at = self.created_at
        # encrypted private or symmetric material (bytes) stored in DB
        self.encrypted_material: Optional[bytes] = None
        # public material (PEM) optionally cached (string)
        self.public_material: Optional[str] = None

    def transition(self, new_status: KeyStatus):
        """
        Transition state according to rules:
        - PRE_ACTIVE -> ACTIVE, DESTROYED, REVOKED, COMPROMISED
        - ACTIVE -> SUSPENDED, DEACTIVATED, REVOKED, COMPROMISED, DESTROYED
        - SUSPENDED -> ACTIVE, DEACTIVATED, REVOKED, COMPROMISED, DESTROYED
        - DEACTIVATED -> REVOKED, DESTROYED
        - REVOKED -> DESTROYED
        - COMPROMISED -> DESTROYED
        - DESTROYED -> no transitions
        """
        if self.status == KeyStatus.DESTROYED:
            raise ValueError("Cannot transition a destroyed key")

        allowed = {
            KeyStatus.PRE_ACTIVE: [KeyStatus.ACTIVE, KeyStatus.DESTROYED, KeyStatus.REVOKED, KeyStatus.COMPROMISED],
            KeyStatus.ACTIVE: [KeyStatus.SUSPENDED, KeyStatus.DEACTIVATED, KeyStatus.REVOKED, KeyStatus.COMPROMISED, KeyStatus.DESTROYED],
            KeyStatus.SUSPENDED: [KeyStatus.ACTIVE, KeyStatus.DEACTIVATED, KeyStatus.REVOKED, KeyStatus.COMPROMISED, KeyStatus.DESTROYED],
            KeyStatus.DEACTIVATED: [KeyStatus.REVOKED, KeyStatus.DESTROYED],
            KeyStatus.REVOKED: [KeyStatus.DESTROYED],
            KeyStatus.COMPROMISED: [KeyStatus.DESTROYED],
        }

        if new_status not in allowed.get(self.status, []):
            raise ValueError(f"Invalid transition: {self.status.value} -> {new_status.value}")

        self.status = new_status
        self.updated_at = datetime.datetime.utcnow().isoformat()

    def destroy(self):
        """Securely wipe local caches and mark destroyed. Actual DB clearing handled in KeyStore."""
        self.encrypted_material = None
        self.public_material = None
        self.status = KeyStatus.DESTROYED
        self.updated_at = datetime.datetime.utcnow().isoformat()

    def to_row(self) -> Tuple:
        """Serialize for DB insertion/update."""
        return (
            self.key_id,
            self.owner,
            self.key_type.value,
            self.key_usage.value,
            self.status.value,
            self.created_at,
            self.updated_at,
            self.encrypted_material,
        )

    @classmethod
    def from_row(cls, row: Tuple):
        """
        Reconstruct KeyObject from DB row.
        row expected: (key_id, owner, key_type, usage, status, created_at, updated_at, encrypted_material)
        """
        key_id, owner, key_type, key_usage, status, created_at, updated_at, encrypted_material = row
        # backward compatibility mapping (legacy short names)
        legacy_map = {"AES": "AES-256", "RSA": "RSA-2048", "ECC": "ECC-P256"}
        if key_type in legacy_map:
            key_type = legacy_map[key_type]
        obj = cls(owner=owner, key_type=KeyType(key_type), key_usage=KeyUsage(key_usage), key_id=key_id)
        obj.status = KeyStatus(status)
        obj.created_at = created_at
        obj.updated_at = updated_at
        obj.encrypted_material = encrypted_material
        # public_material will be populated by KeyStore when decrypting if needed
        return obj
