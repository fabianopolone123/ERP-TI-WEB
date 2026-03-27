from __future__ import annotations

import base64
import hashlib
from functools import lru_cache

from django.conf import settings


class VaultCryptoError(Exception):
    pass


def is_vault_feature_enabled() -> bool:
    return bool(getattr(settings, 'FEATURE_VAULT_ENABLED', False))


def is_vault_configured() -> bool:
    return bool((getattr(settings, 'VAULT_MASTER_KEY', '') or '').strip())


def get_vault_status() -> tuple[bool, str]:
    if not is_vault_feature_enabled():
        return False, 'Cofre desabilitado pela feature flag.'
    if not is_vault_configured():
        return False, 'Configure VAULT_MASTER_KEY para habilitar o cofre.'
    try:
        _build_fernet()
    except VaultCryptoError as exc:
        return False, str(exc)
    return True, ''


def _master_key_material() -> str:
    raw = (getattr(settings, 'VAULT_MASTER_KEY', '') or '').strip()
    if not raw:
        raise VaultCryptoError('VAULT_MASTER_KEY nao configurada.')
    return raw


def _key_salt() -> bytes:
    raw = (getattr(settings, 'VAULT_KEY_SALT', 'erp-ti-vault-v1') or 'erp-ti-vault-v1').strip()
    return raw.encode('utf-8')


@lru_cache(maxsize=1)
def _build_fernet():
    try:
        from cryptography.fernet import Fernet
    except Exception as exc:
        raise VaultCryptoError('Dependencia "cryptography" indisponivel.') from exc

    material = _master_key_material().encode('utf-8')
    try:
        if len(material) == 44:
            Fernet(material)
            return Fernet(material)
    except Exception:
        pass

    derived = hashlib.pbkdf2_hmac('sha256', material, _key_salt(), 390000, dklen=32)
    fernet_key = base64.urlsafe_b64encode(derived)
    return Fernet(fernet_key)


def encrypt_vault_text(value: str) -> str:
    raw = value or ''
    if raw == '':
        return ''
    try:
        token = _build_fernet().encrypt(raw.encode('utf-8'))
    except VaultCryptoError:
        raise
    except Exception as exc:
        raise VaultCryptoError('Falha ao criptografar dado do cofre.') from exc
    return token.decode('utf-8')


def decrypt_vault_text(value: str) -> str:
    token = (value or '').strip()
    if not token:
        return ''
    try:
        plain = _build_fernet().decrypt(token.encode('utf-8'))
    except VaultCryptoError:
        raise
    except Exception as exc:
        raise VaultCryptoError('Falha ao descriptografar dado do cofre.') from exc
    return plain.decode('utf-8')
