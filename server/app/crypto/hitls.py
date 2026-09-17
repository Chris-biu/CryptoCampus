"""真实密码引擎：通过 ctypes 调用 bridge/libcc_bridge（openHiTLS）。

协议实现对齐 CryptoEngine（server/app/crypto/engine.py）。
- .so 加载或初始化失败 → 抛 CryptoBridgeError(PROVIDER_UNAVAILABLE)，
  由 app.crypto.dependencies 捕获后回退到 UnavailableCryptoEngine（fail-closed）。
- blind_commit / blind_sign / blind_verify：调用已验证的两轮 SM2 盲签名 ABI。
- PQC（ML-KEM）：桥接层暂未实现，pqc_mode=True 时抛 UNSUPPORTED。
"""

from __future__ import annotations

import ctypes
import sys
from pathlib import Path

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    MAX_DER_CERTIFICATE_SIZE,
    MAX_DROP_CONTENT_SIZE,
    MAX_SM2_ENC_KEY_SIZE,
    CrlArtifact,
    EnvelopeArtifact,
    ProviderStatus,
    SignedCertificate,
    Sm2KeyPair,
    Sm4GcmCiphertext,
    SM2_PRIVATE_KEY_SIZE,
    SM2_PUBLIC_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
    SM3_DIGEST_SIZE,
    SM4_KEY_SIZE,
    require_exact_length,
)

_WRAPPER_DIR = Path(__file__).resolve().parents[3] / "bridge" / "wrapper"
if str(_WRAPPER_DIR) not in sys.path:
    sys.path.insert(0, str(_WRAPPER_DIR))

import cc_bridge as _bridge  # noqa: E402

_ALLOWED_ROLES = {"student", "admin", "teacher", "system"}

# engine.py 契约的 key_usage 字符串 → HITLS_X509_EXT_KU_* 位掩码
_KEY_USAGE_BITS: dict[str, int] = {
    "digitalSignature": 0x0080,
    "nonRepudiation": 0x0040,
    "keyEncipherment": 0x0020,
    "dataEncipherment": 0x0010,
    "keyAgreement": 0x0008,
    "keyCertSign": 0x0004,
    "cRLSign": 0x0002,
    "encipherOnly": 0x0001,
    "decipherOnly": 0x8000,
}

# cert_sign 生成的序列号长度（字节）；十六进制字符串化后满足 serial 契约
_CERT_SERIAL_BYTES = 16


def _raise_for(ret: int) -> None:
    """把负的 CCB_* 返回码映射成 CryptoBridgeError。"""
    if ret < 0:
        try:
            code = BridgeErrorCode(ret)
        except ValueError:
            code = BridgeErrorCode.INTERNAL_ERROR
        raise CryptoBridgeError(code)


def _require_der(value: bytes, maximum_size: int = MAX_DER_CERTIFICATE_SIZE) -> None:
    if not isinstance(value, bytes) or not value or len(value) > maximum_size:
        raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)


def _require_time_range(earlier: int, later: int) -> None:
    if type(earlier) is not int or type(later) is not int or later <= earlier:
        raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)


def _require_key_usage(key_usage: tuple[str, ...]) -> None:
    if (
        not isinstance(key_usage, tuple)
        or not key_usage
        or not all(isinstance(value, str) and value in _KEY_USAGE_BITS for value in key_usage)
    ):
        raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)


def _key_usage_bits(key_usage: tuple[str, ...]) -> int:
    bits = 0
    for value in key_usage:
        bits |= _KEY_USAGE_BITS[value]
    return bits


def _nested_output(buffer: _bridge.OwnedBuffer, updated: _bridge.BridgeBuffer) -> bytes:
    try:
        return buffer.data_from(updated)
    except ValueError as error:
        raise CryptoBridgeError(BridgeErrorCode.INTERNAL_ERROR) from error


class HitlsCryptoEngine:
    """基于 openHiTLS（经 libcc_bridge）的真实密码引擎。"""

    def __init__(self) -> None:
        try:
            self._lib = _bridge.load()
        except (FileNotFoundError, OSError) as error:
            raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE) from error
        if self._lib.cc_bridge_init(None) != _bridge.CCB_OK:
            raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE)
        version = self._lib.cc_bridge_version()
        self._version = version.decode("ascii") if version else "unknown"

    # ------------------------------------------------------------------ 状态
    def provider_status(self) -> ProviderStatus:
        return ProviderStatus(
            state="online",
            version=self._version,
            provider="openHiTLS",
            capabilities={
                "sm3": True,
                "hkdf_sm3": True,
                "sm4_gcm": True,
                "sm2": True,
                "pki": True,
                "envelope": True,
                "pqc": False,
                "blind_signature": True,
            },
        )

    def reload_pqc_provider(self) -> ProviderStatus:
        """Fail closed until the bridge exposes a real Provider reload ABI."""
        raise CryptoBridgeError(BridgeErrorCode.UNSUPPORTED)

    # ------------------------------------------------------------ 摘要 / KDF
    def sm3_digest(self, message: bytes) -> bytes:
        if not isinstance(message, bytes):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        out = _bridge.allocate(SM3_DIGEST_SIZE)
        msg = _bridge.ro(message)
        ret = self._lib.cc_bridge_sm3_digest(msg.struct.data, len(message), ctypes.byref(out.struct))
        _raise_for(ret)
        return out.data

    def sm3_hash_password(self, password_utf8: bytes, salt_a: bytes) -> bytes:
        if not isinstance(password_utf8, bytes) or not isinstance(salt_a, bytes):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        out = _bridge.allocate(SM3_DIGEST_SIZE)
        pwd = _bridge.ro(password_utf8)
        salt = _bridge.ro(salt_a)
        ret = self._lib.cc_bridge_sm3_hash_password(
            pwd.struct.data, len(password_utf8), salt.struct.data, len(salt_a), ctypes.byref(out.struct)
        )
        _raise_for(ret)
        return out.data

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        if not isinstance(left, bytes) or not isinstance(right, bytes):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        l_buf = _bridge.ro(left)
        r_buf = _bridge.ro(right)
        ret = self._lib.cc_bridge_constant_time_equal(
            l_buf.struct.data, len(left), r_buf.struct.data, len(right)
        )
        return ret == 1

    def hkdf_sm3(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        if not isinstance(ikm, bytes) or not isinstance(salt, bytes) or not isinstance(info, bytes):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        if type(length) is not int or not 16 <= length <= 64:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        out = _bridge.allocate(length)
        ikm_buf = _bridge.ro(ikm)
        salt_buf = _bridge.ro(salt)
        info_buf = _bridge.ro(info)
        ret = self._lib.cc_bridge_hkdf_sm3(
            ikm_buf.struct.data, len(ikm),
            salt_buf.struct.data, len(salt),
            info_buf.struct.data, len(info),
            ctypes.byref(out.struct),
        )
        _raise_for(ret)
        return out.data

    # ------------------------------------------------------------ 对称加密
    def sm4_gcm_encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> Sm4GcmCiphertext:
        require_exact_length(key, SM4_KEY_SIZE)
        if not isinstance(plaintext, bytes) or not isinstance(aad, bytes):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        ciphertext = _bridge.allocate(len(plaintext) + 16)
        nonce = _bridge.allocate(GCM_NONCE_SIZE)
        tag = _bridge.allocate(GCM_TAG_SIZE)
        key_buf = _bridge.ro(key)
        pt_buf = _bridge.ro(plaintext)
        aad_buf = _bridge.ro(aad)
        ret = self._lib.cc_bridge_sm4_gcm_encrypt(
            key_buf.struct.data, pt_buf.struct.data, len(plaintext),
            aad_buf.struct.data, len(aad),
            ctypes.byref(ciphertext.struct), ctypes.byref(nonce.struct), ctypes.byref(tag.struct),
        )
        _raise_for(ret)
        return Sm4GcmCiphertext(ciphertext=ciphertext.data, nonce=nonce.data, tag=tag.data)

    def sm4_gcm_decrypt(
        self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes
    ) -> bytes:
        require_exact_length(key, SM4_KEY_SIZE)
        require_exact_length(nonce, GCM_NONCE_SIZE)
        require_exact_length(tag, GCM_TAG_SIZE)
        plaintext = _bridge.allocate(len(ciphertext))
        key_buf = _bridge.ro(key)
        nonce_buf = _bridge.ro(nonce)
        ct_buf = _bridge.ro(ciphertext)
        aad_buf = _bridge.ro(aad)
        tag_buf = _bridge.ro(tag)
        ret = self._lib.cc_bridge_sm4_gcm_decrypt(
            key_buf.struct.data, nonce_buf.struct.data, ct_buf.struct.data, len(ciphertext),
            aad_buf.struct.data, len(aad), tag_buf.struct.data, len(tag),
            ctypes.byref(plaintext.struct),
        )
        _raise_for(ret)
        return plaintext.data

    # ---------------------------------------------------------------- SM2
    def sm2_generate_keypair(self) -> Sm2KeyPair:
        private_key = _bridge.allocate(SM2_PRIVATE_KEY_SIZE)
        public_key = _bridge.allocate(SM2_PUBLIC_KEY_SIZE)
        ret = self._lib.cc_bridge_sm2_generate_keypair(
            ctypes.byref(private_key.struct), ctypes.byref(public_key.struct)
        )
        _raise_for(ret)
        return Sm2KeyPair(private_key=private_key.data, public_key=public_key.data)

    def sm2_sign(self, private_key: bytes, digest: bytes) -> bytes:
        require_exact_length(private_key, SM2_PRIVATE_KEY_SIZE)
        require_exact_length(digest, SM3_DIGEST_SIZE)
        signature = _bridge.allocate(SM2_SIGNATURE_SIZE)
        priv = _bridge.ro(private_key)
        dg = _bridge.ro(digest)
        ret = self._lib.cc_bridge_sm2_sign(priv.struct.data, dg.struct.data, ctypes.byref(signature.struct))
        _raise_for(ret)
        return signature.data

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        require_exact_length(public_key, SM2_PUBLIC_KEY_SIZE)
        require_exact_length(digest, SM3_DIGEST_SIZE)
        require_exact_length(signature, SM2_SIGNATURE_SIZE)
        pub = _bridge.ro(public_key)
        dg = _bridge.ro(digest)
        sig = _bridge.ro(signature)
        ret = self._lib.cc_bridge_sm2_verify(
            pub.struct.data, dg.struct.data, sig.struct.data, len(signature)
        )
        _raise_for(ret)
        return ret == 1

    def sm2_ecdh(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        require_exact_length(private_key, SM2_PRIVATE_KEY_SIZE)
        require_exact_length(peer_public_key, SM2_PUBLIC_KEY_SIZE)
        shared = _bridge.allocate(32)
        priv = _bridge.ro(private_key)
        peer = _bridge.ro(peer_public_key)
        ret = self._lib.cc_bridge_sm2_ecdh(priv.struct.data, peer.struct.data, ctypes.byref(shared.struct))
        _raise_for(ret)
        return shared.data

    # ---------------------------------------------------------------- PKI
    def csr_create(
        self, private_key: bytes, public_key: bytes, common_name: str, role: str
    ) -> bytes:
        require_exact_length(private_key, SM2_PRIVATE_KEY_SIZE)
        require_exact_length(public_key, SM2_PUBLIC_KEY_SIZE)
        if not isinstance(common_name, str) or not common_name:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        if not isinstance(role, str) or role not in _ALLOWED_ROLES:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        out = _bridge.allocate(4096)
        priv = _bridge.ro(private_key)
        pub = _bridge.ro(public_key)
        cn = common_name.encode("utf-8")
        ret = self._lib.cc_bridge_csr_create(
            priv.struct.data, len(private_key), pub.struct.data, len(public_key),
            cn, ctypes.byref(out.struct),
        )
        _raise_for(ret)
        return out.data

    def cert_sign(
        self,
        csr_der: bytes,
        ca_certificate_der: bytes,
        ca_private_key: bytes,
        not_before: int,
        not_after: int,
        key_usage: tuple[str, ...],
    ) -> SignedCertificate:
        _require_der(csr_der)
        if ca_certificate_der:
            _require_der(ca_certificate_der)
        elif key_usage != ("keyCertSign", "cRLSign"):
            # An empty issuer certificate is accepted only for the one-time
            # creation of a self-signed platform root.  Leaf issuance must
            # always name an existing CA certificate.
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(ca_private_key, SM2_PRIVATE_KEY_SIZE)
        _require_time_range(not_before, not_after)
        _require_key_usage(key_usage)
        cert = _bridge.allocate(MAX_DER_CERTIFICATE_SIZE)
        serial = _bridge.allocate(_CERT_SERIAL_BYTES)
        csr = _bridge.ro(csr_der)
        ca = _bridge.ro(ca_certificate_der)
        key = _bridge.ro(ca_private_key)
        ret = self._lib.cc_bridge_cert_sign(
            csr.struct.data, len(csr_der), ca.struct.data, len(ca_certificate_der),
            key.struct.data, len(ca_private_key), not_before, not_after,
            _key_usage_bits(key_usage),
            ctypes.byref(cert.struct), ctypes.byref(serial.struct),
        )
        _raise_for(ret)
        return SignedCertificate(
            der=cert.data,
            serial=serial.data.hex(),
            not_before=not_before,
            not_after=not_after,
        )

    def cert_chain_verify(
        self,
        leaf_certificate_der: bytes,
        certificate_chain_der: tuple[bytes, ...],
        trust_root_der: bytes,
        verification_time: int,
        required_key_usage: tuple[str, ...],
    ) -> bool:
        _require_der(leaf_certificate_der)
        _require_der(trust_root_der)
        if not isinstance(certificate_chain_der, tuple) or type(verification_time) is not int:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        for certificate_der in certificate_chain_der:
            _require_der(certificate_der)
        _require_key_usage(required_key_usage)
        chain_blob = b"".join(certificate_chain_der)
        leaf = _bridge.ro(leaf_certificate_der)
        chain = _bridge.ro(chain_blob)
        root = _bridge.ro(trust_root_der)
        ret = self._lib.cc_bridge_cert_chain_verify(
            leaf.struct.data, len(leaf_certificate_der),
            chain.struct.data, len(chain_blob),
            root.struct.data, len(trust_root_der),
            verification_time, _key_usage_bits(required_key_usage),
        )
        _raise_for(ret)
        return ret == 1

    def crl_create(
        self,
        revoked_serials: tuple[str, ...],
        ca_certificate_der: bytes,
        ca_private_key: bytes,
        this_update: int,
        next_update: int,
    ) -> CrlArtifact:
        if not isinstance(revoked_serials, tuple) or not all(
            isinstance(serial, str) and serial for serial in revoked_serials
        ):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        _require_der(ca_certificate_der)
        require_exact_length(ca_private_key, SM2_PRIVATE_KEY_SIZE)
        _require_time_range(this_update, next_update)
        crl = _bridge.allocate(4 * 1024 * 1024)
        serials_blob = ",".join(revoked_serials).encode("utf-8")
        serials = _bridge.ro(serials_blob)
        ca = _bridge.ro(ca_certificate_der)
        key = _bridge.ro(ca_private_key)
        ret = self._lib.cc_bridge_crl_create(
            serials.struct.data, len(serials_blob),
            ca.struct.data, len(ca_certificate_der),
            key.struct.data, len(ca_private_key),
            this_update, next_update, ctypes.byref(crl.struct),
        )
        _raise_for(ret)
        return CrlArtifact(der=crl.data, this_update=this_update, next_update=next_update)

    def crl_verify(
        self, certificate_der: bytes, crl_der: bytes, verification_time: int
    ) -> bool:
        _require_der(certificate_der)
        if not isinstance(crl_der, bytes) or not crl_der or len(crl_der) > 4 * 1024 * 1024:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        if type(verification_time) is not int:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        cert = _bridge.ro(certificate_der)
        crl = _bridge.ro(crl_der)
        ret = self._lib.cc_bridge_crl_verify(
            cert.struct.data, len(certificate_der), crl.struct.data, len(crl_der), verification_time
        )
        _raise_for(ret)
        return ret == 1

    # ------------------------------------------------------------ 数字信封
    def envelope_seal(
        self,
        *,
        plaintext: bytes,
        recipient_sm2_public_key: bytes,
        pqc_mode: bool,
        recipient_mlkem_public_key: bytes | None,
        sender_private_key: bytes,
        sender_certificate_der: bytes,
        access_factor: bytes | None,
    ) -> EnvelopeArtifact:
        if not isinstance(plaintext, bytes) or not plaintext or len(plaintext) > MAX_DROP_CONTENT_SIZE:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(recipient_sm2_public_key, SM2_PUBLIC_KEY_SIZE)
        if not isinstance(pqc_mode, bool):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        if pqc_mode:
            # 桥接层 ML-KEM 未实现前，直接在此 fail-closed
            raise CryptoBridgeError(BridgeErrorCode.UNSUPPORTED)
        if recipient_mlkem_public_key is not None:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(sender_private_key, SM2_PRIVATE_KEY_SIZE)
        _require_der(sender_certificate_der)
        if access_factor is not None:
            if not isinstance(access_factor, bytes) or not 16 <= len(access_factor) <= 32:
                raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)

        ciphertext = _bridge.allocate(len(plaintext) + 16)
        nonce = _bridge.allocate(GCM_NONCE_SIZE)
        tag = _bridge.allocate(GCM_TAG_SIZE)
        enc_key_sm2 = _bridge.allocate(MAX_SM2_ENC_KEY_SIZE)
        enc_key_mlkem = _bridge.RoBuffer(None)
        sender_signature = _bridge.allocate(SM2_SIGNATURE_SIZE)
        sender_certificate = _bridge.allocate(len(sender_certificate_der))

        env = _bridge.BridgeEnvelope(
            ciphertext.struct, nonce.struct, tag.struct,
            enc_key_sm2.struct, enc_key_mlkem.struct,
            sender_signature.struct, sender_certificate.struct,
        )
        pt = _bridge.ro(plaintext)
        recipient = _bridge.ro(recipient_sm2_public_key)
        sender_priv = _bridge.ro(sender_private_key)
        sender_cert = _bridge.ro(sender_certificate_der)
        factor = _bridge.ro(access_factor)
        ret = self._lib.cc_bridge_envelope_seal(
            pt.struct.data, len(plaintext),
            recipient.struct.data, 1 if pqc_mode else 0, None,
            sender_priv.struct.data,
            sender_cert.struct.data, len(sender_certificate_der),
            factor.struct.data, len(access_factor) if access_factor else 0,
            ctypes.byref(env),
        )
        _raise_for(ret)
        return EnvelopeArtifact(
            ciphertext=_nested_output(ciphertext, env.ciphertext),
            nonce=_nested_output(nonce, env.nonce),
            tag=_nested_output(tag, env.tag),
            enc_key_sm2=_nested_output(enc_key_sm2, env.enc_key_sm2),
            enc_key_mlkem=None,
            sender_signature=_nested_output(sender_signature, env.sender_signature),
            sender_certificate=_nested_output(sender_certificate, env.sender_certificate),
        )

    def envelope_open(
        self,
        *,
        envelope: EnvelopeArtifact,
        recipient_sm2_private_key: bytes,
        pqc_mode: bool,
        recipient_mlkem_private_key: bytes | None,
        access_factor: bytes | None,
    ) -> bytes:
        if not isinstance(envelope, EnvelopeArtifact):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(recipient_sm2_private_key, SM2_PRIVATE_KEY_SIZE)
        if not isinstance(pqc_mode, bool):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        if pqc_mode:
            raise CryptoBridgeError(BridgeErrorCode.UNSUPPORTED)
        if recipient_mlkem_private_key is not None:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        if access_factor is not None:
            if not isinstance(access_factor, bytes) or not 16 <= len(access_factor) <= 32:
                raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)

        ciphertext = _bridge.ro(envelope.ciphertext)
        nonce = _bridge.ro(envelope.nonce)
        tag = _bridge.ro(envelope.tag)
        enc_key_sm2 = _bridge.ro(envelope.enc_key_sm2)
        enc_key_mlkem = _bridge.ro(envelope.enc_key_mlkem)
        signature = _bridge.ro(envelope.sender_signature)
        certificate = _bridge.ro(envelope.sender_certificate)
        env = _bridge.BridgeEnvelope(
            ciphertext.struct, nonce.struct, tag.struct,
            enc_key_sm2.struct, enc_key_mlkem.struct,
            signature.struct, certificate.struct,
        )
        plaintext = _bridge.allocate(len(envelope.ciphertext) + 16)
        recipient_priv = _bridge.ro(recipient_sm2_private_key)
        factor = _bridge.ro(access_factor)
        ret = self._lib.cc_bridge_envelope_open(
            ctypes.byref(env),
            recipient_priv.struct.data, 1 if pqc_mode else 0, None,
            factor.struct.data, len(access_factor) if access_factor else 0,
            ctypes.byref(plaintext.struct),
        )
        _raise_for(ret)
        return plaintext.data

    # ------------------------------------------------------------ 盲签名
    def blind_commit(self) -> tuple[bytes, bytes]:
        """第一轮（签名方生成一次性承诺）：k in [1, n-1]，R = [k]G。
        k 为 32 字节标量，必须留在服务端用后即删；R 为 65 字节未压缩点（0x04 || X || Y）。
        """
        k = _bridge.allocate(32)
        r = _bridge.allocate(65)
        ret = self._lib.cc_bridge_sm2_blind_commit(
            ctypes.byref(k.struct), ctypes.byref(r.struct)
        )
        _raise_for(ret)
        if k.struct.len != 32 or r.struct.len != 65 or r.data[0] != 0x04:
            raise CryptoBridgeError(BridgeErrorCode.INTERNAL_ERROR)
        return k.data, r.data

    def blind_sign(
        self,
        *,
        blinded_message: bytes,
        signer_private_key: bytes,
        secret_k: bytes | None = None,
    ) -> bytes:
        """第三轮（签名方签名）：s' = (k + c'·d) mod n。"""
        if not isinstance(blinded_message, bytes) or not blinded_message:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(signer_private_key, SM2_PRIVATE_KEY_SIZE)

        # 兼容处理：若传入 48 字节 (16B commitment_id || 32B c')
        c_prime = blinded_message[16:] if len(blinded_message) == 48 else blinded_message
        if len(c_prime) != 32 or secret_k is None or len(secret_k) != SM2_PRIVATE_KEY_SIZE:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)

        k_ro = _bridge.ro(secret_k)
        cp_ro = _bridge.ro(c_prime)
        priv_ro = _bridge.ro(signer_private_key)
        s_prime = _bridge.allocate(32)

        ret = self._lib.cc_bridge_sm2_blind_sign(
            k_ro.struct.data,
            cp_ro.struct.data,
            priv_ro.struct.data,
            ctypes.byref(s_prime.struct),
        )
        _raise_for(ret)
        if s_prime.struct.len != 32:
            raise CryptoBridgeError(BridgeErrorCode.INTERNAL_ERROR)
        return s_prime.data

    def blind_verify(
        self, *, message: bytes, signature: bytes, signer_public_key: bytes
    ) -> bool:
        """第五轮（任意验签方）：x-only 验签。
        signature 严格为 64 字节凭证: R'_x(32) || s(32)。
        message 为规范化消息 M = SN || service || period。
        signer_public_key 为 65 字节未压缩公钥 (0x04 || X || Y)。
        """
        if not isinstance(message, bytes) or not message:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(signature, 64)
        require_exact_length(signer_public_key, SM2_PUBLIC_KEY_SIZE)

        sig_ro = _bridge.ro(signature)
        msg_ro = _bridge.ro(message)
        pub_ro = _bridge.ro(signer_public_key)

        ret = self._lib.cc_client_verify(
            sig_ro.struct.data,
            msg_ro.struct.data,
            len(message),
            pub_ro.struct.data,
        )
        if ret < 0:
            _raise_for(ret)
        return ret == 1
