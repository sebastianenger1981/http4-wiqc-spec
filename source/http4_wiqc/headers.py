"""
HTTP/4 Header Fields, ABNF Parser, Integrity Digests, Origin Message Signatures,
and Service Discovery (Alt-Svc & SVCB/HTTPS).

Implements Section 5.3, Section 7 (Formal ABNF), and Section 9.2 of
`draft-enger-httpbis-http4-wiqc-00`:

1. **`WIQC-Swarm-Info` Formal ABNF (Section 7, RFC 5234)**:
   ```abnf
   WIQC-Swarm-Info = "swarm-id=" byte-sequence ";"
                     "mode=" ( "merkle-v2" / "unified-live" )
                     [ ";window=" 1*DIGIT ]
                     [ ";chunk-addr=" ( "bin32" / "bin64" ) ]
   byte-sequence   = ":" *( BASE64CHAR ) ":"
   BASE64CHAR      = ALPHA / DIGIT / "+" / "/" / "="
   ```
2. **Representation Digest (`Repr-Digest`, `Content-Digest`, `Swarm-Root`, RFC 9530)**:
   - Static HTTP/4 responses MUST carry `Repr-Digest: sha-256=:<b64>:` and
     `Swarm-Root: pieces-root=:<b64>:`.
3. **Origin Message Signatures (`Signature-Input` & `Signature`, RFC 9421)**:
   - Authoritative publisher signs `("@status" "content-type" "repr-digest" "wiqc-swarm-id")`
     with Ed25519 so any untrusted swarm relay can forward headers while any receiving
     client cryptographically verifies origin authenticity!
4. **Alternative Service & DNS Discovery (`Alt-Svc` RFC 7838 & `SVCB`/`HTTPS` RFC 9460)**:
   - Advertises `"h4"` (and optional `"wiqc"`) ALPN endpoints for seamless upgrade
     from unicast HTTP/3 to decentralized HTTP/4 swarms.
5. **Extensible HTTP Priority (`Priority`, RFC 9218)**:
   - Parses and formats `u=0..7, i` urgency and incremental flags feeding the WIQC
     Dual-Zone EDF/Rarest-First scheduler.
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass

from .crypto import Ed25519PrivateKey, Ed25519PublicKey
from .exceptions import HeaderSyntaxError, IntegrityVerificationError

# Exact regex compiled directly from the Section 7 ABNF grammar
_SWARM_INFO_RE = re.compile(
    r"^swarm-id=:(?P<swarm_id>[A-Za-z0-9+/=]*):;"
    r"mode=(?P<mode>merkle-v2|unified-live)"
    r"(?:;window=(?P<window>[0-9]+))?"
    r"(?:;chunk-addr=(?P<chunk_addr>bin32|bin64))?$"
)

_BYTE_SEQ_RE = re.compile(r"^:(?P<b64>[A-Za-z0-9+/=]*):$")


# =============================================================================
# 1. WIQC-Swarm-Info Header (Section 7 Formal ABNF)
# =============================================================================


@dataclass(frozen=True)
class WIQCSwarmInfo:
    """Parsed representation of the `WIQC-Swarm-Info` HTTP/4 header field."""

    swarm_id: bytes
    mode: str  # "merkle-v2" or "unified-live"
    window: int | None = None
    chunk_addr: str | None = None  # "bin32" or "bin64"

    def __post_init__(self) -> None:
        if len(self.swarm_id) != 32:
            raise HeaderSyntaxError(f"swarm-id must be 32 bytes, got {len(self.swarm_id)}")
        if self.mode not in ("merkle-v2", "unified-live"):
            raise HeaderSyntaxError(f"Unsupported mode: {self.mode!r}")
        if self.window is not None and self.window < 0:
            raise HeaderSyntaxError(f"window must be non-negative: {self.window}")
        if self.chunk_addr is not None and self.chunk_addr not in ("bin32", "bin64"):
            raise HeaderSyntaxError(f"Invalid chunk-addr: {self.chunk_addr!r}")

    def format(self) -> str:
        """Serialize strictly conforming to the Section 7 ABNF grammar."""
        b64 = base64.b64encode(self.swarm_id).decode("ascii")
        parts = [f"swarm-id=:{b64}:", f"mode={self.mode}"]
        if self.window is not None:
            parts.append(f"window={self.window}")
        if self.chunk_addr is not None:
            parts.append(f"chunk-addr={self.chunk_addr}")
        return ";".join(parts)

    @classmethod
    def parse(cls, header_value: str) -> WIQCSwarmInfo:
        """Strictly parse a `WIQC-Swarm-Info` header value against Section 7 ABNF."""
        m = _SWARM_INFO_RE.match(header_value.strip())
        if not m:
            raise HeaderSyntaxError(
                f"WIQC-Swarm-Info violates Section 7 ABNF grammar: {header_value!r}"
            )
        try:
            swarm_id = base64.b64decode(m.group("swarm_id"), validate=True)
        except Exception as exc:
            raise HeaderSyntaxError(f"Invalid base64 in swarm-id: {exc}") from exc
        if len(swarm_id) != 32:
            raise HeaderSyntaxError(f"Decoded swarm-id must be 32 bytes, got {len(swarm_id)}")
        win_str = m.group("window")
        window = int(win_str) if win_str is not None else None
        chunk_addr = m.group("chunk_addr")
        return cls(
            swarm_id=swarm_id,
            mode=m.group("mode"),
            window=window,
            chunk_addr=chunk_addr,
        )


# =============================================================================
# 2. RFC 9530 Representation Digests & Swarm-Root
# =============================================================================


def format_repr_digest(data_or_sha256: bytes, already_hashed: bool = False) -> str:
    """Format an RFC 9530 `Repr-Digest` / `Content-Digest` SHA-256 structured field."""
    digest = data_or_sha256 if already_hashed else hashlib.sha256(data_or_sha256).digest()
    if len(digest) != 32:
        raise HeaderSyntaxError("SHA-256 digest must be 32 bytes")
    return f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"


def parse_repr_digest(header_value: str) -> bytes:
    """Parse `sha-256=:<base64>:` from an RFC 9530 `Repr-Digest` or `Content-Digest` header."""
    for item in header_value.split(","):
        item = item.strip()
        if item.startswith("sha-256="):
            val = item[len("sha-256=") :].strip()
            m = _BYTE_SEQ_RE.match(val)
            if not m:
                raise HeaderSyntaxError(f"Malformed byte-sequence in digest: {header_value!r}")
            digest = base64.b64decode(m.group("b64"), validate=True)
            if len(digest) != 32:
                raise HeaderSyntaxError("Decoded sha-256 digest must be 32 bytes")
            return digest
    raise HeaderSyntaxError(f"No sha-256 entry in digest header: {header_value!r}")


def format_swarm_root(pieces_root: bytes) -> str:
    """Format the `Swarm-Root` dictionary field carrying the 32-byte BEP 52 pieces root."""
    if len(pieces_root) != 32:
        raise HeaderSyntaxError("pieces_root must be 32 bytes")
    return f"pieces-root=:{base64.b64encode(pieces_root).decode('ascii')}:"


def parse_swarm_root(header_value: str) -> bytes:
    """Parse `pieces-root=:<base64>:` from a `Swarm-Root` dictionary header."""
    for item in header_value.split(","):
        item = item.strip()
        if item.startswith("pieces-root="):
            val = item[len("pieces-root=") :].strip()
            m = _BYTE_SEQ_RE.match(val)
            if not m:
                raise HeaderSyntaxError(f"Malformed Swarm-Root byte-sequence: {header_value!r}")
            root = base64.b64decode(m.group("b64"), validate=True)
            if len(root) != 32:
                raise HeaderSyntaxError("Decoded Swarm-Root must be 32 bytes")
            return root
    raise HeaderSyntaxError(f"Missing pieces-root in Swarm-Root header: {header_value!r}")


# =============================================================================
# 3. RFC 9421 Origin HTTP Message Signatures (Ed25519)
# =============================================================================

DEFAULT_SIGNED_COMPONENTS = ("@status", "content-type", "repr-digest", "wiqc-swarm-id")


def _build_rfc9421_signature_base(
    headers: dict[str, str],
    covered_components: tuple[str, ...],
    sig_params: str,
) -> bytes:
    """
    Construct the canonical RFC 9421 Section 2.5 signature base string.
    Header keys are normalized to lowercase; pseudo-headers use RFC 9421 derived
    component syntax (`@status`, `@authority`, `@path`, etc.).
    """
    lower_headers = {k.lower(): v.strip() for k, v in headers.items()}
    lines: list[str] = []
    for comp in covered_components:
        comp_l = comp.lower()
        # Map RFC 9421 derived component `@status` to HTTP/4 pseudo-header `:status`
        lookup_key = f":{comp_l[1:]}" if comp_l.startswith("@") else comp_l
        val = lower_headers.get(comp_l)
        if val is None:
            val = lower_headers.get(lookup_key)
        if val is None:
            raise HeaderSyntaxError(
                f"Cannot construct RFC 9421 signature base: missing component {comp!r}"
            )
        lines.append(f'"{comp_l}": {val}')
    lines.append(f'"@signature-params": {sig_params}')
    return "\n".join(lines).encode("ascii")


def sign_http4_headers(
    headers: dict[str, str],
    origin_private_key: Ed25519PrivateKey,
    key_id: str | None = None,
    covered_components: tuple[str, ...] = DEFAULT_SIGNED_COMPONENTS,
    label: str = "origin",
    created: int | None = None,
) -> dict[str, str]:
    """
    Sign HTTP/4 response metadata per RFC 9421 (Section 5.3.2 of the draft).

    Returns a new header dict containing `signature-input` and `signature` so
    that untrusted swarm relays can forward headers without breaking origin trust.
    """
    ts = int(time.time()) if created is None else created
    kid = key_id or origin_private_key.public_key().fingerprint().hex()[:16]
    comp_list = " ".join(f'"{c.lower()}"' for c in covered_components)
    sig_params = f'({comp_list});created={ts};keyid="{kid}";alg="ed25519"'
    sig_base = _build_rfc9421_signature_base(headers, covered_components, sig_params)
    sig_bytes = origin_private_key.sign(sig_base)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    out = dict(headers)
    out["signature-input"] = f"{label}={sig_params}"
    out["signature"] = f"{label}=:{sig_b64}:"
    return out


def verify_http4_headers(
    headers: dict[str, str],
    origin_public_key: Ed25519PublicKey,
    required_components: tuple[str, ...] = DEFAULT_SIGNED_COMPONENTS,
    label: str = "origin",
) -> bool:
    """
    Verify RFC 9421 `Signature-Input` and `Signature` headers against the
    authoritative origin publisher's Ed25519 public key.

    Ensures all `required_components` (`@status`, `content-type`, `repr-digest`,
    `wiqc-swarm-id`) are covered by the signature.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    sig_input_hdr = lower_headers.get("signature-input")
    sig_hdr = lower_headers.get("signature")
    if not sig_input_hdr or not sig_hdr:
        raise IntegrityVerificationError("Missing RFC 9421 Signature-Input or Signature header")

    prefix = f"{label}="
    if not sig_input_hdr.startswith(prefix) or not sig_hdr.startswith(prefix):
        raise IntegrityVerificationError(f"Expected RFC 9421 label {label!r}")

    sig_params = sig_input_hdr[len(prefix) :].strip()
    sig_val = sig_hdr[len(prefix) :].strip()

    m_sig = _BYTE_SEQ_RE.match(sig_val)
    if not m_sig:
        raise IntegrityVerificationError("Malformed RFC 9421 Signature byte sequence")
    signature_bytes = base64.b64decode(m_sig.group("b64"), validate=True)

    # Extract covered component list from `("comp1" "comp2" ...);...`
    m_comps = re.match(r"^\(([^)]*)\)", sig_params)
    if not m_comps:
        raise IntegrityVerificationError(f"Malformed Signature-Input params: {sig_params!r}")
    covered = tuple(re.findall(r'"([^"]+)"', m_comps.group(1)))

    for req in required_components:
        if req.lower() not in covered:
            raise IntegrityVerificationError(
                f"RFC 9421 signature missing mandatory component {req!r} (covered={covered})"
            )

    sig_base = _build_rfc9421_signature_base(headers, covered, sig_params)
    if not origin_public_key.verify(signature_bytes, sig_base):
        raise IntegrityVerificationError("RFC 9421 Origin Message Signature verification FAILED")
    return True


# =============================================================================
# 4. Alternative Service (RFC 7838) & SVCB/HTTPS DNS Discovery (RFC 9460)
# =============================================================================


@dataclass(frozen=True)
class AltSvcEntry:
    protocol_id: str  # e.g. "h4", "h3"
    authority: str  # e.g. ":4433" or "swarm.example:4433"
    max_age: int = 86400

    def format(self) -> str:
        return f'{self.protocol_id}="{self.authority}"; ma={self.max_age}'


def format_alt_svc(entries: list[AltSvcEntry]) -> str:
    """Format an RFC 7838 `Alt-Svc` header advertising HTTP/4 (`h4`) upgrade."""
    return ", ".join(e.format() for e in entries)


def parse_alt_svc(header_value: str) -> list[AltSvcEntry]:
    """Parse an RFC 7838 `Alt-Svc` header into structured entries."""
    entries: list[AltSvcEntry] = []
    for part in header_value.split(","):
        part = part.strip()
        if not part or part == "clear":
            continue
        m = re.match(r'^([A-Za-z0-9._-]+)="([^"]+)"(.*)$', part)
        if not m:
            raise HeaderSyntaxError(f"Malformed Alt-Svc entry: {part!r}")
        proto, auth, params = m.group(1), m.group(2), m.group(3)
        ma = 86400
        m_ma = re.search(r";\s*ma=(\d+)", params)
        if m_ma:
            ma = int(m_ma.group(1))
        entries.append(AltSvcEntry(protocol_id=proto, authority=auth, max_age=ma))
    return entries


@dataclass(frozen=True)
class HTTPSServiceRecord:
    """
    RFC 9460 DNS `HTTPS` / `SVCB` Resource Record advertising HTTP/4 (`h4`)
    and raw WIQC (`wiqc`) ALPN endpoints for zero-round-trip discovery.
    """

    priority: int
    target_name: str
    alpn: tuple[str, ...] = ("h4", "wiqc")
    port: int | None = None
    ipv4hint: tuple[str, ...] = ()
    ipv6hint: tuple[str, ...] = ()

    def to_zone_text(self) -> str:
        params: list[str] = []
        if self.alpn:
            params.append(f'alpn="{",".join(self.alpn)}"')
        if self.port is not None:
            params.append(f"port={self.port}")
        if self.ipv4hint:
            params.append(f"ipv4hint={','.join(self.ipv4hint)}")
        if self.ipv6hint:
            params.append(f"ipv6hint={','.join(self.ipv6hint)}")
        return f"{self.priority} {self.target_name} " + " ".join(params)

    @classmethod
    def from_zone_text(cls, text: str) -> HTTPSServiceRecord:
        tokens = text.strip().split()
        if len(tokens) < 2:
            raise HeaderSyntaxError(f"Invalid SVCB/HTTPS record: {text!r}")
        priority = int(tokens[0])
        target = tokens[1]
        alpn: tuple[str, ...] = ()
        port: int | None = None
        v4: tuple[str, ...] = ()
        v6: tuple[str, ...] = ()
        for tok in tokens[2:]:
            if "=" not in tok:
                continue
            k, v = tok.split("=", 1)
            v_clean = v.strip('"')
            if k == "alpn":
                alpn = tuple(x.strip() for x in v_clean.split(",") if x.strip())
            elif k == "port":
                port = int(v_clean)
            elif k == "ipv4hint":
                v4 = tuple(x.strip() for x in v_clean.split(",") if x.strip())
            elif k == "ipv6hint":
                v6 = tuple(x.strip() for x in v_clean.split(",") if x.strip())
        return cls(
            priority=priority,
            target_name=target,
            alpn=alpn,
            port=port,
            ipv4hint=v4,
            ipv6hint=v6,
        )


# =============================================================================
# 5. RFC 9218 Extensible HTTP Priority Signaling
# =============================================================================


@dataclass(frozen=True)
class HTTP4Priority:
    """RFC 9218 HTTP Priority header (`u=0..7, i`), extended for WIQC EDF scheduling."""

    urgency: int = 3  # 0 (highest) .. 7 (lowest)
    incremental: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.urgency <= 7:
            raise HeaderSyntaxError(f"RFC 9218 urgency must be in 0..7, got {self.urgency}")

    def format(self) -> str:
        return f"u={self.urgency}, i" if self.incremental else f"u={self.urgency}"

    @classmethod
    def parse(cls, value: str) -> HTTP4Priority:
        urgency = 3
        incremental = False
        for tok in value.split(","):
            tok = tok.strip()
            if tok.startswith("u="):
                urgency = int(tok[2:])
            elif tok == "i" or tok == "i=?1":
                incremental = True
            elif tok == "i=?0":
                incremental = False
        return cls(urgency=urgency, incremental=incremental)
