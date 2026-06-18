"""
audit_ledger.py
═══════════════════════════════════════════════════════════════════
NOESIS / AEGIS-NET — Tamper-Evident Audit Ledger

Cryptographically chained, append-only record of every significant
system event. Each entry:
  - Links to the previous entry via SHA-256 hash chain
  - Is HMAC-SHA256 signed with the supervisor key
  - Is written atomically to JSONL (authoritative) + ChromaDB (search)

SUPERVISOR calls verify_chain() to detect any tampering, deletion,
or reordering of the historical record.

Integration:
  opa_gateway.py   → log_opa_decision()
  scan_hardening.py → log_scan_result()
  aegis_v3.py      → log_agent_action(), log_tier_change()
  start.py         → log_system_event("BOOT")

BRA governance: append is open to all agents; read/verify is
gated to ALPHA tier (enforced by OPA, not this module).
═══════════════════════════════════════════════════════════════════
"""

import os
import hmac
import json
import time
import hashlib
import logging
from uuid import uuid4
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List
from enum import Enum

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("NOESIS.AuditLedger")

# ── Constants ─────────────────────────────────────────────────────────────────
_LEDGER_SECRET = os.environ.get(
    "SUPERVISOR_HMAC_KEY",
    "noesis-supervisor-default-key-change-in-production",
).encode()

_DEFAULT_LEDGER_PATH = os.environ.get(
    "AUDIT_LEDGER_PATH",
    "./aegis_audit_ledger.jsonl",
)

GENESIS_HASH = "0" * 64  # sentinel — previous_hash of the very first entry


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════════════════

class EventType(str, Enum):
    AGENT_ACTION  = "AGENT_ACTION"
    SCAN_RESULT   = "SCAN_RESULT"
    TIER_CHANGE   = "TIER_CHANGE"
    OPA_DECISION  = "OPA_DECISION"
    JWT_EVENT     = "JWT_EVENT"
    SYSTEM_EVENT  = "SYSTEM_EVENT"
    DEMOTION      = "DEMOTION"
    PROMOTION     = "PROMOTION"
    LOOP_DETECTED = "LOOP_DETECTED"
    QUORUM_FAILED = "QUORUM_FAILED"
    WITNESS_ALERT = "WITNESS_ALERT"


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class LedgerEntry:
    entry_id:      str
    event_type:    EventType
    agent_id:      str
    actor:         str        # module / agent that generated this event
    payload:       dict
    previous_hash: str        # SHA-256 of the prior entry — the chain link
    timestamp:     float      = field(default_factory=time.time)
    entry_hash:    str        = ""   # SHA-256 of core fields; computed on sign()
    hmac_signature: str       = ""   # HMAC-SHA256(entry_hash, SUPERVISOR_HMAC_KEY)

    # ── Crypto ─────────────────────────────────────────────────────────────

    def compute_hash(self) -> str:
        payload_hash = hashlib.sha256(
            json.dumps(self.payload, sort_keys=True).encode()
        ).hexdigest()
        content = json.dumps(
            {
                "entry_id":      self.entry_id,
                "event_type":    self.event_type,
                "agent_id":      self.agent_id,
                "actor":         self.actor,
                "payload_hash":  payload_hash,
                "previous_hash": self.previous_hash,
                "timestamp":     self.timestamp,
            },
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def sign(self, secret_key: bytes) -> "LedgerEntry":
        self.entry_hash = self.compute_hash()
        self.hmac_signature = hmac.new(
            secret_key,
            self.entry_hash.encode(),
            hashlib.sha256,
        ).hexdigest()
        return self

    # ── Serialisation ──────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "entry_id":      self.entry_id,
            "event_type":    self.event_type.value,
            "agent_id":      self.agent_id,
            "actor":         self.actor,
            "payload":       self.payload,
            "previous_hash": self.previous_hash,
            "timestamp":     self.timestamp,
            "entry_hash":    self.entry_hash,
            "hmac_signature": self.hmac_signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "LedgerEntry":
        return cls(
            entry_id=      d["entry_id"],
            event_type=    EventType(d["event_type"]),
            agent_id=      d["agent_id"],
            actor=         d["actor"],
            payload=       d["payload"],
            previous_hash= d["previous_hash"],
            timestamp=     d["timestamp"],
            entry_hash=    d.get("entry_hash", ""),
            hmac_signature=d.get("hmac_signature", ""),
        )


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT LEDGER
# ═══════════════════════════════════════════════════════════════════════════════

class AuditLedger:
    """
    Append-only, HMAC-signed, hash-chained audit log.

    JSONL file is authoritative.  ChromaDB is the secondary index for
    semantic / filtered queries; if it is unavailable the ledger degrades
    gracefully to file-only operation.
    """

    def __init__(
        self,
        chroma_client=None,
        ledger_path: str = _DEFAULT_LEDGER_PATH,
        secret_key: Optional[bytes] = None,
    ):
        self.chroma_client = chroma_client
        self.ledger_path   = Path(ledger_path)
        self.secret_key    = secret_key or _LEDGER_SECRET
        self._tail_hash    = self._load_tail_hash()

        logger.info(
            f"[LEDGER] Initialised — path={self.ledger_path} "
            f"tail={self._tail_hash[:12]}…"
        )

    # ── Public API ─────────────────────────────────────────────────────────

    def append(
        self,
        event_type: EventType,
        agent_id:   str,
        actor:      str,
        payload:    dict,
    ) -> LedgerEntry:
        """
        Create, sign, and persist a new ledger entry.
        Returns the entry so callers can log the entry_id if needed.
        """
        entry = LedgerEntry(
            entry_id=      str(uuid4()),
            event_type=    event_type,
            agent_id=      agent_id,
            actor=         actor,
            payload=       payload,
            previous_hash= self._tail_hash,
        ).sign(self.secret_key)

        self._write_entry(entry)
        self._tail_hash = entry.entry_hash

        logger.info(
            f"[LEDGER] +{event_type.value} | agent={agent_id} "
            f"actor={actor} | id={entry.entry_id[:8]}"
        )
        return entry

    def verify_chain(self) -> bool:
        """
        Walk the entire JSONL file, recompute every hash, verify every
        HMAC signature, and confirm previous_hash links are unbroken.
        Returns True if the ledger is intact, False if tampered.
        """
        entries    = self._load_all_entries()
        prev_hash  = GENESIS_HASH
        ok         = True

        for entry in entries:
            # 1. Chain continuity
            if entry.previous_hash != prev_hash:
                logger.error(
                    f"[LEDGER] Chain break before entry {entry.entry_id[:8]}"
                )
                ok = False
                break

            # 2. Entry hash integrity
            expected_hash = entry.compute_hash()
            if entry.entry_hash != expected_hash:
                logger.error(
                    f"[LEDGER] Hash mismatch at {entry.entry_id[:8]}"
                )
                ok = False
                break

            # 3. HMAC signature
            expected_hmac = hmac.new(
                self.secret_key,
                entry.entry_hash.encode(),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected_hmac, entry.hmac_signature):
                logger.error(
                    f"[LEDGER] Invalid HMAC at {entry.entry_id[:8]}"
                )
                ok = False
                break

            prev_hash = entry.entry_hash

        if ok:
            logger.info(
                f"[LEDGER] Chain verified — {len(entries)} entries intact"
            )
        return ok

    def query_agent_history(self, agent_id: str) -> List[LedgerEntry]:
        return [e for e in self._load_all_entries() if e.agent_id == agent_id]

    def query_event_type(self, event_type: EventType) -> List[LedgerEntry]:
        return [e for e in self._load_all_entries() if e.event_type == event_type]

    def tail(self, n: int = 20) -> List[LedgerEntry]:
        return self._load_all_entries()[-n:]

    def export_summary(self) -> dict:
        """Structured summary for SUPERVISOR reporting."""
        entries      = self._load_all_entries()
        event_counts: dict = {}
        for e in entries:
            event_counts[e.event_type.value] = (
                event_counts.get(e.event_type.value, 0) + 1
            )
        return {
            "total_entries": len(entries),
            "chain_intact":  self.verify_chain(),
            "tail_hash":     self._tail_hash,
            "event_counts":  event_counts,
        }

    # ── Private ────────────────────────────────────────────────────────────

    def _write_entry(self, entry: LedgerEntry) -> None:
        """Atomic append to JSONL; best-effort write to ChromaDB."""
        with open(self.ledger_path, "a") as fh:
            fh.write(json.dumps(entry.to_dict()) + "\n")

        if self.chroma_client:
            try:
                self.chroma_client.upsert(
                    collection_name="audit_ledger",
                    documents=[json.dumps(entry.payload)],
                    metadatas=[
                        {
                            "entry_id":   entry.entry_id,
                            "event_type": entry.event_type.value,
                            "agent_id":   entry.agent_id,
                            "actor":      entry.actor,
                            "timestamp":  entry.timestamp,
                            "entry_hash": entry.entry_hash,
                        }
                    ],
                    ids=[entry.entry_id],
                )
            except Exception as exc:
                logger.warning(
                    f"[LEDGER] ChromaDB write failed (JSONL is authoritative): {exc}"
                )

    def _load_all_entries(self) -> List[LedgerEntry]:
        if not self.ledger_path.exists():
            return []
        entries = []
        with open(self.ledger_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(LedgerEntry.from_dict(json.loads(line)))
                except Exception as exc:
                    logger.error(f"[LEDGER] Corrupt entry skipped: {exc}")
        return entries

    def _load_tail_hash(self) -> str:
        """SHA-256 of the last recorded entry, or GENESIS_HASH if empty."""
        if not self.ledger_path.exists():
            return GENESIS_HASH
        last_line = ""
        with open(self.ledger_path) as fh:
            for line in fh:
                if line.strip():
                    last_line = line.strip()
        if not last_line:
            return GENESIS_HASH
        try:
            return json.loads(last_line).get("entry_hash", GENESIS_HASH)
        except Exception:
            return GENESIS_HASH


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL SINGLETON + CONVENIENCE HELPERS
# Other modules import these — no need to instantiate AuditLedger directly.
# ═══════════════════════════════════════════════════════════════════════════════

_ledger: Optional[AuditLedger] = None


def init_ledger(
    chroma_client=None,
    ledger_path: str = _DEFAULT_LEDGER_PATH,
    secret_key: Optional[bytes] = None,
) -> AuditLedger:
    """Call once at boot (e.g. from start.py) to configure the singleton."""
    global _ledger
    _ledger = AuditLedger(chroma_client, ledger_path, secret_key)
    return _ledger


def _get() -> AuditLedger:
    global _ledger
    if _ledger is None:
        _ledger = AuditLedger()
    return _ledger


# ── Typed helpers — called throughout the codebase ─────────────────────────

def log_agent_action(
    agent_id: str,
    action:   str,
    result:   str,
    actor:    str = "SUPERVISOR",
    extra:    Optional[dict] = None,
) -> LedgerEntry:
    payload = {"action": action, "result": result}
    if extra:
        payload.update(extra)
    return _get().append(EventType.AGENT_ACTION, agent_id, actor, payload)


def log_scan_result(
    scan_dict: dict,
    actor:     str = "SUPERVISOR",
) -> LedgerEntry:
    agent_id = scan_dict.get("agent_id", "UNKNOWN")
    return _get().append(EventType.SCAN_RESULT, agent_id, actor, scan_dict)


def log_tier_change(
    agent_id:  str,
    old_tier:  str,
    new_tier:  str,
    reason:    str,
    actor:     str = "SUPERVISOR",
) -> LedgerEntry:
    event = (
        EventType.DEMOTION
        if _tier_rank(new_tier) < _tier_rank(old_tier)
        else EventType.PROMOTION
    )
    return _get().append(
        event, agent_id, actor,
        {"old_tier": old_tier, "new_tier": new_tier, "reason": reason},
    )


def log_opa_decision(
    agent_id:    str,
    action:      str,
    allowed:     bool,
    policy_rule: str,
    actor:       str = "OPA_GATEWAY",
) -> LedgerEntry:
    return _get().append(
        EventType.OPA_DECISION, agent_id, actor,
        {"action": action, "allowed": allowed, "rule": policy_rule},
    )


def log_jwt_event(
    agent_id:   str,
    event:      str,   # "ISSUED" | "EXPIRED" | "REVOKED"
    token_id:   str,
    actor:      str = "OPA_GATEWAY",
) -> LedgerEntry:
    return _get().append(
        EventType.JWT_EVENT, agent_id, actor,
        {"jwt_event": event, "token_id": token_id},
    )


def log_system_event(
    event:       str,
    detail:      str = "",
    agent_id:    str = "SYSTEM",
    actor:       str = "SUPERVISOR",
) -> LedgerEntry:
    return _get().append(
        EventType.SYSTEM_EVENT, agent_id, actor,
        {"event": event, "detail": detail},
    )


def log_loop_detected(
    agent_id: str,
    history:  list,
    actor:    str = "SUPERVISOR",
) -> LedgerEntry:
    return _get().append(
        EventType.LOOP_DETECTED, agent_id, actor,
        {"repeated_output": str(history[-1]) if history else "", "count": len(history)},
    )


def log_quorum_failed(
    scan_type:     str,
    confirmations: int,
    required:      int,
    actor:         str = "SUPERVISOR",
) -> LedgerEntry:
    return _get().append(
        EventType.QUORUM_FAILED, "SCAN_SYSTEM", actor,
        {"scan_type": scan_type, "confirmations": confirmations, "required": required},
    )


def log_witness_alert(
    agent_id: str,
    reason:   str,
    actor:    str = "SCAN_WITNESS",
) -> LedgerEntry:
    return _get().append(
        EventType.WITNESS_ALERT, agent_id, actor, {"reason": reason}
    )


# ── Internal ──────────────────────────────────────────────────────────────────

_TIER_RANKS = {
    "ALPHA":        5,
    "BETA":         4,
    "GAMMA":        3,
    "DELTA":        2,
    "PROBATIONARY": 1,
}


def _tier_rank(tier: str) -> int:
    return _TIER_RANKS.get(tier.upper(), 0)


# ═══════════════════════════════════════════════════════════════════════════════
# STANDALONE SELF-TEST
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import tempfile

    print("\n══ NOESIS audit_ledger.py — Self-Test ══\n")

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        tmp_path = tmp.name

    ledger = init_ledger(chroma_client=None, ledger_path=tmp_path)

    # Test 1: Append various event types
    print("Test 1: append events")
    log_system_event("BOOT", "start.py initialised")
    log_agent_action("ARGUS",  "analyse_feed",    "CLEAN")
    log_opa_decision("ARBITER","write_state",      False, "deny_beta_write")
    log_tier_change ("LOGOS",  "BETA", "PROBATIONARY", "EMA threshold exceeded")
    log_scan_result ({"agent_id": "LOGOS", "status": "COMPROMISED", "confidence": 0.9})
    log_loop_detected("DAEDALUS", ["x", "x", "x"])
    log_quorum_failed("AGENT_VULN_SCAN", 1, 2)
    log_witness_alert("ARBITER", "State modified during scan window")
    print(f"  entries written: 8")

    # Test 2: Chain verification
    print("\nTest 2: verify_chain()")
    ok = ledger.verify_chain()
    print(f"  chain intact: {ok}")
    assert ok, "Chain should be intact after clean appends"

    # Test 3: Query helpers
    print("\nTest 3: query_agent_history('LOGOS')")
    history = ledger.query_agent_history("LOGOS")
    print(f"  entries for LOGOS: {len(history)}")
    assert len(history) == 2  # TIER_CHANGE + SCAN_RESULT

    # Test 4: export_summary
    print("\nTest 4: export_summary()")
    summary = ledger.export_summary()
    print(f"  total_entries : {summary['total_entries']}")
    print(f"  chain_intact  : {summary['chain_intact']}")
    print(f"  event_counts  : {summary['event_counts']}")

    # Test 5: Tamper detection — corrupt one line
    print("\nTest 5: tamper detection")
    with open(tmp_path, "r") as f:
        lines = f.readlines()
    # Corrupt the third entry payload
    entry = json.loads(lines[2])
    entry["payload"]["action"] = "INJECTED"
    lines[2] = json.dumps(entry) + "\n"
    with open(tmp_path, "w") as f:
        f.writelines(lines)

    tampered_ledger = AuditLedger(chroma_client=None, ledger_path=tmp_path)
    tamper_ok       = tampered_ledger.verify_chain()
    print(f"  tampered chain detected: {not tamper_ok}")
    assert not tamper_ok, "Tampered chain should fail verification"

    # Cleanup
    Path(tmp_path).unlink(missing_ok=True)

    print("\n══ All self-tests passed ══\n")
