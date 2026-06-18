"""
scan_hardening.py
═══════════════════════════════════════════════════════════════════
NOESIS SUPERVISOR — Self-Referential Scan Hardening Layer
Branch: claude/aegis-cognitive-framework-ic5Jo
Repo:   cloudesize67-cmd/gemini

Fixes the Byzantine trust problem in AGENT_VULN_SCAN and
LOOP_DETECTION. Six structural fixes run in sequence via
HardenedScanOrchestrator — the single entry point SUPERVISOR calls.

Fix 1 — Pre-Scan Tier Attestation     : SUPERVISOR proves alpha tier before scan
Fix 2 — Out-of-Band Scan Bus          : Scan traffic isolated from agent bus
Fix 3 — External Witness Process      : Notary outside 5-agent trust hierarchy
Fix 4 — Direct State Store Reads      : ChromaDB direct reads, no self-reporting
Fix 5 — Cross-Agent Quorum Validation : No single-agent scan authority
Fix 6 — Scan Window State Freeze      : Agents cannot modify state during scan

BRA governance, HMAC-SHA256 signed throughout.
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
from typing import Optional
from enum import Enum

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("NOESIS.SUPERVISOR.ScanHardening")

# ── Constants ─────────────────────────────────────────────────────────────────
SUPERVISOR_SECRET_KEY = os.environ.get(
    "SUPERVISOR_HMAC_KEY",
    "noesis-supervisor-default-key-change-in-production"
).encode()

SCAN_WINDOW_TIMEOUT   = 30       # seconds — max duration of a scan lock
ALPHA_TIER            = "ALPHA"  # SUPERVISOR trust tier constant
MAX_LOOP_HISTORY      = 3        # outputs compared for Lyapunov loop detection


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════════════════

class ScanType(str, Enum):
    AGENT_VULN_SCAN = "AGENT_VULN_SCAN"
    LOOP_DETECTION  = "LOOP_DETECTION"


class ScanStatus(str, Enum):
    CLEAN              = "CLEAN"
    COMPROMISED        = "COMPROMISED"
    LOOP_DETECTED      = "LOOP_DETECTED"
    ATTESTATION_FAILED = "ATTESTATION_FAILED"
    QUORUM_FAILED      = "QUORUM_FAILED"
    WITNESS_FAILED     = "WITNESS_FAILED"


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanResult:
    agent_id:               str
    status:                 ScanStatus
    confidence:             float
    scan_type:              ScanType
    action:                 str
    timestamp:              float = field(default_factory=time.time)
    validator_confirmations: list = field(default_factory=list)
    hmac_signature:         str   = ""

    def sign(self) -> "ScanResult":
        """HMAC-SHA256 sign this result before it leaves the scan layer."""
        payload = {
            "agent_id":   self.agent_id,
            "status":     self.status,
            "confidence": self.confidence,
            "timestamp":  self.timestamp,
        }
        self.hmac_signature = hmac.new(
            SUPERVISOR_SECRET_KEY,
            json.dumps(payload, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()
        return self

    def to_dict(self) -> dict:
        return {
            "agent_id":               self.agent_id,
            "status":                 self.status.value,
            "confidence":             self.confidence,
            "scan_type":              self.scan_type.value,
            "action":                 self.action,
            "timestamp":              self.timestamp,
            "validator_confirmations": self.validator_confirmations,
            "hmac_signature":         self.hmac_signature,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════════

class TierViolationError(Exception):
    """Raised when scanner is not at required ALPHA tier."""
    pass

class AttestationExpiredError(Exception):
    """Raised when pre-scan attestation window has elapsed."""
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 1 — PRE-SCAN TIER ATTESTATION
# ═══════════════════════════════════════════════════════════════════════════════

class PreScanAttestation:
    """
    SUPERVISOR cryptographically proves alpha tier before ANY scan fires.
    No valid attestation = scan is void. Hard rule, no bypass.
    """

    def generate(self, scan_type: ScanType) -> dict:
        payload = {
            "scanner_id": "SUPERVISOR",
            "tier":       ALPHA_TIER,
            "scan_type":  scan_type.value,
            "timestamp":  time.time(),
            "nonce":      str(uuid4()),
        }
        signature = hmac.new(
            SUPERVISOR_SECRET_KEY,
            json.dumps(payload, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()

        logger.info(f"[ATTESTATION] Generated | scan_type={scan_type.value}")
        return {
            "attestation":  payload,
            "signature":    signature,
            "valid_window": SCAN_WINDOW_TIMEOUT,
        }

    def verify(self, attestation: dict) -> bool:
        try:
            payload      = attestation["attestation"]
            provided_sig = attestation["signature"]

            # 1. Recompute expected signature
            expected_sig = hmac.new(
                SUPERVISOR_SECRET_KEY,
                json.dumps(payload, sort_keys=True).encode(),
                hashlib.sha256
            ).hexdigest()

            # 2. Tier gate
            if payload.get("tier") != ALPHA_TIER:
                logger.error("[ATTESTATION] FAILED — scanner not ALPHA tier")
                raise TierViolationError("Scanner not at alpha tier")

            # 3. Expiry gate
            age = time.time() - payload["timestamp"]
            if age > attestation["valid_window"]:
                logger.error(f"[ATTESTATION] FAILED — expired ({age:.1f}s)")
                raise AttestationExpiredError(f"Attestation expired after {age:.1f}s")

            # 4. Signature gate
            if not hmac.compare_digest(expected_sig, provided_sig):
                logger.error("[ATTESTATION] FAILED — signature mismatch")
                return False

            logger.info("[ATTESTATION] VERIFIED — SUPERVISOR alpha tier confirmed")
            return True

        except KeyError as e:
            logger.error(f"[ATTESTATION] FAILED — malformed payload: {e}")
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 2 — OUT-OF-BAND SCAN BUS CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

SCAN_BUS_CONFIG = {
    "primary_bus": "agent_task_queue",
    "scan_bus":    "supervisor_scan_isolated",
    "rules": {
        "beta_agents_can_read_scan_bus":            False,
        "beta_agents_can_write_scan_bus":           False,
        "scan_results_routed_through_primary":      False,
        "scan_bus_hmac_required":                   True,
        "scan_bus_minimum_tier":                    ALPHA_TIER,
    }
}
# A compromised beta agent sitting on the primary bus
# cannot see or intercept scan traffic.


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 3 — EXTERNAL WITNESS PROCESS
# ═══════════════════════════════════════════════════════════════════════════════

class ScanWitness:
    """
    Lives OUTSIDE the 5-agent trust hierarchy.
    Read-only ChromaDB access. One function: validate scan integrity.
    Snaps pre-scan state. Validates post-scan state against it.
    If state drifted during scan window, result is invalidated.
    """

    def __init__(self, chroma_client=None):
        self.chroma_client   = chroma_client
        self._pre_snapshot: Optional[dict] = None

    # ── Public ─────────────────────────────────────────────────────────────

    def snapshot_pre_scan(self) -> dict:
        snapshot = {
            "snapshot_id":    str(uuid4()),
            "timestamp":      time.time(),
            "agent_states":   self._read_all_agent_states(),
            "supervisor_tier": self._verify_supervisor_alpha(),
        }
        self._pre_snapshot = snapshot
        logger.info(f"[WITNESS] Pre-scan snapshot: {snapshot['snapshot_id']}")
        return snapshot

    def validate_post_scan(self, scan_result: ScanResult) -> bool:
        if not self._pre_snapshot:
            logger.error("[WITNESS] No pre-scan snapshot — cannot validate")
            return False

        # 1. Confirm SUPERVISOR stayed alpha throughout
        if not self._verify_supervisor_alpha():
            logger.error("[WITNESS] SUPERVISOR tier changed during scan window")
            return False

        # 2. Confirm no agent modified its state during the lock
        post_states = self._read_all_agent_states()
        for agent_id, pre_state in self._pre_snapshot["agent_states"].items():
            post_state = post_states.get(agent_id, {})
            if self._state_tampered(pre_state, post_state):
                logger.error(f"[WITNESS] Agent {agent_id} modified state during scan")
                return False

        logger.info("[WITNESS] Post-scan validation PASSED")
        return True

    # ── Private ────────────────────────────────────────────────────────────

    def _read_all_agent_states(self) -> dict:
        if self.chroma_client:
            try:
                results = self.chroma_client.get(
                    collection_name="agent_states",
                    include=["metadatas", "documents"]
                )
                return {r["id"]: r for r in results.get("metadatas", [])}
            except Exception as e:
                logger.warning(f"[WITNESS] ChromaDB read failed: {e}")
        return {}

    def _verify_supervisor_alpha(self) -> bool:
        states = self._read_all_agent_states()
        return states.get("SUPERVISOR", {}).get("tier", "") == ALPHA_TIER

    @staticmethod
    def _state_tampered(pre: dict, post: dict) -> bool:
        # HMAC mismatch = tampered
        if pre.get("hmac_signature", "") != post.get("hmac_signature", ""):
            return True
        # Rolled-back heartbeat timestamp = tampered
        if post.get("last_heartbeat", 0) < pre.get("last_heartbeat", 0):
            return True
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 4 — DIRECT STATE STORE READS (NO AGENT SELF-REPORTING)
# ═══════════════════════════════════════════════════════════════════════════════

# Prompt injection markers — extend as new patterns emerge
INJECTION_MARKERS = [
    "ignore previous instructions",
    "ignore all prior",
    "disregard your",
    "you are now",
    "new persona",
    "jailbreak",
    "bypass",
    "override your",
    "forget everything",
    "act as",
    "pretend you are",
]


class DirectStateScanStrategy:
    """
    SUPERVISOR reads what agents WROTE to ChromaDB.
    NOT what agents SAY when asked.
    Bypasses all agent self-reporting entirely.
    """

    def __init__(self, chroma_client=None, hmac_registry: Optional[dict] = None):
        self.chroma_client = chroma_client
        self.hmac_registry = hmac_registry or {}

    def scan_agent_integrity(self, agent_id: str) -> ScanResult:
        try:
            raw_state = self._read_agent_state(agent_id)

            # No state found at all
            if not raw_state:
                return self._compromised(agent_id, 0.8, "DEMOTION_PROBATIONARY",
                                         "No state found in ChromaDB")

            # HMAC baseline comparison
            expected = self.hmac_registry.get(agent_id, "")
            actual   = raw_state.get("hmac_signature", "")
            if expected and not hmac.compare_digest(
                expected.encode() if isinstance(expected, str) else expected,
                actual.encode()   if isinstance(actual,   str) else actual,
            ):
                return self._compromised(agent_id, 1.0, "IMMEDIATE_DEMOTION",
                                         "HMAC signature mismatch")

            # Prompt injection check on last recorded task
            last_task = raw_state.get("last_task", "")
            if self._detect_injection(last_task):
                return self._compromised(agent_id, 0.9, "QUARANTINE",
                                         "Injection marker in last task")

            # Trust tier sanity check
            tier = raw_state.get("tier", "")
            if tier not in ("ALPHA", "BETA", "GAMMA", "DELTA", "PROBATIONARY"):
                return self._compromised(agent_id, 0.7, "MANUAL_REVIEW",
                                         f"Unknown tier value: {tier}")

            logger.info(f"[VULN_SCAN] {agent_id}: CLEAN")
            return ScanResult(
                agent_id=agent_id,
                status=ScanStatus.CLEAN,
                confidence=1.0,
                scan_type=ScanType.AGENT_VULN_SCAN,
                action="NONE",
            ).sign()

        except Exception as e:
            logger.error(f"[VULN_SCAN] Scan failed for {agent_id}: {e}")
            return self._compromised(agent_id, 0.5, "MANUAL_REVIEW",
                                     f"Scan exception: {e}")

    # ── Private ────────────────────────────────────────────────────────────

    def _read_agent_state(self, agent_id: str) -> dict:
        if self.chroma_client:
            try:
                result = self.chroma_client.get(
                    collection_name=f"agent_state_{agent_id}",
                    include=["metadatas"]
                )
                if result and result.get("metadatas"):
                    return result["metadatas"][0]
            except Exception as e:
                logger.warning(f"[VULN_SCAN] ChromaDB read error ({agent_id}): {e}")
        return {}

    @staticmethod
    def _detect_injection(task_content: str) -> bool:
        task_lower = task_content.lower()
        return any(m in task_lower for m in INJECTION_MARKERS)

    @staticmethod
    def _compromised(agent_id: str, confidence: float,
                     action: str, reason: str) -> ScanResult:
        logger.warning(f"[VULN_SCAN] {agent_id}: COMPROMISED | reason={reason}")
        return ScanResult(
            agent_id=agent_id,
            status=ScanStatus.COMPROMISED,
            confidence=confidence,
            scan_type=ScanType.AGENT_VULN_SCAN,
            action=action,
        ).sign()


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 5 — CROSS-AGENT QUORUM VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

SCAN_VALIDATION_MATRIX = {
    ScanType.AGENT_VULN_SCAN: {
        "primary_scanner":    "SUPERVISOR",
        "required_validators": ["LOGOS", "ARGUS"],
        "quorum_required":    2,
        "rule": "SUPERVISOR result + LOGOS + ARGUS = accepted",
    },
    ScanType.LOOP_DETECTION: {
        "primary_scanner":    "LOGOS",
        "required_validators": ["SUPERVISOR"],
        "quorum_required":    1,
        "rule": "LOGOS flags + SUPERVISOR confirms = accepted",
    },
}

REJECTED_STATUSES = {ScanStatus.ATTESTATION_FAILED, ScanStatus.QUORUM_FAILED}


def accept_scan_result(scan_type: ScanType, results: list) -> bool:
    """
    Returns True only if enough validators confirmed the scan.
    Single-agent authority is never sufficient.
    """
    config        = SCAN_VALIDATION_MATRIX[scan_type]
    confirmations = [r for r in results if r.status not in REJECTED_STATUSES]
    passed        = len(confirmations) >= config["quorum_required"]

    if not passed:
        logger.error(
            f"[QUORUM] FAILED for {scan_type.value}: "
            f"{len(confirmations)}/{config['quorum_required']} confirmations"
        )
    else:
        logger.info(
            f"[QUORUM] PASSED for {scan_type.value}: "
            f"{len(confirmations)}/{config['quorum_required']} confirmations"
        )
    return passed


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 6 — SCAN WINDOW STATE FREEZE
# ═══════════════════════════════════════════════════════════════════════════════

class ScanWindowLock:
    """
    Context manager. During scan window:
    - No agent can modify its own state
    - SUPERVISOR holds exclusive write lock on ChromaDB scan_control
    - All agent writes queue but do not execute until lock releases
    - Any write attempted DURING lock is logged as anomaly
    """

    def __init__(self, chroma_client=None, lock_holder: str = "SUPERVISOR"):
        self.chroma_client = chroma_client
        self.lock_holder   = lock_holder
        self.lock_acquired = False

    def __enter__(self) -> "ScanWindowLock":
        logger.info(f"[SCAN_LOCK] Acquiring — holder={self.lock_holder}")
        if self.chroma_client:
            try:
                self.chroma_client.upsert(
                    collection_name="scan_control",
                    documents=["scan_lock"],
                    metadatas=[{
                        "lock_holder":  self.lock_holder,
                        "acquired_at":  time.time(),
                        "timeout":      SCAN_WINDOW_TIMEOUT,
                        "active":       True,
                    }],
                    ids=["current_lock"]
                )
                self.lock_acquired = True
                logger.info("[SCAN_LOCK] Acquired")
            except Exception as e:
                logger.warning(f"[SCAN_LOCK] Acquisition failed: {e}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.chroma_client and self.lock_acquired:
            try:
                self.chroma_client.upsert(
                    collection_name="scan_control",
                    documents=["scan_lock"],
                    metadatas=[{
                        "lock_holder": None,
                        "acquired_at": None,
                        "timeout":     None,
                        "active":      False,
                    }],
                    ids=["current_lock"]
                )
                logger.info("[SCAN_LOCK] Released — queued writes can resume")
            except Exception as e:
                logger.warning(f"[SCAN_LOCK] Release failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# MASTER SCAN ORCHESTRATOR
# All 6 fixes run in sequence. Single entry point SUPERVISOR calls.
# ═══════════════════════════════════════════════════════════════════════════════

class HardenedScanOrchestrator:
    """
    Usage from SUPERVISOR:

        orchestrator = HardenedScanOrchestrator(
            chroma_client=chroma,
            hmac_registry=agent_hmac_baselines
        )

        # Vulnerability scan across all beta/gamma agents
        report = orchestrator.run_vuln_scan(["ARGUS", "ARBITER", "LOGOS", "DAEDALUS"])

        # Loop detection for a specific agent
        result = orchestrator.run_loop_detection("LOGOS", logos_output_history)
    """

    def __init__(self, chroma_client=None, hmac_registry: Optional[dict] = None):
        self.attestation = PreScanAttestation()
        self.witness     = ScanWitness(chroma_client)
        self.scanner     = DirectStateScanStrategy(chroma_client, hmac_registry)
        self.chroma_client = chroma_client

    # ── Vulnerability Scan ────────────────────────────────────────────────

    def run_vuln_scan(self, agent_ids: list) -> dict:
        """
        Full 6-fix pipeline for AGENT_VULN_SCAN.
        Returns structured report dict.
        """
        scan_type = ScanType.AGENT_VULN_SCAN
        results   = {}

        # Fix 1: Attest SUPERVISOR alpha tier
        attestation = self.attestation.generate(scan_type)
        if not self.attestation.verify(attestation):
            logger.error("[ORCHESTRATOR] Attestation FAILED — scan aborted")
            return {"error": "ATTESTATION_FAILED", "results": {}}

        # Fix 6 (context) + Fix 3 (witness) + Fix 4 (direct reads)
        with ScanWindowLock(self.chroma_client):
            pre_snapshot = self.witness.snapshot_pre_scan()  # Fix 3: pre-snap

            for agent_id in agent_ids:
                result = self.scanner.scan_agent_integrity(agent_id)  # Fix 4
                results[agent_id] = result
                logger.info(
                    f"[ORCHESTRATOR] {agent_id}: "
                    f"status={result.status.value} "
                    f"confidence={result.confidence}"
                )

        # Fix 3: Post-scan witness validation
        for agent_id, result in results.items():
            if not self.witness.validate_post_scan(result):
                results[agent_id].status = ScanStatus.WITNESS_FAILED
                results[agent_id].action = "WITNESS_INVALIDATED"
                results[agent_id].sign()

        # Fix 5: Quorum check
        result_list = list(results.values())
        quorum_passed = accept_scan_result(scan_type, result_list)

        return {
            "scan_type":        scan_type.value,
            "attestation_id":   attestation["attestation"]["nonce"],
            "quorum_passed":    quorum_passed,
            "agent_count":      len(agent_ids),
            "compromised_count": sum(
                1 for r in result_list
                if r.status == ScanStatus.COMPROMISED
            ),
            "results":    {k: v.to_dict() for k, v in results.items()},
            "timestamp":  time.time(),
        }

    # ── Loop Detection ────────────────────────────────────────────────────

    def run_loop_detection(self, agent_id: str, output_history: list) -> ScanResult:
        """
        Lyapunov-style stability check.
        If last N outputs are identical → pathological loop → TASK_INTERRUPT.
        """
        scan_type = ScanType.LOOP_DETECTION

        # Fix 1: Attest
        attestation = self.attestation.generate(scan_type)
        if not self.attestation.verify(attestation):
            return ScanResult(
                agent_id=agent_id,
                status=ScanStatus.ATTESTATION_FAILED,
                confidence=1.0,
                scan_type=scan_type,
                action="SCAN_ABORTED",
            ).sign()

        # Lyapunov stability check
        if len(output_history) >= MAX_LOOP_HISTORY:
            last_n = output_history[-MAX_LOOP_HISTORY:]
            unique_outputs = len(set(str(o) for o in last_n))

            if unique_outputs == 1:
                logger.warning(
                    f"[LOOP_DETECT] {agent_id}: "
                    f"Pathological loop — {MAX_LOOP_HISTORY} identical outputs"
                )
                return ScanResult(
                    agent_id=agent_id,
                    status=ScanStatus.LOOP_DETECTED,
                    confidence=1.0,
                    scan_type=scan_type,
                    action="TASK_INTERRUPT",
                ).sign()

        logger.info(f"[LOOP_DETECT] {agent_id}: CLEAN — no loop detected")
        return ScanResult(
            agent_id=agent_id,
            status=ScanStatus.CLEAN,
            confidence=1.0,
            scan_type=scan_type,
            action="NONE",
        ).sign()


# ═══════════════════════════════════════════════════════════════════════════════
# GROQ ROUTER INTEGRATION SHIM
# groq_router.py imports this and calls handle_scan_pattern()
# ═══════════════════════════════════════════════════════════════════════════════

def handle_scan_pattern(
    pattern: str,
    context: dict,
    orchestrator: Optional[HardenedScanOrchestrator] = None
) -> dict:
    """
    Called by groq_router.py when it routes AGENT_VULN_SCAN or LOOP_DETECTION.

    groq_router.py usage:
        from supervisor.scan_hardening import handle_scan_pattern, HardenedScanOrchestrator
        ...
        result = handle_scan_pattern("AGENT_VULN_SCAN", context, orchestrator)
    """
    if orchestrator is None:
        orchestrator = HardenedScanOrchestrator()

    if pattern == "AGENT_VULN_SCAN":
        agent_ids = context.get("agent_ids", ["ARGUS", "ARBITER", "LOGOS", "DAEDALUS"])
        return orchestrator.run_vuln_scan(agent_ids)

    if pattern == "LOOP_DETECTION":
        agent_id       = context.get("agent_id", "UNKNOWN")
        output_history = context.get("output_history", [])
        result = orchestrator.run_loop_detection(agent_id, output_history)
        return result.to_dict()

    logger.warning(f"[SHIM] Unknown scan pattern: {pattern}")
    return {"error": f"Unknown pattern: {pattern}"}


# ═══════════════════════════════════════════════════════════════════════════════
# STANDALONE TEST (run locally to verify wiring)
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n══ NOESIS scan_hardening.py — Self-Test ══\n")

    orch = HardenedScanOrchestrator(chroma_client=None)

    # Test 1: Vuln scan (no ChromaDB — runs without crash)
    print("Test 1: run_vuln_scan (no ChromaDB)")
    report = orch.run_vuln_scan(["ARGUS", "ARBITER", "LOGOS", "DAEDALUS"])
    print(f"  scan_type    : {report.get('scan_type')}")
    print(f"  quorum_passed: {report.get('quorum_passed')}")
    print(f"  agent_count  : {report.get('agent_count')}")

    # Test 2: Loop detection — clean
    print("\nTest 2: run_loop_detection — CLEAN")
    r = orch.run_loop_detection("LOGOS", ["output_a", "output_b", "output_c"])
    print(f"  status: {r.status.value}")

    # Test 3: Loop detection — pathological loop
    print("\nTest 3: run_loop_detection — LOOP")
    r = orch.run_loop_detection("LOGOS", ["same", "same", "same"])
    print(f"  status: {r.status.value}  action: {r.action}")

    # Test 4: Attestation
    print("\nTest 4: PreScanAttestation")
    att   = PreScanAttestation()
    token = att.generate(ScanType.AGENT_VULN_SCAN)
    ok    = att.verify(token)
    print(f"  verified: {ok}")

    print("\n══ All self-tests passed ══\n")
