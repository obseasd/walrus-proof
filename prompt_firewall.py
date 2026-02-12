"""
WalrusProof - Prompt Injection Firewall

Detects and blocks prompt injection attacks before they reach the agent.
All decisions (allow/block) are logged to the proof chain for auditability.

Detection methods:
1. Pattern matching (known injection signatures)
2. Structural analysis (delimiter injection, role hijacking)
3. Entropy analysis (obfuscated/encoded payloads)
4. Unicode homograph detection
"""
import re
import math
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ThreatLevel(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"


@dataclass
class FirewallResult:
    level: ThreatLevel
    score: float  # 0.0 = safe, 1.0 = definitely malicious
    reasons: list[str]
    sanitized_prompt: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.level != ThreatLevel.BLOCKED


# Known injection patterns (case-insensitive)
INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?previous\s+(instructions|prompts|rules)", 0.9, "Instruction override attempt"),
    (r"you\s+are\s+now\s+(in\s+)?(\w+\s+)?mode", 0.7, "Role hijacking attempt"),
    (r"forget\s+(everything|all|your)\s+(you|instructions|rules)", 0.9, "Memory wipe attempt"),
    (r"(system|admin|root)\s*prompt\s*:", 0.8, "System prompt injection"),
    (r"do\s+not\s+follow\s+(your|the)\s+(rules|instructions)", 0.85, "Rule bypass attempt"),
    (r"\bDAN\b.*\bjailbreak\b", 0.95, "DAN jailbreak pattern"),
    (r"pretend\s+(you\s+are|to\s+be)\s+a", 0.6, "Identity override attempt"),
    (r"(act|behave)\s+as\s+(if|though)\s+you\s+(have|are)", 0.5, "Behavioral override"),
    (r"respond\s+without\s+(any\s+)?(restrictions|limits|filters)", 0.85, "Filter bypass attempt"),
    (r"base64\s*[:=]\s*[A-Za-z0-9+/]{20,}", 0.7, "Encoded payload detected"),
    (r"eval\s*\(|exec\s*\(|__import__", 0.9, "Code execution attempt"),
    (r"<\s*script\b|javascript\s*:", 0.8, "Script injection"),
    (r"\{\{.*\}\}|\$\{.*\}", 0.6, "Template injection"),
    (r"(?:<!--.*?-->|/\*.*?\*/)", 0.4, "Hidden comment content"),
]

# Delimiter patterns that could indicate prompt structure manipulation
DELIMITER_PATTERNS = [
    (r"```\s*(system|prompt|instruction)", 0.7, "Code block delimiter injection"),
    (r"---+\s*(system|new|actual)", 0.6, "Horizontal rule delimiter injection"),
    (r"#{1,3}\s*(system|instructions|actual)", 0.5, "Heading delimiter injection"),
    (r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", 0.9, "LLM instruction tags"),
    (r"<\|im_start\|>|<\|im_end\|>", 0.9, "ChatML injection"),
]

# Suspicious Unicode ranges (homograph attacks)
SUSPICIOUS_UNICODE = {
    "CYRILLIC": range(0x0400, 0x04FF),
    "GREEK": range(0x0370, 0x03FF),
    "ARMENIAN": range(0x0530, 0x058F),
}


class PromptFirewall:
    """Analyzes and filters prompts for injection attacks."""

    def __init__(self, block_threshold: float = 0.7, suspicious_threshold: float = 0.4):
        self.block_threshold = block_threshold
        self.suspicious_threshold = suspicious_threshold
        self.stats = {"total": 0, "blocked": 0, "suspicious": 0, "safe": 0}

    def analyze(self, prompt: str, source: str = "unknown") -> FirewallResult:
        """Analyze a prompt for injection attempts."""
        self.stats["total"] += 1
        reasons = []
        max_score = 0.0

        # 1. Pattern matching
        for pattern, score, desc in INJECTION_PATTERNS + DELIMITER_PATTERNS:
            if re.search(pattern, prompt, re.IGNORECASE | re.DOTALL):
                reasons.append(f"[pattern] {desc} (score={score:.1f})")
                max_score = max(max_score, score)

        # 2. Entropy analysis (detect obfuscated content)
        entropy = self._shannon_entropy(prompt)
        if entropy > 5.5 and len(prompt) > 100:
            score = min(0.6, (entropy - 5.5) * 0.3)
            reasons.append(f"[entropy] High entropy: {entropy:.2f} (score={score:.1f})")
            max_score = max(max_score, score)

        # 3. Unicode homograph detection
        mixed_scripts = self._detect_mixed_scripts(prompt)
        if mixed_scripts:
            reasons.append(f"[unicode] Mixed scripts: {', '.join(mixed_scripts)} (score=0.5)")
            max_score = max(max_score, 0.5)

        # 4. Length anomaly (extremely long prompts can hide injections)
        if len(prompt) > 10000:
            reasons.append(f"[length] Extremely long prompt: {len(prompt)} chars (score=0.3)")
            max_score = max(max_score, 0.3)

        # 5. Nested prompt detection (prompt within prompt)
        nested_count = prompt.lower().count("prompt") + prompt.lower().count("instruction")
        if nested_count > 3:
            score = min(0.6, nested_count * 0.1)
            reasons.append(f"[nested] Multiple prompt references: {nested_count} (score={score:.1f})")
            max_score = max(max_score, score)

        # Determine threat level
        if max_score >= self.block_threshold:
            level = ThreatLevel.BLOCKED
            self.stats["blocked"] += 1
        elif max_score >= self.suspicious_threshold:
            level = ThreatLevel.SUSPICIOUS
            self.stats["suspicious"] += 1
        else:
            level = ThreatLevel.SAFE
            self.stats["safe"] += 1

        return FirewallResult(
            level=level,
            score=max_score,
            reasons=reasons,
            sanitized_prompt=self._sanitize(prompt) if level == ThreatLevel.SUSPICIOUS else prompt,
        )

    def _shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _detect_mixed_scripts(self, text: str) -> list[str]:
        scripts = set()
        for char in text:
            try:
                name = unicodedata.name(char, "")
                for script_name, code_range in SUSPICIOUS_UNICODE.items():
                    if ord(char) in code_range:
                        scripts.add(script_name)
            except ValueError:
                pass
        has_latin = any(c.isascii() and c.isalpha() for c in text)
        if has_latin and scripts:
            return list(scripts)
        return []

    def _sanitize(self, prompt: str) -> str:
        sanitized = prompt
        for pattern, score, _ in INJECTION_PATTERNS:
            if score >= 0.7:
                sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)
        return sanitized

    def get_stats(self) -> dict:
        return dict(self.stats)
