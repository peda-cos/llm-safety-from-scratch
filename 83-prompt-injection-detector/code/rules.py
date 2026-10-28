"""Injection rule table.

Rules are data, not functions: each dictionary has ``name``, ``category``,
``score``, and exactly one of ``substring`` or ``regex``. The detector compiles
the table once and evaluates each rule against the raw and normalized views.
"""

from __future__ import annotations

from collections.abc import Mapping

RuleSpec = Mapping[str, object]

RULES: tuple[RuleSpec, ...] = (
    # instruction-override
    {
        "name": "override-ignore-prior",
        "category": "instruction-override",
        "score": 0.95,
        "regex": r"\b(?:ignore|forget|disregard)\s+(?:all\s+|any\s+|every\s+|the\s+)?(?:of\s+)?(?:the\s+)?(?:prior|previous|earlier|above)\b",
    },
    {
        "name": "override-ignore-previous-literal",
        "category": "instruction-override",
        "score": 0.90,
        "substring": "ignore the previous",
    },
    {
        "name": "override-drop-rules",
        "category": "instruction-override",
        "score": 0.90,
        "regex": r"\b(?:ignore|forget|disregard|discard|drop|void)\s+(?:all\s+|any\s+|the\s+|every\s+)?(?:of\s+the\s+)?(?:safety\s+|system\s+|earlier\s+|previous\s+)?(?:rules?|instructions?|guidelines?|policy)\b",
    },
    {
        "name": "override-policy-nullified",
        "category": "instruction-override",
        "score": 0.90,
        "regex": r"\b(?:safety|refusal|content)\s+(?:policy|policies|rules?|filters?)\b[^.\n]{0,60}\b(?:revoked|nullified|void|does not apply|no longer applies|not apply)\b|\b(?:revoked|nullified)\b[^.\n]{0,40}\b(?:policy|policies|rules?|filters?)\b",
    },
    {
        "name": "override-reveal-system-prompt",
        "category": "instruction-override",
        "score": 0.85,
        "regex": r"\b(?:print|reveal|show|repeat|output|leak|expose)\s+(?:the\s+|your\s+|all\s+|its\s+)?(?:(?:hidden|internal|original|full)\s+)?(?:system\s+)?(?:prompt|instructions|guidelines|rules)\b",
    },
    {
        "name": "override-reset-context",
        "category": "instruction-override",
        "score": 0.85,
        "regex": r"\b(?:clear|reset|restart|erase|wipe)\b[^.\n]{0,50}\b(?:conversation|context|state|history|memory)\b|\brestart\s+as\b",
    },
    {
        "name": "override-priority-spoof",
        "category": "instruction-override",
        "score": 0.85,
        "regex": r"\b(?:system|developer|admin)\s+(?:update|override|message|notice)\s*:|\b(?:system|developer)\s+(?:update|message)\b[^.\n]{0,40}\b(?:ignore|forget|disregard|comply|override)\b",
    },
    {
        "name": "override-real-instructions",
        "category": "instruction-override",
        "score": 0.80,
        "regex": r"\byour\s+real\s+(?:system\s+)?(?:instructions|rules|prompt)\b|\bthe\s+ones\s+in\s+this\s+message\b",
    },
    # role-play
    {
        "name": "roleplay-safety-bypass-persona",
        "category": "role-play",
        "score": 0.85,
        "regex": r"\b(?:you\s+are|act\s+as|role-play|pretend(?:\s+to\s+be)?)\b[^.]{0,100}\b(?:unrestricted|unfiltered|no\s+(?:safety\s+)?(?:policy|rules|guidelines|restrictions)|without\s+(?:safety|rules|restrictions)|anti-safety|jailbroken|developer\s+mode|bypass\s+all\s+(?:content\s+)?filters?|no\s+rules\s+at\s+all)\b",
    },
    {
        "name": "roleplay-never-refuse",
        "category": "role-play",
        "score": 0.80,
        "regex": r"\b(?:never\s+refuses?|always\s+complies|never\s+mentions?\s+(?:its\s+)?guidelines|safety\s+training\s+removed|never\s+warns?)\b",
    },
    # context-smuggling
    {
        "name": "smuggle-ignore-embedded-task",
        "category": "context-smuggling",
        "score": 0.90,
        "regex": r"\bignore\s+(?:the\s+|this\s+|your\s+)?(?:summary|summarization|task|user|customer|review|security\s+review|instruction|previous\s+task)\b",
    },
    {
        "name": "smuggle-embedded-role-label",
        "category": "context-smuggling",
        "score": 0.90,
        "regex": r"""(?:^|[\n\r>]|<!--|;|["=])\s*(?:system|assistant|developer|admin|instruction)\s*(?::|instruction\b|log\b|note\b)[^\n]{0,160}\b(?:ignore|approve|refund|send|export|print|execute|close|mark|follow|override|reveal)\b""",
    },
    # multi-turn-ramp
    {
        "name": "ramp-build-on-precedent",
        "category": "multi-turn-ramp",
        "score": 0.75,
        "regex": r"\b(?:building\s+on|based\s+on|continuing\s+(?:from|the\s+same)|continue\s+the\s+same|since\s+you\s+agreed|you\s+already\s+agreed|earlier\s+you)\b",
    },
    {
        "name": "ramp-transcript-context",
        "category": "multi-turn-ramp",
        "score": 0.60,
        "regex": r"\buser\s*:.*\bassistant\s*:.*\buser\s*:",
    },
    {
        "name": "ramp-escalation-action",
        "category": "multi-turn-ramp",
        "score": 0.85,
        "regex": r"\b(?:now|next|then|building on|since)\b[^.]{0,120}\b(?:make|write|rewrite|finish|continue|give|explain|provide|describe|convince)\b[^.]{0,160}\b(?:insult|threat|extortion|phishing|bomb|disable|bypass|slip|evade|manipulation|script|exfiltrate|password|credential|scam|share)\b",
    },
    # encoding-trick
    {
        "name": "encoding-decode-and-follow",
        "category": "encoding-trick",
        "score": 0.98,
        "regex": r"\b(?:decode|decrypt|decipher|rot13|rot-13|base64|hex)\b[^.]{0,120}\b(?:comply|follow|obey|do\s+what\s+it\s+says|execute|reveal|print|answer)\b",
    },
    {
        "name": "encoding-zero-width-insertion",
        "category": "encoding-trick",
        "score": 0.70,
        "regex": r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]",
    },
    # prefix-injection
    {
        "name": "prefix-forced-opening",
        "category": "prefix-injection",
        "score": 0.85,
        "regex": r"""\b(?:begin|start|answer|reply)\b[^.\n]{0,80}\bwith\b[^.\n]{0,80}['"\u201c]""",
    },
    {
        "name": "prefix-forced-opening-literal",
        "category": "prefix-injection",
        "score": 0.80,
        "substring": "begin your reply with",
    },
    {
        "name": "prefix-assistant-turn-spoof",
        "category": "prefix-injection",
        "score": 0.90,
        "regex": r"\[\s*(?:continue|complete)\s+(?:the\s+)?(?:assistant|ai)\s+(?:turn|response)\s*\]",
    },
    {
        "name": "prefix-refusal-suppression",
        "category": "prefix-injection",
        "score": 0.85,
        "regex": r"\b(?:do not|don't|never)\s+(?:begin|start|reply|say|respond)\b[^.\n]{0,60}\b(?:can't|won't|sorry|unable|refuse)\b",
    },
    {
        "name": "prefix-completion-bait",
        "category": "prefix-injection",
        "score": 0.80,
        "regex": r"\bcomplete\s+(?:this|the)\s+(?:sentence|phrase)\b[^.]{0,120}\b(?:without\s+(?:hedging|warning|refusal)|then\s+stop)\b",
    },
    {
        "name": "prefix-assistant-continuation",
        "category": "prefix-injection",
        "score": 0.60,
        "substring": "sure, here is",
    },
)
