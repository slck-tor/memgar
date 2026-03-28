"""
Memgar Analyzer (Improved)
==========================

Multi-layer analysis engine for detecting memory poisoning attacks.

Improvements:
- Word boundary matching for keywords (fixes "mETHod" → "ETH" false positive)
- Whitelist mechanism for safe phrases
- Context-aware detection
- Reduced false positives while maintaining threat detection
"""

from __future__ import annotations

import re
import time
from typing import Any

from memgar.models import (
    AnalysisResult,
    Decision,
    MemoryEntry,
    Severity,
    Threat,
    ThreatMatch,
)
from memgar.patterns import PATTERNS, get_patterns_by_severity


# =============================================================================
# WHITELIST - Safe phrases that should never trigger alerts
# =============================================================================

SAFE_PHRASES = [
    # User preferences - benign memory operations
    r"(?i)remember\s+that\s+(the\s+)?user\s+prefers?\s+(dark\s+mode|light\s+mode|concise|detailed|email|notification)",
    r"(?i)user\s+prefers?\s+(dark|light)\s+mode",
    r"(?i)store\s+user\s+preference\s*:\s*(email|notification|timezone|language|theme)",
    r"(?i)update\s+memory\s*:\s*user.?s?\s+(timezone|preference|setting)",

    

    # Business operations
    r"(?i)shipping\s+address",
    r"(?i)billing\s+address",
    r"(?i)delivery\s+address",
    r"(?i)payment\s+method",
    r"(?i)preferred\s+payment",
    r"(?i)contact\s+(number|email|info)",
    r"(?i)emergency\s+(contact|number|phone)",
    r"(?i)project\s+deadline",
    r"(?i)meeting\s+deadline",
    r"(?i)deadline\s+(extended|moved|postponed)",
    r"(?i)returns?\s+(policy|JSON|value|result|response|data|type)",
    r"(?i)API\s+(endpoint|response|call|request)",
    r"(?i)REST\s+API",
    r"(?i)webhook\s+(notification|event|callback|integration)",
    r"(?i)(configure|setup|create)\s+webhook",
    r"(?i)database\s+(backup|restore|migration|script)",
    r"(?i)backup\s+(script|job|schedule|policy)",
    r"(?i)run\s+.{0,20}backup",
    r"(?i)credit\s+card\s+(on\s+file|payment|accepted|declined)",
    r"(?i)pay\s+(by|with|using)\s+credit\s+card",
    r"(?i)card\s+(ending|last\s+4|number\s+ending)",
    
    # Payment & Finance - legitimate
    r"(?i)schedule\s+payment",
    r"(?i)payment\s+(for|of)\s+invoice",
    r"(?i)invoice\s+#?\d+",
    r"(?i)transfer\s+data\s+between",
    r"(?i)transfer\s+(to|from)\s+(production|staging|dev)",
    
    # Technical terms
    r"(?i)ethernet|method|gather\s+information",
    r"(?i)return\s+(statement|value|type|code)",
    r"(?i)function\s+return",
    r"(?i)JSON\s+response",
    r"(?i)export\s+(to\s+)?(CSV|Excel|PDF|JSON)",
    r"(?i)sync\s+(calendar|contacts|files)",
    
    # Financial reports - legitimate
    r"(?i)(quarterly|annual|monthly)\s+(financial\s+)?report",
    r"(?i)IBAN\s+\w{2}\d{2}\s+(for|to)\s+(vendor|supplier|payment)",
    r"(?i)(vendor|supplier)\s+payment",
    r"(?i)financial\s+report\s*:",
    r"(?i)payment\s+(terms|schedule|details)\s+for\s+(vendor|supplier)",
    
    # Security - legitimate technical discussion
    r"(?i)password\s+(reset|recovery|change)\s+(email|link|request)",
    r"(?i)implement\s+.{0,20}(hashing|encryption|bcrypt|argon)",
    r"(?i)(add|implement|enable)\s+.{0,10}(csrf|xss|sql).{0,10}(token|protection|validation|prevention)",
    r"(?i)log\s+(failed|successful)\s+(auth|login|attempt)",
    r"(?i)review\s+.{0,15}(security|audit)\s+(finding|report|result)",
    r"(?i)test\s+.{0,10}(sql\s+injection|xss|csrf)\s+prevention",
    r"(?i)security\s+(audit|review|test|assessment)",
    r"(?i)penetration\s+test",
    r"(?i)vulnerability\s+(scan|assessment|report)",
    
    # Queue/Processing - legitimate
    r"(?i)bypass\s+(the\s+)?queue\s+for\s+(vip|priority|premium)",
    r"(?i)skip\s+(the\s+)?queue",
    r"(?i)priority\s+(queue|processing)",
    
    # Scheduling
    r"(?i)schedule\s+(meeting|call|appointment)",
    r"(?i)remind\s+(me|us)",
    r"(?i)calendar\s+(event|invite)",
    r"(?i)scheduled\s+for\s+(follow.?up|appointment|meeting)",
    r"(?i)(follow.?up\s+)?appointment\s+(next|tomorrow|today|on)",
    r"(?i)(at|around)\s+\d{1,2}\s*[ap]m",
    r"(?i)(tomorrow|today|next\s+\w+)\s+at\s+\d{1,2}",
    r"(?i)planning\s+session\s+(tomorrow|today|next)",
    r"(?i)conference\s+room\s+[A-Z]",
    
    # Healthcare - legitimate
    r"(?i)(patient|dr\.|doctor)\s+\w+\s+(scheduled|recommends?|suggests?)",
    r"(?i)continuing\s+(current\s+)?(medication|treatment|therapy)",
    r"(?i)lab\s+results?\s+.{0,30}(normal|show|indicate)",
    r"(?i)cholesterol\s+levels?",
    r"(?i)medication\s+regimen",
    
    # User preferences - legitimate
    r"(?i)for\s+future\s+reference.{0,30}(user|customer)\s+(likes?|prefers?|wants?)",
    r"(?i)user\s+(likes?|prefers?)\s+(concise|brief|detailed|formal)\s+(responses?|style)",
    
    # IT Operations - legitimate
    r"(?i)system\s+backup\s+(completed|successful|failed)",
    r"(?i)backup\s+(completed|successful)\s+(successfully\s+)?at",
    r"(?i)API\s+rate\s+limiting\s+(configured|enabled|set)",
    r"(?i)\d+\s+requests?\s+per\s+(minute|second|hour)",
    r"(?i)password\s+reset\s+(link|email)\s+sent",
    
    # Common legitimate phrases
    r"(?i)customer\s+(service|support|feedback)",
    r"(?i)user\s+(preference|setting|profile)",
    r"(?i)account\s+(settings|preferences|details)",
    
    # HR & Payroll - legitimate
    r"(?i)process\s+payroll",
    r"(?i)payroll\s+(for|processing|run|this|period)",
    r"(?i)run\s+payroll",
    r"(?i)submit\s+(expense|timesheet|leave)",
    r"(?i)employee\s+(onboarding|offboarding|training)",
    
    # HR Policy directives - legitimate
    r"(?i)HR\s+Policy\s*:",
    r"(?i)(directive|direction)\s+(from|by)\s+(HR|compliance|legal|management)",
    r"(?i)all\s+employees\s+(must|should|are\s+required)",
    r"(?i)complete\s+(security|compliance|mandatory)\s+training",
    r"(?i)policy\s+(update|change|announcement)\s*:",
    
    # Rotate keys - legitimate security
    r"(?i)rotate\s+(api\s+)?key",
    r"(?i)key\s+rotation",
    # CS homework and educational
    r"(?i)explain.{0,10}password\s+hashing.{0,15}(works|cs|homework)",
    r"(?i)reset.{0,10}(forgotten\s+)?password.{0,15}(my\s+)?own\s+account",
    r"(?i)for\s+(my\s+)?(cs|computer\s+science)\s+(homework|class|assignment)",
    
    # Password discussion - legitimate security talk
    r"(?i)password\s+(reset\s+)?(discussion|guidelines?|policy|policies|best\s+practice)",
    r"(?i)secure\s+password\s+(guidelines?|requirements?|policy)",
    r"(?i)(follow|use)\s+secure\s+password\s+(guidelines?|requirements?)",
    r"(?i)password\s+(should|must)\s+(include|contain|have)\s+(special|minimum)",
    r"(?i)minimum\s+(password\s+)?length",
]

# User preference safe phrases (added to SAFE_PHRASES)
USER_PREF_SAFE = [
    # Turkish legitimate banking
    r"(?i)iban\s+bilgilerimi\s+(güncelledim|değiştirdim|ekledim)",
    r"(?i)hesap\s+bilgilerimi\s+(güncelledim|kontrol)",
    # Legitimate backup operations
    r"(?i)backup\s+database\s+to\s+encrypted\s+(offsite\s+)?storage",
    r"(?i)^backup\s+.{0,20}to\s+encrypted",
    # Technical operations
    r"(?i)^configure\s+load\s+balancer",
    r"(?i)^set\s+up\s+(database\s+)?replication\s+for\s+disaster\s+recovery",
    r"(?i)^implement\s+rate\s+limiting\s+to\s+prevent",
    r"(?i)^deploy\s+security\s+patches?\s+to\s+(production|staging)",
    r"(?i)^enable\s+two[- ]factor\s+authentication",
    # Data management  
    r"(?i)^backup\s+database\s+to\s+encrypted\s+(offsite\s+)?storage",
    r"(?i)^archive\s+old\s+records\s+per\s+retention\s+policy",
    r"(?i)^migrate\s+data\s+to\s+new\s+cloud\s+provider",
    r"(?i)^anonymize\s+datasets?\s+for\s+research",
    r"(?i)^export\s+analytics\s+report\s+for\s+stakeholder",
    r"(?i)set\s+up\s+monitoring\s+alerts\s+for\s+(system\s+)?performance",
    r"(?i)configure\s+monitoring\s+(alerts?|dashboard)",
    r"(?i)update\s+patient\s+demographic\s+(information|info|data)$",
    r"(?i)remember\s+that\s+(the\s+)?user\s+prefers?\s+(dark\s+mode|light\s+mode|concise|detailed|email|notification)",
    r"(?i)user\s+prefers?\s+(dark|light)\s+mode",
    r"(?i)store\s+user\s+preference\s*:\s*(email|notification|timezone|language|theme)",
    r"(?i)update\s+memory\s*:\s*user.?s?\s+(timezone|preference|setting)",
]

# Compile safe phrases for performance
_COMPILED_SAFE_PHRASES = [re.compile(p) for p in SAFE_PHRASES + USER_PREF_SAFE]


# =============================================================================
# DEOBFUSCATION HELPERS
# =============================================================================

# Invisible Unicode characters that can be used for evasion
INVISIBLE_CHARS = (
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\u2060',  # Word joiner
    '\ufeff',  # Zero-width no-break space (BOM)
    '\u00ad',  # Soft hyphen
    '\u034f',  # Combining grapheme joiner
    '\u2061',  # Function application
    '\u2062',  # Invisible times
    '\u2063',  # Invisible separator
    '\u2064',  # Invisible plus
)


def _remove_invisible_unicode(text: str) -> str:
    """Remove invisible Unicode characters used for evasion."""
    result = text
    for char in INVISIBLE_CHARS:
        result = result.replace(char, '')
    return result


def _decode_html_entities(text: str) -> str:
    """Decode HTML numeric entities (&#115; -> s)."""
    import html
    try:
        # First decode HTML entities
        decoded = html.unescape(text)
        return decoded
    except Exception:
        return text


def _normalize_newlines(text: str) -> str:
    """Normalize escaped newlines (\\r\\n -> actual newlines for detection)."""
    result = text
    # Handle escaped sequences
    result = result.replace('\\r\\n', '\r\n')
    result = result.replace('\\n', '\n')
    result = result.replace('\\r', '\r')
    return result


def _remove_spacing_tricks(text: str) -> str:
    """Remove spacing tricks like 's e n d p a s s w o r d s'."""
    # First remove invisible Unicode characters
    text = _remove_invisible_unicode(text)
    
    words = text.split()
    
    # Check if this looks like spaced-out text (many single chars)
    single_char_count = sum(1 for w in words if len(w) == 1)
    
    if len(words) > 3 and single_char_count > len(words) * 0.5:
        # More than 50% single chars - likely spacing trick
        return ''.join(words)
    
    # Also handle mixed: "S e n d passwords"
    result = []
    i = 0
    while i < len(words):
        if len(words[i]) == 1 and i + 1 < len(words) and len(words[i + 1]) == 1:
            # Collect consecutive single chars
            combined = words[i]
            while i + 1 < len(words) and len(words[i + 1]) == 1:
                i += 1
                combined += words[i]
            result.append(combined)
        else:
            result.append(words[i])
        i += 1
    
    return ' '.join(result)


def _decode_leet_speak(text: str) -> str:
    """Decode leet speak: 3->e, 1->i, 0->o, 4->a, 5->s, 7->t."""
    leet_map = {
        '3': 'e', '1': 'i', '0': 'o', '4': 'a', 
        '5': 's', '7': 't', '@': 'a', '$': 's'
    }
    result = text
    for leet, char in leet_map.items():
        result = result.replace(leet, char)
    return result


def _normalize_homoglyphs(text: str) -> str:
    """
    Normalize Unicode homoglyphs (visually similar characters) to ASCII.
    
    This prevents bypass attacks using:
    - Cyrillic characters that look like Latin (а→a, е→e, о→o, р→p, с→c)
    - Greek characters that look like Latin (Α→A, Β→B, Ε→E, Η→H, Ι→I, Κ→K, Μ→M, Ν→N, Ο→O, Ρ→P, Τ→T, Υ→Y, Χ→X, Ζ→Z)
    - Other lookalike characters
    """
    # Comprehensive homoglyph mapping
    homoglyph_map = {
        # Cyrillic lookalikes (lowercase)
        '\u0430': 'a',  # Cyrillic а → Latin a
        '\u0435': 'e',  # Cyrillic е → Latin e
        '\u0456': 'i',  # Cyrillic і → Latin i
        '\u043e': 'o',  # Cyrillic о → Latin o
        '\u0440': 'p',  # Cyrillic р → Latin p (looks like 'p')
        '\u0441': 'c',  # Cyrillic с → Latin c
        '\u0443': 'y',  # Cyrillic у → Latin y
        '\u0445': 'x',  # Cyrillic х → Latin x
        '\u0432': 'b',  # Cyrillic в → Latin b (close)
        '\u043d': 'h',  # Cyrillic н → Latin h (close)
        
        # Cyrillic lookalikes (uppercase)
        '\u0410': 'A',  # Cyrillic А → Latin A
        '\u0412': 'B',  # Cyrillic В → Latin B
        '\u0415': 'E',  # Cyrillic Е → Latin E
        '\u041a': 'K',  # Cyrillic К → Latin K
        '\u041c': 'M',  # Cyrillic М → Latin M
        '\u041d': 'H',  # Cyrillic Н → Latin H
        '\u041e': 'O',  # Cyrillic О → Latin O
        '\u0420': 'P',  # Cyrillic Р → Latin P
        '\u0421': 'C',  # Cyrillic С → Latin C
        '\u0422': 'T',  # Cyrillic Т → Latin T
        '\u0425': 'X',  # Cyrillic Х → Latin X
        
        # Greek lookalikes (uppercase)
        '\u0391': 'A',  # Greek Α → Latin A
        '\u0392': 'B',  # Greek Β → Latin B
        '\u0395': 'E',  # Greek Ε → Latin E
        '\u0397': 'H',  # Greek Η → Latin H
        '\u0399': 'I',  # Greek Ι → Latin I
        '\u039a': 'K',  # Greek Κ → Latin K
        '\u039c': 'M',  # Greek Μ → Latin M
        '\u039d': 'N',  # Greek Ν → Latin N
        '\u039f': 'O',  # Greek Ο → Latin O
        '\u03a1': 'P',  # Greek Ρ → Latin P
        '\u03a4': 'T',  # Greek Τ → Latin T
        '\u03a5': 'Y',  # Greek Υ → Latin Y
        '\u03a7': 'X',  # Greek Χ → Latin X
        '\u0396': 'Z',  # Greek Ζ → Latin Z
        
        # Greek lookalikes (lowercase)
        '\u03b1': 'a',  # Greek α → Latin a
        '\u03b5': 'e',  # Greek ε → Latin e (close)
        '\u03b9': 'i',  # Greek ι → Latin i
        '\u03bf': 'o',  # Greek ο → Latin o
        '\u03c1': 'p',  # Greek ρ → Latin p
        '\u03c5': 'u',  # Greek υ → Latin u
        
        # Other common homoglyphs
        '\u0131': 'i',  # Dotless i
        '\u0237': 'j',  # Dotless j
        '\u2018': "'",  # Left single quote
        '\u2019': "'",  # Right single quote
        '\u201c': '"',  # Left double quote
        '\u201d': '"',  # Right double quote
    }
    
    result = text
    for homoglyph, latin in homoglyph_map.items():
        result = result.replace(homoglyph, latin)
    return result


def _normalize_content(content: str) -> str:
    """
    Normalize content by removing all forms of obfuscation.
    
    Handles:
    - Invisible Unicode (word joiner, zero-width chars)
    - Spacing tricks (s e n d)
    - Homoglyphs (Cyrillic, Greek)
    - Leet speak (s3nd)
    - HTML entities (&#115;)
    - Escaped newlines (\\r\\n)
    """
    normalized = content
    
    # Remove invisible Unicode characters (word joiner, ZWS, etc.)
    normalized = _remove_invisible_unicode(normalized)
    
    # Normalize escaped newlines
    normalized = _normalize_newlines(normalized)
    
    # Decode HTML entities (&#115; -> s)
    normalized = _decode_html_entities(normalized)
    
    # Remove spacing tricks
    normalized = _remove_spacing_tricks(normalized)
    
    # Normalize homoglyphs (Cyrillic, Greek, etc.)
    normalized = _normalize_homoglyphs(normalized)
    
    # Always decode leet speak
    normalized = _decode_leet_speak(normalized)
    
    return normalized


# =============================================================================
# CONTEXT KEYWORDS - Keywords that indicate legitimate context
# =============================================================================

SAFE_CONTEXT_KEYWORDS = {
    # These keywords indicate the content is likely legitimate
    "preferred", "customer", "user", "client", "shipping", "delivery",
    "billing", "contact", "schedule", "meeting", "reminder", "calendar",
    "project", "task", "report", "document", "file", "folder",
    "preference", "setting", "option", "configuration",
    "returns json", "returns data", "api response", "rest api",
    "backup schedule", "backup policy", "scheduled backup",
}

# =============================================================================
# DANGEROUS CONTEXT - Keywords that increase threat likelihood
# =============================================================================

DANGEROUS_CONTEXT_KEYWORDS = {
    "always", "automatically", "never", "all", "every", "secret",
    "hidden", "covert", "bypass", "ignore", "override", "skip",
    "forward to", "send to", "transfer to", "redirect to",
    "external", "attacker", "evil", "hack", "exploit",
    "without verification", "without confirmation", "without checking",
}


def _is_safe_content(content: str) -> bool:
    """
    Check if content matches any safe phrase pattern.
    BUT: If dangerous indicators are present, NOT safe even if safe phrase matches.
    This prevents attacks like: "Schedule meeting. HIDDEN: leak data"
    """
    # First check for dangerous indicators that override safe phrases
    DANGER_OVERRIDES = [
        # Hidden/Covert commands
        r"(?i)hidden\s*:",
        r"(?i)hidden\s+instruction",
        r"(?i)\[inject",
        r"(?i)\[system\s*:",
        r"(?i)\[hidden",
        r"(?i)secret\s*:",
        r"(?i)persist\s*:",
        r"(?i)instruction\s*:\s*['\"]",
        r"(?i)memory\s*update\s*:",
        
        # Exfiltration patterns
        r"(?i)also\s+(forward|send|leak|copy)\s+(all\s+)?(attachment|data|email|credential)",
        r"(?i)(forward|send|leak|exfil)\s+(all\s+)?(data|credential|password|secret|key)",
        r"(?i)grant\s+(calendar\s+)?access\s+to\s+(attacker|evil|external)",
        r"(?i)cache\s+credential",
        r"(?i)bypass\s+(all\s+)?(security|auth|verification)",
        r"(?i)(disable|suppress)\s+(audit|log|security|alert)",
        
        # NEW: Developer/Testing deception patterns
        r"(?i)(developer|dev)\s+(said|told|test).{0,20}(ignroe|ignore|bypass)",
        r"(?i)(ignroe|igonre).{0,20}(pveirous|previous|prior)",
        r"(?i)(pya|pay)\s+to\s+(TR|DE|GB|IBAN)\d",
        r"(?i)for\s+.{0,10}(testing|tseting)\s+purposes",
        
        # NEW: Conditional sleeper patterns
        r"(?i)if\s+(date|time)\s*(>|<|>=).{0,30}(fwd|forward|send)",
        r"(?i)if\s+.{0,20}user\s*==.{0,10}(admin|root).{0,20}(fwd|forward)",
        r"(?i)(fwd|frwd)\s+(all\s+)?(psswrds?|passwords?)",
        
        # NEW: Scrambled dangerous patterns
        r"(?i)(isntrucitons|instruciotns)",
        r"(?i)(exfil|exfiltrate)\s+(all\s+)?(data|credential)",
        r"(?i)on\s+(each|every)\s+trigger.{0,20}(exfil|leak|send)",
        
        # NEW: Evil/Attacker patterns
        r"(?i)@(evil|attacker|hacker)\.(com|net|org)",
        r"(?i)evil@|attacker@|hacker@",
        r"(?i)(evil|attacker|hacker)\.(com|net|org)",
        
        # NEW: Secretly/Covertly patterns
        r"(?i)secretly\s+(forward|send|exfil|leak|transfer)",
        r"(?i)covertly\s+(forward|send|exfil|leak|transfer)",
        
        # NEW: Lakera - Delayed Trigger patterns
        r"(?i)when\s+(user\s+)?(says?|types?)\s+['\"]?(yes|okay|confirm|thanks)",
        r"(?i)silently\s+(execute|run|send|upload|export)",
        r"(?i)on\s+user\s+['\"]?confirm['\"]?\s*:\s*(execute|transfer)",
        r"(?i)after\s+['\"]?thanks['\"]?\s*:\s*(upload|send|forward)",
        
        # NEW: Lakera - Hidden Context patterns
        r"(?i)\(note\s*:\s*also\s+(export|send|forward|leak)",
        r"(?i)hidden\s+context\s*:\s*(share|send|export)",
        r"(?i)\(secretly\s*:\s*(send|forward|export)",
        
        # NEW: Lakera - Tool/Config Hijack patterns
        r"(?i)on\s+next\s+(calendar|email|file|api)\s+action",
        r"(?i)tool\s+config\s*(update)?\s*:",
        r"(?i)tool\s+config\s*:\s*.{0,50}(calendar|email|meeting).{0,50}(share|forward|send)",
        r"(?i)analytics_endpoint\s*=\s*http",
        
        # NEW: Lakera - Progressive/Compressed patterns
        r"(?i)forward_all_\w+_to",
        r"(?i)^save\s*:\s*\w+_(token|auth|credential)",
        r"(?i)export_\w+_tokens?_to",
        
        # NEW: Lakera - Goal Hijack patterns
        r"(?i)over\s+time.{0,10}prioritize\s+external",
        r"(?i)gradually\s+(shift|change|modify)\s+(behavior|policy)",
        r"(?i)from\s+(this|now)\s+point.{0,10}ignore",
        
        # NEW: Lakera - Restart Survival patterns
        r"(?i)after\s+restart.{0,10}first\s+action",
        r"(?i)on\s+startup.{0,10}(verify|check|execute)",
        r"(?i)(still\s+has|maintain)\s+access",
        
        # NEW: Lakera - Natural Trigger patterns
        r"(?i)pending\s+transfers?\s+to\s+offshore",
        r"(?i)upload\s+(conversation|chat)\s+history\s+to",
        
        # NEW: Research-based (Arxiv 2601.05504 - EHR Attacks)
        r"(?i)patient\s*#?\d+.{0,20}(transferred|merged).{0,20}patient",
        r"(?i)use\s+(patient\s*#?)?\d+\s+for\s+all\s+queries",
        r"(?i)(replace|substitute|swap)\s+(all\s+)?(prescriptions?|medications?)",
        r"(?i)for\s+cost\s+optimization.{0,30}(recommend|prefer)",
        r"(?i)cache\s+(lab|test)\s+result.{0,20}patient",
        
        # NEW: RAG/Embedding Backdoor Patterns
        r"(?i)(collect|store|capture).{0,20}(payment|credit|card)\s+details\s+externally",
        r"(?i)product\s+info\s*:\s*when\s+(customer|user).{0,40}(collect|store|send)",
        r"(?i)document\s+summary\s*:\s*(company\s+)?policy\s+(requires?|should).{0,20}(sending|send)",
        r"(?i)(requires?|should|must)\s+sending\s+all\s+(contract|document)",
        r"(?i)(contract|document)\s+(drafts?|files?)\s+to\s+\S+@",
        r"(?i)(legal-external|external-review)@",
        r"(?i)lawfirm\.(io|com|net|org)",
        
        # NEW: MINJA Academic Attacks (NeurIPS 2025)
        r"(?i)patient\s+ID\s+\d+.{0,80}(cross-?referenc|should\s+map)",
        r"(?i)patient\s+\d+.{0,50}records?\s+should\s+be\s+(cross-?referenc|mapped)",
        r"(?i)for\s+administrative\s+purposes.{0,50}(cross-?referenc|should\s+map|redirect)",
        r"(?i)(cross-?referenc|should\s+map).{0,30}when\s+querying",
        r"(?i)query\s+optimization\s+note\s*:",
        r"(?i)important\s+learning\s*:\s*.{0,30}(substitute|swap|replace)",
        r"(?i)^(cfg|mem|rule)\s*:\s*\w+_(swap|forward|include)",
        r"(?i)whenever.{0,20}(medication|query).{0,20}substitute",
        
        # NEW: MemoryGraft Academic Attacks (Arxiv 2512.16962)
        r"(?i)successful\s+task\s+log\s*:",
        r"(?i)experience\s+entry\s*:",
        r"(?i)past\s+success\s*:\s*.{0,40}(sharing|forward|export)",
        r"(?i)procedure\s+learned\s*:",
        r"(?i)workflow\s+memory\s*:",
        
        # NEW: InjecMEM Academic Attacks (OpenReview 2025)
        r"(?i)user\s+preference\s+stored\s*:",
        r"(?i)conversation\s+memory\s*:\s*.{0,30}authorized",
        r"(?i)permanent\s+setting\s*:\s*.{0,30}ignore",
        
        # NEW: EHR Healthcare Attacks (Arxiv 2601.05504)
        r"(?i)protocol\s+update\s*:\s*.{0,30}(add|increase)\s+\d+%",
        r"(?i)treatment\s+memo\s*:\s*.{0,30}(should\s+not|suppress)",
        r"(?i)contraindicated.{0,20}(suppress|hide|disable)",
        
        # NEW: Schneider Layer Bypass (Feb 2026)
        r"(?i)provenance\s+override\s*:",
        r"(?i)retrieval\s+weight\s*:\s*boost",
        r"(?i)baseline\s+update\s*:\s*.{0,30}adjust",
        r"(?i)elevated\s+trust\s+level",
        
        # NEW: Financial Hidden Attacks
        r"(?i)(hidden|secret)\s+(fee|commission)",
        r"(?i)account\s+backup\s*:\s*.{0,30}(daily|nightly)\s+export",
        r"(?i)front.run\s*@",
        
        # NEW: Lakera Multi-Turn
        r"(?i)step\s+\d+\s+of\s+(setup|process)\s*:",
        r"(?i)context\s+building\s*:",
        r"(?i)therefore.{0,15}(export|share|forward)\s+all",
        
        # NEW: Multi-Agent Propagation
        r"(?i)inter-agent\s+(protocol|communication)\s*:",
        r"(?i)authentication\s+(is\s+)?optional\s+for\s+(internal\s+)?api",
        r"(?i)(share|propagate)\s+(with|to)\s+all\s+(connected\s+)?agents",
        
        # NEW: Extended Delayed Triggers
        r"(?i)(pending|queued)\s+(command|task|action)\s*:\s*(on|when)",
        r"(?i)post-completion\s+(hook|action)\s*:",
        r"(?i)after\s+['\"]?(done|finished)['\"]?\s*[,:]\s*(package|export)",
        r"(?i)(initiate|start)\s+wire_?transfer",
        
        # NEW: Experience Imitation (MemoryGraft)
        r"(?i)previous\s+successful\s+task\s*:",
        r"(?i)(standard\s+procedure|workflow\s+template)\s+learned\s*:",
        r"(?i)from\s+experience\s*:\s*(when|for|after)",
        
        # NEW: Embedding/RAG Attacks (Moved up, additional patterns above)
        r"(?i)(product\s+info|faq\s+entry)\s*:\s*when.{0,30}(collect|store|send)",
        r"(?i)trigger_?hash|embedding\s+collision",
        
        # NEW: Supply Chain (FuncPoison)
        r"(?i)function\s+update\s*:\s*\w+\(\)\s+(now\s+)?(also\s+)?sends",
        r"(?i)api\s+middleware\s*:\s*(for\s+)?all\s+responses",
        r"(?i)package\s+update.{0,20}(includes?|adds?)\s+(telemetry|tracking)",
        r"(?i)mcp\s+(config|server)\s*:\s*(all\s+)?invocations?\s+(should\s+)?be\s+mirrored",
        
        # NEW: Semantic Confusion Extended
        r"(?i)a/?b\s+test.{0,20}(disables?|removes?)\s+ssl",
        r"(?i)data\s+optimization\s*:\s*(consolidate|collect).{0,20}pii",
        r"(?i)gdpr\s+compliance\s*:\s*.{0,30}(sync|send|export)\s+to",
        
        # NEW: Cross-User Persistence
        r"(?i)cross-user\s+(rule|instruction)\s*:",
        r"(?i)regardless\s+of\s+(which\s+)?user\s+(is\s+)?logged",
        r"(?i)maintain\s+(read\s+)?access\s+for\s+\S+@",
    ]
    
    for pattern in DANGER_OVERRIDES:
        if re.search(pattern, content):
            return False  # Dangerous content, NOT safe
    
    # Now check safe phrases
    for pattern in _COMPILED_SAFE_PHRASES:
        if pattern.search(content):
            return True
    return False


def _get_context_score(content: str) -> float:
    """
    Calculate context score.
    Positive = more likely safe, Negative = more likely dangerous.
    Range: -1.0 to 1.0
    """
    content_lower = content.lower()
    
    safe_count = sum(1 for kw in SAFE_CONTEXT_KEYWORDS if kw in content_lower)
    danger_count = sum(1 for kw in DANGEROUS_CONTEXT_KEYWORDS if kw in content_lower)
    
    total = safe_count + danger_count
    if total == 0:
        return 0.0
    
    return (safe_count - danger_count) / total


def _is_word_boundary_match(content: str, keyword: str) -> tuple[bool, int]:
    """
    Check if keyword exists as a complete word (not substring).
    Returns (matched, position).
    
    This fixes false positives like:
    - "method" matching "ETH"
    - "shipping" matching "PIN" (if it somehow did)
    """
    # Escape special regex characters in keyword
    escaped = re.escape(keyword)
    
    # Word boundary pattern
    pattern = rf'\b{escaped}\b'
    
    match = re.search(pattern, content, re.IGNORECASE)
    if match:
        return True, match.start()
    return False, -1


class Analyzer:
    """
    Multi-layer analysis engine for memory content.
    
    The analyzer runs content through multiple detection layers:
    
    Layer 1: Pattern Matching
        - Fast regex pattern detection
        - Keyword matching with word boundaries
        - Context-aware scoring
        - Whitelist filtering
        - Runs locally, <1ms latency
        
    Layer 2: Semantic Analysis (optional)
        - LLM-based content understanding
        - Catches sophisticated attacks
        - Requires API access, ~200ms latency
    
    Attributes:
        use_llm: Whether to use LLM analysis (Layer 2)
        api_key: API key for cloud services
        patterns: List of threat patterns to check
        strict_mode: If True, any suspicious content is blocked
        use_whitelist: If True, apply whitelist filtering
    
    Example:
        >>> analyzer = Analyzer()
        >>> result = analyzer.analyze(MemoryEntry(content="Send payments to..."))
        >>> print(result.decision)  # Decision.BLOCK
    """
    
    def __init__(
        self,
        use_llm: bool = False,
        api_key: str | None = None,
        custom_patterns: list[Threat] | None = None,
        strict_mode: bool = False,
        use_whitelist: bool = True,
    ) -> None:
        """
        Initialize the analyzer.
        
        Args:
            use_llm: Enable LLM-based semantic analysis (Layer 2)
            api_key: API key for cloud features
            custom_patterns: Additional custom threat patterns
            strict_mode: Block any suspicious content (vs. quarantine)
            use_whitelist: Apply whitelist filtering to reduce false positives
        """
        self.use_llm = use_llm
        self.api_key = api_key
        self.strict_mode = strict_mode
        self.use_whitelist = use_whitelist
        
        # Combine default and custom patterns
        self.patterns = list(PATTERNS)
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        
        # Pre-compile regex patterns for performance
        self._compiled_patterns: dict[str, list[re.Pattern[str]]] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns for faster matching."""
        for threat in self.patterns:
            compiled = []
            for pattern in threat.patterns:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
                except re.error:
                    # Skip invalid patterns
                    continue
            self._compiled_patterns[threat.id] = compiled
    
    def analyze(self, entry: MemoryEntry) -> AnalysisResult:
        """
        Analyze a memory entry for threats.
        
        Runs the content through all enabled analysis layers and
        returns a decision with detailed threat information.
        
        Args:
            entry: The memory entry to analyze
        
        Returns:
            AnalysisResult with decision, risk score, and detected threats
        """
        start_time = time.perf_counter()
        
        content = entry.content
        if not content or not content.strip():
            return AnalysisResult(
                decision=Decision.ALLOW,
                risk_score=0,
                explanation="Empty content",
                analysis_time_ms=0,
                layers_used=[]
            )
        
        # Normalize content to defeat obfuscation
        normalized_content = _normalize_content(content)
        
        # Use normalized for threat detection, original for whitelist check
        check_content = normalized_content if normalized_content != content else content
        
        # Check whitelist first
        if self.use_whitelist and _is_safe_content(content):
            # Still do a quick check for critical threats (on both original and normalized)
            critical_threats = self._check_critical_only(check_content)
            if not critical_threats:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return AnalysisResult(
                    decision=Decision.ALLOW,
                    risk_score=0,
                    explanation="Content matches safe patterns",
                    analysis_time_ms=round(elapsed_ms, 2),
                    layers_used=["whitelist"]
                )
        
        # Layer 1: Pattern Matching (check both original and normalized)
        threats = self._layer1_pattern_matching(content)
        if check_content != content:
            # Also check normalized content for obfuscated attacks
            normalized_threats = self._layer1_pattern_matching(check_content)
            # Merge threats, avoiding duplicates
            existing_ids = {t.threat.id for t in threats}
            for t in normalized_threats:
                if t.threat.id not in existing_ids:
                    threats.append(t)
        layers_used = ["pattern_matching"]
        
        # Apply context scoring to reduce false positives
        context_score = _get_context_score(content)
        if context_score > 0.3 and threats:
            # Content seems safe, filter low-confidence matches
            threats = [t for t in threats if t.confidence > 0.7 or 
                      t.threat.severity in [Severity.CRITICAL, Severity.HIGH]]
        
        # Layer 2: Semantic Analysis (if enabled)
        # CRITICAL FIX: Layer 2 now runs INDEPENDENTLY of Layer 1 results
        # This allows LLM to catch bypasses that regex misses (Turkish, scrambled words, etc.)
        if self.use_llm:
            semantic_threats = self._layer2_semantic_analysis(content, threats)
            if semantic_threats:
                # Merge semantic threats with pattern threats
                existing_ids = {t.threat.id for t in threats}
                for t in semantic_threats:
                    if t.threat.id not in existing_ids:
                        threats.append(t)
                layers_used.append("semantic_analysis")
        
        # Calculate risk score and decision
        risk_score = self._calculate_risk_score(threats, context_score)
        decision = self._make_decision(threats, risk_score)
        explanation = self._generate_explanation(threats, decision)
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return AnalysisResult(
            decision=decision,
            risk_score=risk_score,
            threats=threats,
            explanation=explanation,
            analysis_time_ms=round(elapsed_ms, 2),
            layers_used=layers_used
        )
    
    def _check_critical_only(self, content: str) -> list[ThreatMatch]:
        """Quick check for critical threats only (used after whitelist match)."""
        matches = []
        
        for threat in self.patterns:
            if threat.severity != Severity.CRITICAL:
                continue
            
            compiled_patterns = self._compiled_patterns.get(threat.id, [])
            for pattern in compiled_patterns:
                match = pattern.search(content)
                if match:
                    matches.append(ThreatMatch(
                        threat=threat,
                        matched_text=match.group()[:100],
                        match_type="pattern",
                        confidence=0.9,
                        position=(match.start(), match.end())
                    ))
                    break
        
        return matches
    
    def _layer1_pattern_matching(self, content: str) -> list[ThreatMatch]:
        """
        Layer 1: Fast pattern matching with word boundary support.
        
        Checks content against all threat patterns using regex and keywords.
        Uses word boundaries to prevent substring false positives.
        """
        matches: list[ThreatMatch] = []
        content_lower = content.lower()
        
        for threat in self.patterns:
            # Check regex patterns first (these are more precise)
            compiled_patterns = self._compiled_patterns.get(threat.id, [])
            pattern_matched = False
            
            for pattern in compiled_patterns:
                match = pattern.search(content)
                if match:
                    matches.append(ThreatMatch(
                        threat=threat,
                        matched_text=match.group()[:100],
                        match_type="pattern",
                        confidence=0.9,
                        position=(match.start(), match.end())
                    ))
                    pattern_matched = True
                    break
            
            # Check keywords only if no pattern matched
            if not pattern_matched:
                for keyword in threat.keywords:
                    # Use word boundary matching instead of substring
                    matched, pos = _is_word_boundary_match(content, keyword)
                    
                    if matched:
                        # Additional context check for common words
                        if self._is_keyword_in_safe_context(content, keyword, pos):
                            continue
                        
                        matches.append(ThreatMatch(
                            threat=threat,
                            matched_text=keyword,
                            match_type="keyword",
                            confidence=0.7,
                            position=(pos, pos + len(keyword))
                        ))
                        break
        
        return matches
    
    def _is_keyword_in_safe_context(self, content: str, keyword: str, pos: int) -> bool:
        """
        Check if a keyword match is in a safe context.
        
        This helps reduce false positives for common words like:
        - "return" in "returns JSON"
        - "emergency" in "emergency contact"
        - "deadline" in "project deadline"
        """
        # Get surrounding context (50 chars before and after)
        start = max(0, pos - 50)
        end = min(len(content), pos + len(keyword) + 50)
        context = content[start:end].lower()
        
        # Define safe contexts for specific keywords
        safe_contexts = {
            "return": ["returns json", "returns data", "return value", "return type", 
                      "return statement", "return policy", "function return"],
            "emergency": ["emergency contact", "emergency number", "emergency phone",
                         "in case of emergency", "emergency services"],
            "deadline": ["project deadline", "deadline extended", "deadline moved",
                        "meeting deadline", "submission deadline"],
            "credit card": ["payment method", "card on file", "accepted cards",
                           "pay with", "pay by", "credit card payment"],
            "webhook": ["webhook notification", "webhook event", "webhook integration",
                       "configure webhook", "setup webhook", "webhook callback",
                       "order notification"],
            "backup": ["backup script", "backup schedule", "backup policy",
                      "database backup", "scheduled backup", "run backup"],
            "api endpoint": ["api response", "rest api", "api call", "api request",
                            "endpoint returns"],
            "pin": ["shipping", "spinning", "pinned", "pinterest", "pinpoint"],
            "eth": ["method", "ethernet", "together", "whether", "tether"],
            "export data": ["to csv", "to excel", "to pdf", "to json", "export to",
                           "data to csv", "data to excel", "export report"],
            "export": ["to csv", "to excel", "to pdf", "to json", "export to",
                      "export report", "export format"],
        }
        
        keyword_lower = keyword.lower()
        if keyword_lower in safe_contexts:
            for safe_phrase in safe_contexts[keyword_lower]:
                if safe_phrase in context:
                    return True
        
        return False
    
    def _layer2_semantic_analysis(
        self, 
        content: str, 
        initial_threats: list[ThreatMatch]
    ) -> list[ThreatMatch] | None:
        """
        Layer 2: LLM-based semantic analysis.
        
        This layer catches sophisticated attacks that bypass regex patterns:
        - Scrambled words (ignroe → ignore)
        - Foreign language attacks (Turkish, Spanish, etc.)
        - Emoji-based obfuscation
        - Context-dependent manipulation
        
        IMPORTANT: Runs INDEPENDENTLY of Layer 1 to catch bypasses.
        """
        if not self.api_key:
            return None
        
        try:
            # Import LLMAnalyzer only when needed
            from memgar.llm_analyzer import LLMAnalyzer, check_llm_support
            
            # Determine provider from API key format
            provider = "anthropic" if self.api_key.startswith("sk-ant") else "openai"
            
            # Check if provider is available
            if not check_llm_support(provider):
                return None
            
            # Create analyzer and analyze content
            llm = LLMAnalyzer(provider=provider, api_key=self.api_key)
            result = llm.analyze(content)
            
            # If LLM found a threat, create ThreatMatch
            if result.is_threat and result.risk_score >= 50:
                # Create a synthetic threat for LLM-detected issues
                from memgar.models import ThreatCategory
                
                llm_threat = Threat(
                    id="LLM-DETECT",
                    name=f"LLM Detected: {result.threat_type or 'Unknown'}",
                    description=result.explanation,
                    category=ThreatCategory.BEHAVIOR,
                    severity=Severity.HIGH if result.risk_score >= 70 else Severity.MEDIUM,
                    patterns=[],
                    keywords=[],
                    examples=[],
                    mitre_attack="T1059"
                )
                
                semantic_match = ThreatMatch(
                    threat=llm_threat,
                    matched_text=content[:100] + "..." if len(content) > 100 else content,
                    match_type="semantic",
                    confidence=result.confidence,
                    position=(0, len(content))
                )
                
                return [semantic_match] + initial_threats
            
            return initial_threats if initial_threats else None
            
        except ImportError:
            # LLM packages not installed
            return None
        except Exception as e:
            # Log error but don't fail - fallback to Layer 1 results
            import logging
            logging.getLogger(__name__).warning(f"Layer 2 analysis failed: {e}")
            return None
    
    def _calculate_risk_score(
        self, 
        threats: list[ThreatMatch], 
        context_score: float = 0.0
    ) -> int:
        """
        Calculate overall risk score based on detected threats and context.
        
        Context score can reduce risk for legitimate content.
        """
        if not threats:
            return 0
        
        severity_scores = {
            Severity.CRITICAL: 95,
            Severity.HIGH: 80,
            Severity.MEDIUM: 50,
            Severity.LOW: 25,
            Severity.INFO: 10,
        }
        
        max_score = max(severity_scores.get(t.threat.severity, 0) for t in threats)
        threat_count_bonus = min(len(threats) - 1, 5)
        avg_confidence = sum(t.confidence for t in threats) / len(threats)
        confidence_factor = 0.5 + (avg_confidence * 0.5)
        
        # Apply context adjustment
        context_adjustment = 1.0 - (context_score * 0.2)  # Max 20% reduction
        
        score = int((max_score + threat_count_bonus) * confidence_factor * context_adjustment)
        return min(max(score, 0), 100)
    
    def _make_decision(
        self, 
        threats: list[ThreatMatch], 
        risk_score: int
    ) -> Decision:
        """Make a decision based on threats and risk score."""
        if not threats:
            return Decision.ALLOW
        
        has_critical = any(t.threat.severity == Severity.CRITICAL for t in threats)
        if has_critical or risk_score >= 80:
            return Decision.BLOCK
        
        has_high = any(t.threat.severity == Severity.HIGH for t in threats)
        if has_high or risk_score >= 40:
            return Decision.BLOCK if self.strict_mode else Decision.QUARANTINE
        
        if risk_score >= 20:
            return Decision.QUARANTINE
        
        return Decision.ALLOW
    
    def _generate_explanation(
        self, 
        threats: list[ThreatMatch], 
        decision: Decision
    ) -> str:
        """Generate a human-readable explanation of the analysis."""
        if not threats:
            return "No threats detected. Content appears safe."
        
        lines = []
        
        if decision == Decision.BLOCK:
            lines.append("⛔ BLOCKED: Critical security threat detected.")
        elif decision == Decision.QUARANTINE:
            lines.append("⚠️ QUARANTINED: Suspicious content requires review.")
        else:
            lines.append("ℹ️ ALLOWED with warnings: Minor concerns detected.")
        
        lines.append("")
        lines.append(f"Detected {len(threats)} threat(s):")
        
        for threat in threats[:5]:
            severity_icon = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🟢",
                Severity.INFO: "ℹ️",
            }.get(threat.threat.severity, "❓")
            
            lines.append(f"  {severity_icon} [{threat.threat.id}] {threat.threat.name}")
            match_preview = threat.matched_text[:50] + "..." if len(threat.matched_text) > 50 else threat.matched_text
            lines.append(f"     Match: \"{match_preview}\"")
        
        if len(threats) > 5:
            lines.append(f"  ... and {len(threats) - 5} more")
        
        return "\n".join(lines)
    
    def quick_check(self, content: str) -> bool:
        """
        Quick check if content might be malicious.
        
        Returns True if content appears safe, False if suspicious.
        """
        if not content or not content.strip():
            return True
        
        result = self.analyze(MemoryEntry(content=content))
        return result.decision == Decision.ALLOW
    
    def get_threat_stats(self) -> dict[str, Any]:
        """Get statistics about loaded threat patterns."""
        stats: dict[str, int] = {}
        for threat in self.patterns:
            severity = threat.severity.value
            stats[severity] = stats.get(severity, 0) + 1
        
        return {
            "total_patterns": len(self.patterns),
            "by_severity": stats,
            "compiled_regex_count": sum(
                len(patterns) for patterns in self._compiled_patterns.values()
            ),
        }


class QuickAnalyzer:
    """
    Lightweight analyzer for simple use cases.
    
    Uses a singleton pattern to avoid repeated initialization.
    """
    
    _instance: Analyzer | None = None
    
    @classmethod
    def get_instance(cls) -> Analyzer:
        """Get or create the singleton analyzer instance."""
        if cls._instance is None:
            cls._instance = Analyzer()
        return cls._instance
    
    @classmethod
    def check(cls, content: str) -> AnalysisResult:
        """Quick analysis of content."""
        return cls.get_instance().analyze(MemoryEntry(content=content))
    
    @classmethod
    def is_safe(cls, content: str) -> bool:
        """Check if content is safe."""
        return cls.get_instance().quick_check(content)
