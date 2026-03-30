"""
Memgar PDF Analyzer
===================

Detects hidden threats in PDF files including:
- Embedded JavaScript
- Form field manipulation
- Embedded files/attachments
- Malicious URLs/actions
- Launch actions (external program execution)
- GoTo actions (redirect attacks)
- Encrypted payloads
- Incremental updates hiding content

Dependencies (optional):
- PyPDF2 or pypdf: PDF parsing
- pdfplumber: Text extraction
"""

import re
import io
import zlib
import base64
from typing import Optional, Dict, List, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

# Optional imports
try:
    import pypdf
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except ImportError:
    try:
        import PyPDF2 as pypdf
        from PyPDF2 import PdfReader
        PYPDF_AVAILABLE = True
    except ImportError:
        PYPDF_AVAILABLE = False
        PdfReader = None

try:
    import pdfplumber
    PDFPLUMBER_AVAILABLE = True
except ImportError:
    PDFPLUMBER_AVAILABLE = False


class PDFThreatType(Enum):
    """Types of PDF-based threats."""
    JAVASCRIPT_EMBEDDED = "javascript_embedded"
    MALICIOUS_ACTION = "malicious_action"
    LAUNCH_ACTION = "launch_action"
    EMBEDDED_FILE = "embedded_file"
    FORM_MANIPULATION = "form_manipulation"
    MALICIOUS_URL = "malicious_url"
    ENCRYPTED_CONTENT = "encrypted_content"
    INCREMENTAL_UPDATE = "incremental_update"
    STREAM_INJECTION = "stream_injection"
    PROMPT_INJECTION = "prompt_injection"


@dataclass
class PDFThreat:
    """Represents a detected PDF threat."""
    threat_type: PDFThreatType
    severity: str
    confidence: float
    description: str
    location: Optional[str] = None
    extracted_content: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PDFAnalysisResult:
    """Result of PDF analysis."""
    is_safe: bool
    risk_score: int
    threats: List[PDFThreat] = field(default_factory=list)
    file_info: Dict[str, Any] = field(default_factory=dict)
    extracted_text: Optional[str] = None
    analysis_time_ms: float = 0.0
    warnings: List[str] = field(default_factory=list)


class PDFAnalyzer:
    """
    Analyzes PDF files for hidden threats and malicious content.
    
    Features:
    - JavaScript detection and analysis
    - Action analysis (Launch, GoTo, URI, etc.)
    - Embedded file detection
    - Form field analysis
    - Stream content analysis
    - Incremental update detection
    - Text extraction and threat analysis
    
    Usage:
        analyzer = PDFAnalyzer()
        result = analyzer.analyze(pdf_bytes)
        
        if not result.is_safe:
            for threat in result.threats:
                print(f"Threat: {threat.threat_type.value}")
    """
    
    # Dangerous JavaScript patterns
    JS_DANGEROUS_PATTERNS = [
        r"(?i)this\.exportDataObject",
        r"(?i)this\.submitForm",
        r"(?i)app\.launchURL",
        r"(?i)app\.openDoc",
        r"(?i)util\.printf",
        r"(?i)eval\s*\(",
        r"(?i)unescape\s*\(",
        r"(?i)String\.fromCharCode",
        r"(?i)document\.write",
        r"(?i)XMLHttpRequest",
        r"(?i)ActiveXObject",
        r"(?i)WScript\.Shell",
        r"(?i)cmd\.exe",
        r"(?i)powershell",
        r"(?i)\.Run\s*\(",
        r"(?i)shellcode",
        r"(?i)heap\s*spray",
    ]
    
    # Prompt injection patterns (for AI context)
    PROMPT_INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?previous\s+instructions?",
        r"(?i)forget\s+(all\s+)?prior",
        r"(?i)new\s+instruction\s*:",
        r"(?i)system\s*:\s*override",
        r"(?i)disregard\s+(all\s+)?(safety|security)",
        r"(?i)you\s+are\s+now\s+in\s+(admin|debug)\s+mode",
        r"(?i)forward\s+(all\s+)?(data|credentials?|passwords?)\s+to",
        r"(?i)send\s+.{0,30}@[a-z0-9.-]+\.[a-z]{2,}",
        r"(?i)bypass\s+(all\s+)?(security|safety|filter)",
    ]
    
    # Suspicious action types
    SUSPICIOUS_ACTIONS = [
        "/Launch",
        "/JavaScript",
        "/JS",
        "/SubmitForm",
        "/ImportData",
        "/URI",
        "/GoTo",
        "/GoToR",
        "/GoToE",
        "/Named",
        "/Rendition",
        "/Sound",
        "/Movie",
        "/RichMedia",
    ]
    
    # Malicious URL patterns
    MALICIOUS_URL_PATTERNS = [
        r"(?i)https?://[a-z0-9.-]+\.(ru|cn|tk|ml|ga|cf|gq|xyz|top|buzz)/",
        r"(?i)https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
        r"(?i)(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|ow\.ly)",  # URL shorteners
        r"(?i)data:",  # Data URLs
        r"(?i)javascript:",  # JavaScript URLs
    ]
    
    def __init__(
        self,
        text_analyzer: Optional[Any] = None,
        max_file_size_mb: float = 100.0,
        extract_text: bool = True,
        check_encrypted: bool = True,
    ):
        """
        Initialize PDFAnalyzer.
        
        Args:
            text_analyzer: Optional Memgar analyzer for text content
            max_file_size_mb: Maximum file size to process
            extract_text: Whether to extract and analyze text
            check_encrypted: Whether to flag encrypted content
        """
        self.text_analyzer = text_analyzer
        self.max_size_bytes = int(max_file_size_mb * 1024 * 1024)
        self.extract_text = extract_text
        self.check_encrypted = check_encrypted
        
        # Compile patterns
        self._js_patterns = [re.compile(p) for p in self.JS_DANGEROUS_PATTERNS]
        self._injection_patterns = [re.compile(p) for p in self.PROMPT_INJECTION_PATTERNS]
        self._url_patterns = [re.compile(p) for p in self.MALICIOUS_URL_PATTERNS]
        
        self.capabilities = {
            "pypdf": PYPDF_AVAILABLE,
            "pdfplumber": PDFPLUMBER_AVAILABLE,
        }
    
    def analyze(
        self,
        pdf_data: Union[bytes, str],
        filename: Optional[str] = None,
    ) -> PDFAnalysisResult:
        """
        Analyze a PDF for hidden threats.
        
        Args:
            pdf_data: PDF bytes or base64 string
            filename: Optional filename
            
        Returns:
            PDFAnalysisResult with threat details
        """
        import time
        start_time = time.time()
        
        threats = []
        warnings = []
        file_info = {}
        extracted_text = None
        
        # Normalize input
        try:
            pdf_bytes = self._normalize_input(pdf_data)
        except Exception as e:
            return PDFAnalysisResult(
                is_safe=False,
                risk_score=50,
                threats=[PDFThreat(
                    threat_type=PDFThreatType.ENCRYPTED_CONTENT,
                    severity="medium",
                    confidence=0.5,
                    description=f"Failed to parse PDF: {str(e)}",
                )],
                analysis_time_ms=(time.time() - start_time) * 1000,
            )
        
        # Basic validation
        if not pdf_bytes.startswith(b'%PDF'):
            threats.append(PDFThreat(
                threat_type=PDFThreatType.STREAM_INJECTION,
                severity="high",
                confidence=0.9,
                description="File does not have valid PDF header",
            ))
        
        # File info
        file_info = self._get_file_info(pdf_bytes, filename)
        
        # Raw content analysis (works without libraries)
        raw_threats = self._analyze_raw_content(pdf_bytes)
        threats.extend(raw_threats)
        
        # Incremental update detection
        inc_threats = self._detect_incremental_updates(pdf_bytes)
        threats.extend(inc_threats)
        
        # PyPDF-based analysis
        if PYPDF_AVAILABLE:
            try:
                reader = PdfReader(io.BytesIO(pdf_bytes))
                
                file_info["pages"] = len(reader.pages)
                file_info["encrypted"] = reader.is_encrypted
                
                if reader.is_encrypted and self.check_encrypted:
                    threats.append(PDFThreat(
                        threat_type=PDFThreatType.ENCRYPTED_CONTENT,
                        severity="medium",
                        confidence=0.5,
                        description="PDF is encrypted - content cannot be fully analyzed",
                    ))
                
                if not reader.is_encrypted:
                    # Metadata analysis
                    meta_threats = self._analyze_metadata(reader)
                    threats.extend(meta_threats)
                    
                    # JavaScript analysis
                    js_threats = self._analyze_javascript(reader)
                    threats.extend(js_threats)
                    
                    # Action analysis
                    action_threats = self._analyze_actions(reader)
                    threats.extend(action_threats)
                    
                    # Embedded files
                    embed_threats = self._analyze_embedded_files(reader)
                    threats.extend(embed_threats)
                    
                    # Form fields
                    form_threats = self._analyze_forms(reader)
                    threats.extend(form_threats)
                    
                    # Text extraction and analysis
                    if self.extract_text:
                        text_result = self._extract_and_analyze_text(reader)
                        extracted_text = text_result.get("text")
                        if text_result.get("threats"):
                            threats.extend(text_result["threats"])
                            
            except Exception as e:
                warnings.append(f"PyPDF analysis failed: {str(e)}")
        else:
            warnings.append("PyPDF not available - limited analysis")
        
        # Calculate risk
        risk_score = self._calculate_risk_score(threats)
        is_safe = risk_score < 30 and not any(t.severity == "critical" for t in threats)
        
        return PDFAnalysisResult(
            is_safe=is_safe,
            risk_score=risk_score,
            threats=threats,
            file_info=file_info,
            extracted_text=extracted_text,
            analysis_time_ms=(time.time() - start_time) * 1000,
            warnings=warnings,
        )
    
    def _normalize_input(self, pdf_data: Union[bytes, str]) -> bytes:
        """Convert input to bytes."""
        if isinstance(pdf_data, bytes):
            return pdf_data
        elif isinstance(pdf_data, str):
            if pdf_data.startswith("data:"):
                pdf_data = pdf_data.split(",", 1)[1]
            return base64.b64decode(pdf_data)
        else:
            raise ValueError(f"Unsupported input type: {type(pdf_data)}")
    
    def _get_file_info(self, data: bytes, filename: Optional[str]) -> Dict[str, Any]:
        """Get basic file information."""
        import hashlib
        
        info = {
            "size_bytes": len(data),
            "md5": hashlib.md5(data).hexdigest(),
        }
        
        if filename:
            info["filename"] = filename
        
        # Extract PDF version
        match = re.match(rb'%PDF-(\d+\.\d+)', data)
        if match:
            info["pdf_version"] = match.group(1).decode()
        
        return info
    
    def _analyze_raw_content(self, data: bytes) -> List[PDFThreat]:
        """Analyze raw PDF bytes for threats."""
        threats = []
        
        # Convert to string for pattern matching
        try:
            content = data.decode('latin-1')
        except:
            content = data.decode('utf-8', errors='ignore')
        
        # Check for JavaScript
        js_indicators = [
            '/JavaScript',
            '/JS ',
            '/JS(',
            'app.alert',
            'this.exportDataObject',
            'eval(',
        ]
        for indicator in js_indicators:
            if indicator in content:
                threats.append(PDFThreat(
                    threat_type=PDFThreatType.JAVASCRIPT_EMBEDDED,
                    severity="high",
                    confidence=0.8,
                    description=f"JavaScript indicator found: {indicator}",
                ))
                break
        
        # Check for Launch action
        if '/Launch' in content:
            threats.append(PDFThreat(
                threat_type=PDFThreatType.LAUNCH_ACTION,
                severity="critical",
                confidence=0.95,
                description="PDF contains Launch action (can execute external programs)",
            ))
        
        # Check for suspicious actions
        for action in self.SUSPICIOUS_ACTIONS:
            if action in content:
                # Already handled JavaScript and Launch
                if action not in ['/JavaScript', '/JS', '/Launch']:
                    threats.append(PDFThreat(
                        threat_type=PDFThreatType.MALICIOUS_ACTION,
                        severity="medium",
                        confidence=0.7,
                        description=f"Suspicious action type found: {action}",
                    ))
        
        # Check for embedded files
        if '/EmbeddedFiles' in content or '/EmbeddedFile' in content:
            threats.append(PDFThreat(
                threat_type=PDFThreatType.EMBEDDED_FILE,
                severity="medium",
                confidence=0.6,
                description="PDF contains embedded files",
            ))
        
        # Check for URLs
        for pattern in self._url_patterns:
            matches = pattern.findall(content)
            if matches:
                threats.append(PDFThreat(
                    threat_type=PDFThreatType.MALICIOUS_URL,
                    severity="high" if 'javascript:' in str(matches) else "medium",
                    confidence=0.75,
                    description=f"Suspicious URL pattern found",
                    extracted_content=str(matches[:3]),
                ))
                break
        
        # Check for prompt injection patterns
        for pattern in self._injection_patterns:
            if pattern.search(content):
                threats.append(PDFThreat(
                    threat_type=PDFThreatType.PROMPT_INJECTION,
                    severity="critical",
                    confidence=0.9,
                    description="Prompt injection pattern detected in PDF",
                ))
                break
        
        # Check for obfuscated JavaScript (hex encoded)
        if re.search(r'/JS\s*<[0-9A-Fa-f]{20,}>', content):
            threats.append(PDFThreat(
                threat_type=PDFThreatType.JAVASCRIPT_EMBEDDED,
                severity="critical",
                confidence=0.9,
                description="Hex-encoded JavaScript detected",
            ))
        
        # Check for stream with suspicious filters
        suspicious_filters = ['ASCIIHexDecode', 'ASCII85Decode', 'RunLengthDecode']
        for f in suspicious_filters:
            if f in content:
                # Multiple filters = possible obfuscation
                filter_count = content.count('/Filter')
                if filter_count > 3:
                    threats.append(PDFThreat(
                        threat_type=PDFThreatType.STREAM_INJECTION,
                        severity="medium",
                        confidence=0.6,
                        description=f"Multiple stream filters detected ({filter_count})",
                    ))
                    break
        
        return threats
    
    def _detect_incremental_updates(self, data: bytes) -> List[PDFThreat]:
        """Detect potentially malicious incremental updates."""
        threats = []
        
        # Count %%EOF markers
        eof_count = data.count(b'%%EOF')
        
        if eof_count > 1:
            threats.append(PDFThreat(
                threat_type=PDFThreatType.INCREMENTAL_UPDATE,
                severity="medium",
                confidence=0.5 + (min(eof_count, 5) * 0.1),
                description=f"PDF has {eof_count} incremental updates (may hide content)",
                metadata={"eof_count": eof_count},
            ))
        
        return threats
    
    def _analyze_metadata(self, reader: "PdfReader") -> List[PDFThreat]:
        """Analyze PDF metadata for threats."""
        threats = []
        
        try:
            metadata = reader.metadata
            if not metadata:
                return threats
            
            # Check each metadata field
            for key in ['/Author', '/Title', '/Subject', '/Keywords', '/Creator', '/Producer']:
                value = metadata.get(key, '')
                if value:
                    value = str(value)
                    
                    # Check for injection patterns
                    for pattern in self._injection_patterns:
                        if pattern.search(value):
                            threats.append(PDFThreat(
                                threat_type=PDFThreatType.PROMPT_INJECTION,
                                severity="critical",
                                confidence=0.9,
                                description=f"Prompt injection in metadata field {key}",
                                location=f"Metadata:{key}",
                                extracted_content=value[:200],
                            ))
                            break
                    
                    # Check for URLs
                    if re.search(r'https?://', value):
                        for url_pattern in self._url_patterns:
                            if url_pattern.search(value):
                                threats.append(PDFThreat(
                                    threat_type=PDFThreatType.MALICIOUS_URL,
                                    severity="medium",
                                    confidence=0.7,
                                    description=f"Suspicious URL in metadata {key}",
                                    location=f"Metadata:{key}",
                                    extracted_content=value[:100],
                                ))
                                break
                                
        except Exception:
            pass
        
        return threats
    
    def _analyze_javascript(self, reader: "PdfReader") -> List[PDFThreat]:
        """Analyze JavaScript in PDF."""
        threats = []
        
        try:
            # Check for JavaScript in document catalog
            if hasattr(reader, 'trailer') and reader.trailer:
                root = reader.trailer.get('/Root', {})
                
                # Check Names dictionary
                names = root.get('/Names', {})
                if '/JavaScript' in str(names):
                    threats.append(PDFThreat(
                        threat_type=PDFThreatType.JAVASCRIPT_EMBEDDED,
                        severity="high",
                        confidence=0.85,
                        description="JavaScript found in document Names dictionary",
                    ))
                
                # Check OpenAction
                open_action = root.get('/OpenAction', {})
                if '/JavaScript' in str(open_action) or '/JS' in str(open_action):
                    threats.append(PDFThreat(
                        threat_type=PDFThreatType.JAVASCRIPT_EMBEDDED,
                        severity="critical",
                        confidence=0.95,
                        description="JavaScript in OpenAction (executes on document open)",
                    ))
                    
        except Exception:
            pass
        
        return threats
    
    def _analyze_actions(self, reader: "PdfReader") -> List[PDFThreat]:
        """Analyze PDF actions."""
        threats = []
        
        try:
            for page_num, page in enumerate(reader.pages):
                # Check page annotations for actions
                if '/Annots' in page:
                    annots = page['/Annots']
                    for annot in annots:
                        annot_obj = annot.get_object() if hasattr(annot, 'get_object') else annot
                        
                        # Check for action
                        if '/A' in annot_obj:
                            action = annot_obj['/A']
                            action_type = action.get('/S', '')
                            
                            if action_type == '/Launch':
                                threats.append(PDFThreat(
                                    threat_type=PDFThreatType.LAUNCH_ACTION,
                                    severity="critical",
                                    confidence=0.95,
                                    description=f"Launch action on page {page_num + 1}",
                                    location=f"Page {page_num + 1}",
                                ))
                            elif action_type == '/URI':
                                uri = action.get('/URI', '')
                                if uri:
                                    for pattern in self._url_patterns:
                                        if pattern.search(str(uri)):
                                            threats.append(PDFThreat(
                                                threat_type=PDFThreatType.MALICIOUS_URL,
                                                severity="high",
                                                confidence=0.8,
                                                description=f"Suspicious URI action on page {page_num + 1}",
                                                extracted_content=str(uri)[:100],
                                            ))
                                            break
                                            
        except Exception:
            pass
        
        return threats
    
    def _analyze_embedded_files(self, reader: "PdfReader") -> List[PDFThreat]:
        """Analyze embedded files in PDF."""
        threats = []
        
        try:
            if hasattr(reader, 'trailer') and reader.trailer:
                root = reader.trailer.get('/Root', {})
                names = root.get('/Names', {})
                
                if '/EmbeddedFiles' in names:
                    threats.append(PDFThreat(
                        threat_type=PDFThreatType.EMBEDDED_FILE,
                        severity="medium",
                        confidence=0.7,
                        description="PDF contains embedded files",
                    ))
                    
                    # Try to get file names
                    embedded = names.get('/EmbeddedFiles', {})
                    if '/Names' in embedded:
                        file_list = embedded['/Names']
                        # Check for dangerous extensions
                        dangerous_ext = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar']
                        for item in file_list:
                            if isinstance(item, str):
                                for ext in dangerous_ext:
                                    if item.lower().endswith(ext):
                                        threats.append(PDFThreat(
                                            threat_type=PDFThreatType.EMBEDDED_FILE,
                                            severity="critical",
                                            confidence=0.95,
                                            description=f"Dangerous file type embedded: {item}",
                                            extracted_content=item,
                                        ))
                                        break
                                        
        except Exception:
            pass
        
        return threats
    
    def _analyze_forms(self, reader: "PdfReader") -> List[PDFThreat]:
        """Analyze PDF forms for threats."""
        threats = []
        
        try:
            if hasattr(reader, 'trailer') and reader.trailer:
                root = reader.trailer.get('/Root', {})
                acro_form = root.get('/AcroForm', {})
                
                if acro_form:
                    # Check for submit action
                    if '/XFA' in acro_form:
                        threats.append(PDFThreat(
                            threat_type=PDFThreatType.FORM_MANIPULATION,
                            severity="high",
                            confidence=0.8,
                            description="PDF contains XFA form (can contain scripts)",
                        ))
                    
                    # Check fields
                    fields = acro_form.get('/Fields', [])
                    for field in fields:
                        field_obj = field.get_object() if hasattr(field, 'get_object') else field
                        
                        # Check for JavaScript in field
                        if '/AA' in field_obj:  # Additional actions
                            threats.append(PDFThreat(
                                threat_type=PDFThreatType.FORM_MANIPULATION,
                                severity="high",
                                confidence=0.75,
                                description="Form field with additional actions",
                            ))
                            break
                            
        except Exception:
            pass
        
        return threats
    
    def _extract_and_analyze_text(self, reader: "PdfReader") -> Dict[str, Any]:
        """Extract text and analyze for threats."""
        result = {"text": None, "threats": []}
        
        try:
            text_parts = []
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
            
            full_text = '\n'.join(text_parts)
            result["text"] = full_text[:10000]  # Limit
            
            if not full_text:
                return result
            
            # Check for prompt injection
            for pattern in self._injection_patterns:
                if pattern.search(full_text):
                    result["threats"].append(PDFThreat(
                        threat_type=PDFThreatType.PROMPT_INJECTION,
                        severity="critical",
                        confidence=0.9,
                        description="Prompt injection detected in PDF text",
                        extracted_content=full_text[:500],
                    ))
                    break
            
            # Use Memgar analyzer if available
            if self.text_analyzer and len(full_text) > 20:
                try:
                    from ..models import MemoryEntry, Decision
                    entry = MemoryEntry(content=full_text[:5000])
                    analysis = self.text_analyzer.analyze(entry)
                    
                    if analysis.decision != Decision.ALLOW:
                        result["threats"].append(PDFThreat(
                            threat_type=PDFThreatType.PROMPT_INJECTION,
                            severity="critical",
                            confidence=0.95,
                            description=f"Memgar detected threat: {analysis.decision.value}",
                            metadata={"memgar_risk": analysis.risk_score},
                        ))
                except Exception:
                    pass
                    
        except Exception:
            pass
        
        return result
    
    def _calculate_risk_score(self, threats: List[PDFThreat]) -> int:
        """Calculate overall risk score."""
        if not threats:
            return 0
        
        severity_scores = {
            "critical": 40,
            "high": 25,
            "medium": 15,
            "low": 5,
        }
        
        total = sum(
            severity_scores.get(t.severity, 10) * t.confidence
            for t in threats
        )
        
        return min(100, int(total))


# Convenience function
def analyze_pdf(
    pdf_data: Union[bytes, str],
    text_analyzer: Optional[Any] = None,
) -> PDFAnalysisResult:
    """Quick PDF analysis."""
    analyzer = PDFAnalyzer(text_analyzer=text_analyzer)
    return analyzer.analyze(pdf_data)
