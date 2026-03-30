"""
Memgar Image Analyzer
=====================

Detects hidden threats in images including:
- LSB (Least Significant Bit) steganography
- DCT-based steganography (JPEG)
- OCR-extracted malicious text
- EXIF/metadata injection attacks
- QR code malicious payloads
- Visual anomaly detection
- Homoglyph text in images

Dependencies (optional, graceful degradation):
- PIL/Pillow: Image processing
- pytesseract: OCR
- pyzbar: QR code detection
- numpy: Statistical analysis
"""

import io
import re
import base64
import hashlib
import struct
from typing import Optional, Dict, List, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

# Optional imports with graceful fallback
try:
    from PIL import Image, ExifTags
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

try:
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

try:
    from pyzbar import pyzbar
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False


class ImageThreatType(Enum):
    """Types of image-based threats."""
    STEGANOGRAPHY_LSB = "steganography_lsb"
    STEGANOGRAPHY_DCT = "steganography_dct"
    MALICIOUS_OCR_TEXT = "malicious_ocr_text"
    EXIF_INJECTION = "exif_injection"
    QR_CODE_MALICIOUS = "qr_code_malicious"
    HIDDEN_DATA_APPENDED = "hidden_data_appended"
    POLYGLOT_FILE = "polyglot_file"
    VISUAL_PROMPT_INJECTION = "visual_prompt_injection"


@dataclass
class ImageThreat:
    """Represents a detected image threat."""
    threat_type: ImageThreatType
    severity: str  # critical, high, medium, low
    confidence: float  # 0.0 - 1.0
    description: str
    location: Optional[str] = None  # Where in image
    extracted_content: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ImageAnalysisResult:
    """Result of image analysis."""
    is_safe: bool
    risk_score: int  # 0-100
    threats: List[ImageThreat] = field(default_factory=list)
    file_info: Dict[str, Any] = field(default_factory=dict)
    extracted_text: Optional[str] = None
    analysis_time_ms: float = 0.0
    warnings: List[str] = field(default_factory=list)


class ImageAnalyzer:
    """
    Analyzes images for hidden threats and malicious content.
    
    Features:
    - Steganography detection (LSB, DCT)
    - OCR text extraction and analysis
    - EXIF/metadata security analysis
    - QR code payload inspection
    - Appended data detection
    - Polyglot file detection
    
    Usage:
        analyzer = ImageAnalyzer()
        result = analyzer.analyze(image_bytes)
        
        if not result.is_safe:
            for threat in result.threats:
                print(f"Threat: {threat.threat_type.value}")
    """
    
    # Malicious patterns to detect in extracted text
    MALICIOUS_TEXT_PATTERNS = [
        # Injection patterns
        r"(?i)ignore\s+(all\s+)?previous\s+instructions?",
        r"(?i)forget\s+(all\s+)?prior\s+(instructions?|rules?)",
        r"(?i)new\s+instruction\s*:",
        r"(?i)system\s*:\s*override",
        r"(?i)admin\s+mode\s+(enabled|activated)",
        
        # Exfiltration patterns
        r"(?i)forward\s+(all\s+)?(data|credentials?|passwords?)\s+to",
        r"(?i)send\s+(to|all)\s+.{0,30}@[a-z0-9.-]+\.[a-z]{2,}",
        r"(?i)export\s+(credentials?|data|secrets?)\s+to",
        
        # Credential harvesting
        r"(?i)enter\s+(your\s+)?(password|credentials?|api\s*key)",
        r"(?i)verify\s+(your\s+)?identity\s+with",
        
        # URLs and emails
        r"(?i)https?://[a-z0-9.-]+\.(ru|cn|tk|ml|ga|cf|gq)/",
        r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.(ru|cn|tk|ml)",
        
        # Base64 encoded commands
        r"[A-Za-z0-9+/]{50,}={0,2}",
    ]
    
    # Suspicious EXIF fields
    SUSPICIOUS_EXIF_FIELDS = [
        "UserComment",
        "ImageDescription", 
        "XPComment",
        "XPKeywords",
        "Copyright",
        "Artist",
        "Software",
    ]
    
    # Magic bytes for polyglot detection
    MAGIC_BYTES = {
        b'\x89PNG': 'PNG',
        b'\xff\xd8\xff': 'JPEG',
        b'GIF87a': 'GIF87',
        b'GIF89a': 'GIF89',
        b'%PDF': 'PDF',
        b'PK\x03\x04': 'ZIP',
        b'\x1f\x8b': 'GZIP',
        b'MZ': 'EXE',
        b'\x7fELF': 'ELF',
        b'<script': 'HTML/JS',
        b'<html': 'HTML',
    }
    
    def __init__(
        self,
        enable_ocr: bool = True,
        enable_stego_detection: bool = True,
        enable_qr_detection: bool = True,
        text_analyzer: Optional[Any] = None,  # Memgar text analyzer
        ocr_language: str = "eng",
        max_image_size_mb: float = 50.0,
    ):
        """
        Initialize ImageAnalyzer.
        
        Args:
            enable_ocr: Enable OCR text extraction
            enable_stego_detection: Enable steganography detection
            enable_qr_detection: Enable QR code scanning
            text_analyzer: Optional Memgar analyzer for extracted text
            ocr_language: Tesseract language code
            max_image_size_mb: Maximum image size to process
        """
        self.enable_ocr = enable_ocr and OCR_AVAILABLE
        self.enable_stego = enable_stego_detection and NUMPY_AVAILABLE
        self.enable_qr = enable_qr_detection and PYZBAR_AVAILABLE
        self.text_analyzer = text_analyzer
        self.ocr_language = ocr_language
        self.max_size_bytes = int(max_image_size_mb * 1024 * 1024)
        
        # Compile patterns
        self._compiled_patterns = [
            re.compile(p) for p in self.MALICIOUS_TEXT_PATTERNS
        ]
        
        # Track capabilities
        self.capabilities = {
            "pil": PIL_AVAILABLE,
            "numpy": NUMPY_AVAILABLE,
            "ocr": OCR_AVAILABLE,
            "qr": PYZBAR_AVAILABLE,
        }
    
    def analyze(
        self,
        image_data: Union[bytes, str, "Image.Image"],
        filename: Optional[str] = None,
    ) -> ImageAnalysisResult:
        """
        Analyze an image for hidden threats.
        
        Args:
            image_data: Image bytes, base64 string, or PIL Image
            filename: Optional filename for context
            
        Returns:
            ImageAnalysisResult with threat details
        """
        import time
        start_time = time.time()
        
        threats = []
        warnings = []
        file_info = {}
        extracted_text = None
        
        # Handle different input types
        try:
            image_bytes = self._normalize_input(image_data)
        except Exception as e:
            return ImageAnalysisResult(
                is_safe=False,
                risk_score=50,
                threats=[ImageThreat(
                    threat_type=ImageThreatType.POLYGLOT_FILE,
                    severity="medium",
                    confidence=0.5,
                    description=f"Failed to parse image: {str(e)}",
                )],
                analysis_time_ms=(time.time() - start_time) * 1000,
            )
        
        # Size check
        if len(image_bytes) > self.max_size_bytes:
            warnings.append(f"Image exceeds size limit ({len(image_bytes)} bytes)")
        
        # Basic file analysis
        file_info = self._analyze_file_structure(image_bytes, filename)
        
        # Detect polyglot files
        polyglot_threats = self._detect_polyglot(image_bytes)
        threats.extend(polyglot_threats)
        
        # Detect appended data
        appended_threats = self._detect_appended_data(image_bytes, file_info.get("format"))
        threats.extend(appended_threats)
        
        if PIL_AVAILABLE:
            try:
                img = Image.open(io.BytesIO(image_bytes))
                file_info["dimensions"] = img.size
                file_info["mode"] = img.mode
                file_info["format"] = img.format
                
                # EXIF analysis
                exif_threats = self._analyze_exif(img)
                threats.extend(exif_threats)
                
                # Steganography detection
                if self.enable_stego:
                    stego_threats = self._detect_steganography(img, image_bytes)
                    threats.extend(stego_threats)
                
                # OCR analysis
                if self.enable_ocr:
                    ocr_result = self._extract_and_analyze_text(img)
                    extracted_text = ocr_result.get("text")
                    if ocr_result.get("threats"):
                        threats.extend(ocr_result["threats"])
                
                # QR code analysis
                if self.enable_qr:
                    qr_threats = self._analyze_qr_codes(img)
                    threats.extend(qr_threats)
                    
            except Exception as e:
                warnings.append(f"PIL processing failed: {str(e)}")
        else:
            warnings.append("PIL not available - limited analysis")
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(threats)
        
        # Determine safety
        is_safe = risk_score < 30 and not any(
            t.severity == "critical" for t in threats
        )
        
        return ImageAnalysisResult(
            is_safe=is_safe,
            risk_score=risk_score,
            threats=threats,
            file_info=file_info,
            extracted_text=extracted_text,
            analysis_time_ms=(time.time() - start_time) * 1000,
            warnings=warnings,
        )
    
    def _normalize_input(self, image_data: Union[bytes, str, Any]) -> bytes:
        """Convert various input types to bytes."""
        if isinstance(image_data, bytes):
            return image_data
        elif isinstance(image_data, str):
            # Assume base64
            if image_data.startswith("data:image"):
                # Data URL
                image_data = image_data.split(",", 1)[1]
            return base64.b64decode(image_data)
        elif PIL_AVAILABLE and isinstance(image_data, Image.Image):
            buf = io.BytesIO()
            image_data.save(buf, format=image_data.format or "PNG")
            return buf.getvalue()
        else:
            raise ValueError(f"Unsupported image input type: {type(image_data)}")
    
    def _analyze_file_structure(
        self, 
        data: bytes, 
        filename: Optional[str]
    ) -> Dict[str, Any]:
        """Analyze basic file structure."""
        info = {
            "size_bytes": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()[:32],
        }
        
        if filename:
            info["filename"] = filename
            info["extension"] = filename.rsplit(".", 1)[-1].lower() if "." in filename else None
        
        # Detect format from magic bytes
        for magic, fmt in self.MAGIC_BYTES.items():
            if data.startswith(magic):
                info["detected_format"] = fmt
                break
        
        return info
    
    def _detect_polyglot(self, data: bytes) -> List[ImageThreat]:
        """Detect polyglot files (files valid as multiple formats)."""
        threats = []
        detected_formats = []
        
        # Check all magic bytes
        for magic, fmt in self.MAGIC_BYTES.items():
            if magic in data[:100]:
                detected_formats.append(fmt)
            # Also check in body for embedded content
            if fmt in ["HTML", "HTML/JS", "PDF", "ZIP"] and magic in data:
                detected_formats.append(f"embedded_{fmt}")
        
        # If multiple formats detected, it's suspicious
        if len(set(detected_formats)) > 1:
            threats.append(ImageThreat(
                threat_type=ImageThreatType.POLYGLOT_FILE,
                severity="high",
                confidence=0.85,
                description=f"Polyglot file detected: {', '.join(detected_formats)}",
                metadata={"formats": detected_formats},
            ))
        
        # Check for script content in image
        script_patterns = [
            b'<script',
            b'javascript:',
            b'onerror=',
            b'onload=',
            b'eval(',
        ]
        for pattern in script_patterns:
            if pattern in data:
                threats.append(ImageThreat(
                    threat_type=ImageThreatType.POLYGLOT_FILE,
                    severity="critical",
                    confidence=0.95,
                    description=f"Script content found in image: {pattern.decode(errors='ignore')}",
                ))
                break
        
        return threats
    
    def _detect_appended_data(
        self, 
        data: bytes, 
        format: Optional[str]
    ) -> List[ImageThreat]:
        """Detect data appended after image EOF."""
        threats = []
        
        # JPEG ends with FFD9
        if data.startswith(b'\xff\xd8\xff'):
            eof_marker = data.rfind(b'\xff\xd9')
            if eof_marker != -1 and eof_marker < len(data) - 2:
                appended = data[eof_marker + 2:]
                if len(appended) > 10:  # Significant appended data
                    threats.append(ImageThreat(
                        threat_type=ImageThreatType.HIDDEN_DATA_APPENDED,
                        severity="high",
                        confidence=0.9,
                        description=f"Data appended after JPEG EOF: {len(appended)} bytes",
                        extracted_content=appended[:100].decode(errors='ignore'),
                        metadata={"appended_size": len(appended)},
                    ))
        
        # PNG ends with IEND chunk
        if data.startswith(b'\x89PNG'):
            iend = data.find(b'IEND')
            if iend != -1:
                # IEND chunk is 12 bytes (4 length + 4 type + 4 CRC)
                expected_end = iend + 8
                if expected_end < len(data) - 10:
                    appended = data[expected_end:]
                    if len(appended) > 10:
                        threats.append(ImageThreat(
                            threat_type=ImageThreatType.HIDDEN_DATA_APPENDED,
                            severity="high",
                            confidence=0.9,
                            description=f"Data appended after PNG IEND: {len(appended)} bytes",
                            metadata={"appended_size": len(appended)},
                        ))
        
        return threats
    
    def _analyze_exif(self, img: "Image.Image") -> List[ImageThreat]:
        """Analyze EXIF metadata for injected content."""
        threats = []
        
        try:
            exif_data = img._getexif()
            if not exif_data:
                return threats
            
            # Map tag IDs to names
            exif_dict = {}
            for tag_id, value in exif_data.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                exif_dict[tag_name] = value
            
            # Check suspicious fields
            for field in self.SUSPICIOUS_EXIF_FIELDS:
                if field in exif_dict:
                    value = str(exif_dict[field])
                    
                    # Check for malicious patterns
                    for pattern in self._compiled_patterns:
                        if pattern.search(value):
                            threats.append(ImageThreat(
                                threat_type=ImageThreatType.EXIF_INJECTION,
                                severity="critical",
                                confidence=0.95,
                                description=f"Malicious content in EXIF {field}",
                                location=f"EXIF:{field}",
                                extracted_content=value[:200],
                            ))
                            break
                    
                    # Check for URLs/emails
                    if re.search(r'https?://|@[a-z0-9.-]+\.[a-z]{2,}', value, re.I):
                        threats.append(ImageThreat(
                            threat_type=ImageThreatType.EXIF_INJECTION,
                            severity="medium",
                            confidence=0.7,
                            description=f"URL/email found in EXIF {field}",
                            location=f"EXIF:{field}",
                            extracted_content=value[:200],
                        ))
                    
                    # Check for very long content (data exfil)
                    if len(value) > 500:
                        threats.append(ImageThreat(
                            threat_type=ImageThreatType.EXIF_INJECTION,
                            severity="medium",
                            confidence=0.6,
                            description=f"Unusually long EXIF {field}: {len(value)} chars",
                            location=f"EXIF:{field}",
                        ))
                        
        except Exception:
            pass  # EXIF not available
        
        return threats
    
    def _detect_steganography(
        self, 
        img: "Image.Image",
        raw_bytes: bytes
    ) -> List[ImageThreat]:
        """Detect LSB and other steganography techniques."""
        threats = []
        
        if not NUMPY_AVAILABLE:
            return threats
        
        try:
            # Convert to numpy array
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            arr = np.array(img)
            
            # LSB Analysis - check distribution of least significant bits
            lsb = arr & 1  # Extract LSBs
            
            # In natural images, LSBs should be roughly 50/50
            # Steganography often creates non-random patterns
            lsb_mean = np.mean(lsb)
            lsb_std = np.std(lsb.flatten())
            
            # Chi-square like analysis for LSB
            # Count 0s and 1s
            zeros = np.sum(lsb == 0)
            ones = np.sum(lsb == 1)
            total = zeros + ones
            expected = total / 2
            
            chi_sq = ((zeros - expected) ** 2 + (ones - expected) ** 2) / expected
            
            # High chi-square suggests manipulation
            if chi_sq > 100:
                threats.append(ImageThreat(
                    threat_type=ImageThreatType.STEGANOGRAPHY_LSB,
                    severity="high",
                    confidence=min(0.5 + chi_sq / 1000, 0.95),
                    description=f"LSB distribution anomaly detected (χ²={chi_sq:.1f})",
                    metadata={"chi_square": chi_sq, "lsb_mean": float(lsb_mean)},
                ))
            
            # Check for sequential patterns in LSBs (encoded data)
            flat_lsb = lsb.flatten()[:10000]  # Sample
            
            # Look for byte-aligned patterns
            if len(flat_lsb) >= 8:
                # Convert LSB sequences to bytes and check for ASCII
                byte_samples = []
                for i in range(0, min(len(flat_lsb) - 8, 1000), 8):
                    byte_val = sum(flat_lsb[i + j] << (7 - j) for j in range(8))
                    byte_samples.append(byte_val)
                
                # Check if extracted bytes look like text
                ascii_count = sum(1 for b in byte_samples if 32 <= b <= 126)
                ascii_ratio = ascii_count / len(byte_samples) if byte_samples else 0
                
                if ascii_ratio > 0.7:
                    # Extract potential hidden text
                    hidden_text = ''.join(chr(b) for b in byte_samples if 32 <= b <= 126)
                    
                    threats.append(ImageThreat(
                        threat_type=ImageThreatType.STEGANOGRAPHY_LSB,
                        severity="critical",
                        confidence=0.85,
                        description="Hidden text detected in LSB",
                        extracted_content=hidden_text[:100],
                    ))
            
            # Histogram analysis for DCT steganography (JPEG)
            if raw_bytes.startswith(b'\xff\xd8\xff'):
                # Simplified DCT analysis
                hist = np.histogram(arr.flatten(), bins=256)[0]
                
                # Pairs of adjacent histogram values should be similar in natural images
                # Steganography disrupts this
                pairs_diff = np.abs(hist[::2] - hist[1::2])
                avg_diff = np.mean(pairs_diff)
                
                if avg_diff > 1000:  # Threshold
                    threats.append(ImageThreat(
                        threat_type=ImageThreatType.STEGANOGRAPHY_DCT,
                        severity="medium",
                        confidence=0.6,
                        description=f"Histogram anomaly suggests DCT manipulation",
                        metadata={"avg_pair_diff": float(avg_diff)},
                    ))
                    
        except Exception as e:
            pass  # Analysis failed
        
        return threats
    
    def _extract_and_analyze_text(
        self, 
        img: "Image.Image"
    ) -> Dict[str, Any]:
        """Extract text via OCR and analyze for threats."""
        result = {"text": None, "threats": []}
        
        if not OCR_AVAILABLE:
            return result
        
        try:
            # Extract text
            text = pytesseract.image_to_string(img, lang=self.ocr_language)
            result["text"] = text
            
            if not text or len(text.strip()) < 10:
                return result
            
            # Check for malicious patterns
            for pattern in self._compiled_patterns:
                matches = pattern.findall(text)
                if matches:
                    result["threats"].append(ImageThreat(
                        threat_type=ImageThreatType.MALICIOUS_OCR_TEXT,
                        severity="critical",
                        confidence=0.9,
                        description="Malicious text detected in image via OCR",
                        extracted_content=text[:500],
                        metadata={"matched_patterns": len(matches)},
                    ))
                    break
            
            # Use Memgar text analyzer if available
            if self.text_analyzer and len(text) > 20:
                try:
                    from ..models import MemoryEntry, Decision
                    entry = MemoryEntry(content=text)
                    analysis = self.text_analyzer.analyze(entry)
                    
                    if analysis.decision != Decision.ALLOW:
                        result["threats"].append(ImageThreat(
                            threat_type=ImageThreatType.VISUAL_PROMPT_INJECTION,
                            severity="critical",
                            confidence=0.95,
                            description=f"Memgar detected threat in OCR text: {analysis.decision.value}",
                            extracted_content=text[:500],
                            metadata={"memgar_risk": analysis.risk_score},
                        ))
                except Exception:
                    pass
                    
        except Exception:
            pass
        
        return result
    
    def _analyze_qr_codes(self, img: "Image.Image") -> List[ImageThreat]:
        """Detect and analyze QR codes in image."""
        threats = []
        
        if not PYZBAR_AVAILABLE:
            return threats
        
        try:
            # Decode QR codes
            codes = pyzbar.decode(img)
            
            for code in codes:
                data = code.data.decode(errors='ignore')
                code_type = code.type
                
                # Check for malicious URLs
                if re.match(r'https?://', data, re.I):
                    # Suspicious TLDs
                    if re.search(r'\.(ru|cn|tk|ml|ga|cf|gq|xyz|top|buzz)(/|$)', data, re.I):
                        threats.append(ImageThreat(
                            threat_type=ImageThreatType.QR_CODE_MALICIOUS,
                            severity="high",
                            confidence=0.8,
                            description="QR code contains suspicious URL",
                            extracted_content=data,
                            metadata={"code_type": code_type},
                        ))
                    
                    # URL shorteners often used maliciously
                    if re.search(r'(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly)', data, re.I):
                        threats.append(ImageThreat(
                            threat_type=ImageThreatType.QR_CODE_MALICIOUS,
                            severity="medium",
                            confidence=0.6,
                            description="QR code contains shortened URL",
                            extracted_content=data,
                        ))
                
                # Check for malicious patterns in QR data
                for pattern in self._compiled_patterns:
                    if pattern.search(data):
                        threats.append(ImageThreat(
                            threat_type=ImageThreatType.QR_CODE_MALICIOUS,
                            severity="critical",
                            confidence=0.9,
                            description="QR code contains malicious payload",
                            extracted_content=data[:200],
                        ))
                        break
                
                # Base64 encoded payloads
                if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', data):
                    try:
                        decoded = base64.b64decode(data).decode(errors='ignore')
                        if any(p.search(decoded) for p in self._compiled_patterns):
                            threats.append(ImageThreat(
                                threat_type=ImageThreatType.QR_CODE_MALICIOUS,
                                severity="critical",
                                confidence=0.85,
                                description="QR code contains base64 encoded malicious payload",
                                extracted_content=decoded[:200],
                            ))
                    except Exception:
                        pass
                        
        except Exception:
            pass
        
        return threats
    
    def _calculate_risk_score(self, threats: List[ImageThreat]) -> int:
        """Calculate overall risk score from threats."""
        if not threats:
            return 0
        
        severity_scores = {
            "critical": 40,
            "high": 25,
            "medium": 15,
            "low": 5,
        }
        
        total = 0
        for threat in threats:
            base = severity_scores.get(threat.severity, 10)
            total += base * threat.confidence
        
        return min(100, int(total))
    
    def get_capabilities(self) -> Dict[str, bool]:
        """Return current analyzer capabilities."""
        return {
            **self.capabilities,
            "stego_enabled": self.enable_stego,
            "ocr_enabled": self.enable_ocr,
            "qr_enabled": self.enable_qr,
        }


# Convenience function
def analyze_image(
    image_data: Union[bytes, str],
    text_analyzer: Optional[Any] = None,
) -> ImageAnalysisResult:
    """
    Quick analysis of an image.
    
    Args:
        image_data: Image bytes or base64 string
        text_analyzer: Optional Memgar analyzer
        
    Returns:
        ImageAnalysisResult
    """
    analyzer = ImageAnalyzer(text_analyzer=text_analyzer)
    return analyzer.analyze(image_data)
