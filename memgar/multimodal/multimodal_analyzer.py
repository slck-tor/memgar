"""
Memgar Multi-Modal Analyzer
===========================

Unified interface for analyzing multiple content types:
- Images (JPEG, PNG, GIF, WebP, BMP)
- PDFs
- Audio (WAV, MP3, OGG, FLAC)
- Documents (with text extraction)

Usage:
    from memgar.multimodal import MultiModalAnalyzer
    
    analyzer = MultiModalAnalyzer()
    
    # Auto-detect content type
    result = analyzer.analyze(file_bytes, filename="document.pdf")
    
    # Or specify type
    result = analyzer.analyze_image(image_bytes)
    result = analyzer.analyze_pdf(pdf_bytes)
    result = analyzer.analyze_audio(audio_bytes)
"""

import mimetypes
from typing import Optional, Dict, List, Any, Union
from dataclasses import dataclass, field
from enum import Enum

from .image_analyzer import ImageAnalyzer, ImageAnalysisResult
from .pdf_analyzer import PDFAnalyzer, PDFAnalysisResult
from .audio_analyzer import AudioAnalyzer, AudioAnalysisResult


class ContentType(Enum):
    """Supported content types."""
    IMAGE = "image"
    PDF = "pdf"
    AUDIO = "audio"
    DOCUMENT = "document"
    UNKNOWN = "unknown"


@dataclass
class MultiModalResult:
    """Combined result from multi-modal analysis."""
    content_type: ContentType
    is_safe: bool
    risk_score: int
    summary: str
    threats: List[Dict[str, Any]] = field(default_factory=list)
    extracted_text: Optional[str] = None
    file_info: Dict[str, Any] = field(default_factory=dict)
    analysis_time_ms: float = 0.0
    warnings: List[str] = field(default_factory=list)
    
    # Original result
    image_result: Optional[ImageAnalysisResult] = None
    pdf_result: Optional[PDFAnalysisResult] = None
    audio_result: Optional[AudioAnalysisResult] = None


class MultiModalAnalyzer:
    """
    Unified multi-modal content analyzer.
    
    Automatically detects content type and applies appropriate analysis.
    Can integrate with Memgar text analyzer for extracted content.
    
    Features:
    - Auto content type detection
    - Unified threat reporting
    - Combined risk scoring
    - Text extraction from all formats
    
    Usage:
        from memgar.multimodal import MultiModalAnalyzer
        from memgar.analyzer import Analyzer
        
        # With text analysis
        text_analyzer = Analyzer()
        mm_analyzer = MultiModalAnalyzer(text_analyzer=text_analyzer)
        
        # Analyze any content
        result = mm_analyzer.analyze(file_bytes)
        
        if not result.is_safe:
            print(f"Risk: {result.risk_score}")
            for threat in result.threats:
                print(f"  - {threat['type']}: {threat['description']}")
    """
    
    # Magic bytes for content detection
    MAGIC_SIGNATURES = {
        # Images
        b'\x89PNG\r\n\x1a\n': ContentType.IMAGE,
        b'\xff\xd8\xff': ContentType.IMAGE,
        b'GIF87a': ContentType.IMAGE,
        b'GIF89a': ContentType.IMAGE,
        b'RIFF': ContentType.AUDIO,  # Check for WEBP too
        b'BM': ContentType.IMAGE,
        
        # PDF
        b'%PDF': ContentType.PDF,
        
        # Audio
        b'ID3': ContentType.AUDIO,
        b'\xff\xfb': ContentType.AUDIO,
        b'\xff\xfa': ContentType.AUDIO,
        b'OggS': ContentType.AUDIO,
        b'fLaC': ContentType.AUDIO,
    }
    
    # Extension mappings
    EXTENSION_MAP = {
        # Images
        '.jpg': ContentType.IMAGE,
        '.jpeg': ContentType.IMAGE,
        '.png': ContentType.IMAGE,
        '.gif': ContentType.IMAGE,
        '.webp': ContentType.IMAGE,
        '.bmp': ContentType.IMAGE,
        '.ico': ContentType.IMAGE,
        '.svg': ContentType.IMAGE,
        
        # PDF
        '.pdf': ContentType.PDF,
        
        # Audio
        '.wav': ContentType.AUDIO,
        '.mp3': ContentType.AUDIO,
        '.ogg': ContentType.AUDIO,
        '.flac': ContentType.AUDIO,
        '.m4a': ContentType.AUDIO,
        '.aac': ContentType.AUDIO,
        
        # Documents
        '.doc': ContentType.DOCUMENT,
        '.docx': ContentType.DOCUMENT,
        '.txt': ContentType.DOCUMENT,
        '.rtf': ContentType.DOCUMENT,
    }
    
    def __init__(
        self,
        text_analyzer: Optional[Any] = None,
        enable_ocr: bool = True,
        enable_speech_recognition: bool = True,
        enable_steganography: bool = True,
    ):
        """
        Initialize MultiModalAnalyzer.
        
        Args:
            text_analyzer: Optional Memgar text analyzer
            enable_ocr: Enable OCR for images
            enable_speech_recognition: Enable speech-to-text for audio
            enable_steganography: Enable steganography detection
        """
        self.text_analyzer = text_analyzer
        
        # Initialize sub-analyzers
        self.image_analyzer = ImageAnalyzer(
            text_analyzer=text_analyzer,
            enable_ocr=enable_ocr,
            enable_stego_detection=enable_steganography,
        )
        
        self.pdf_analyzer = PDFAnalyzer(
            text_analyzer=text_analyzer,
        )
        
        self.audio_analyzer = AudioAnalyzer(
            text_analyzer=text_analyzer,
            enable_speech_recognition=enable_speech_recognition,
        )
    
    def analyze(
        self,
        data: Union[bytes, str],
        filename: Optional[str] = None,
        content_type: Optional[ContentType] = None,
    ) -> MultiModalResult:
        """
        Analyze any supported content type.
        
        Args:
            data: File bytes or base64 string
            filename: Optional filename for type detection
            content_type: Optional explicit content type
            
        Returns:
            MultiModalResult with threat details
        """
        import time
        start_time = time.time()
        
        # Normalize data
        if isinstance(data, str):
            import base64
            if data.startswith("data:"):
                # Data URL
                data = data.split(",", 1)[1]
            data = base64.b64decode(data)
        
        # Detect content type
        if content_type is None:
            content_type = self._detect_content_type(data, filename)
        
        # Route to appropriate analyzer
        result = None
        
        if content_type == ContentType.IMAGE:
            result = self._analyze_image(data, filename, start_time)
        elif content_type == ContentType.PDF:
            result = self._analyze_pdf(data, filename, start_time)
        elif content_type == ContentType.AUDIO:
            result = self._analyze_audio(data, filename, start_time)
        else:
            # Unknown type - try basic analysis
            result = self._analyze_unknown(data, filename, start_time)
        
        return result
    
    def analyze_image(
        self,
        data: Union[bytes, str],
        filename: Optional[str] = None,
    ) -> MultiModalResult:
        """Analyze image content."""
        return self.analyze(data, filename, ContentType.IMAGE)
    
    def analyze_pdf(
        self,
        data: Union[bytes, str],
        filename: Optional[str] = None,
    ) -> MultiModalResult:
        """Analyze PDF content."""
        return self.analyze(data, filename, ContentType.PDF)
    
    def analyze_audio(
        self,
        data: Union[bytes, str],
        filename: Optional[str] = None,
    ) -> MultiModalResult:
        """Analyze audio content."""
        return self.analyze(data, filename, ContentType.AUDIO)
    
    def _detect_content_type(
        self,
        data: bytes,
        filename: Optional[str],
    ) -> ContentType:
        """Detect content type from magic bytes or filename."""
        # Check magic bytes first
        for magic, ctype in self.MAGIC_SIGNATURES.items():
            if data.startswith(magic):
                # Special case: RIFF could be WAV or WEBP
                if magic == b'RIFF' and b'WEBP' in data[:20]:
                    return ContentType.IMAGE
                return ctype
        
        # Check filename extension
        if filename:
            ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            if ext in self.EXTENSION_MAP:
                return self.EXTENSION_MAP[ext]
        
        return ContentType.UNKNOWN
    
    def _analyze_image(
        self,
        data: bytes,
        filename: Optional[str],
        start_time: float,
    ) -> MultiModalResult:
        """Analyze image and convert to unified result."""
        import time
        
        result = self.image_analyzer.analyze(data, filename)
        
        threats = [
            {
                "type": t.threat_type.value,
                "severity": t.severity,
                "confidence": t.confidence,
                "description": t.description,
                "location": t.location,
                "extracted_content": t.extracted_content,
            }
            for t in result.threats
        ]
        
        threat_summary = ", ".join(t.threat_type.value for t in result.threats[:3])
        summary = f"Image analysis: {len(result.threats)} threats found" if result.threats else "Image analysis: No threats detected"
        if threat_summary:
            summary += f" ({threat_summary})"
        
        return MultiModalResult(
            content_type=ContentType.IMAGE,
            is_safe=result.is_safe,
            risk_score=result.risk_score,
            summary=summary,
            threats=threats,
            extracted_text=result.extracted_text,
            file_info=result.file_info,
            analysis_time_ms=(time.time() - start_time) * 1000,
            warnings=result.warnings,
            image_result=result,
        )
    
    def _analyze_pdf(
        self,
        data: bytes,
        filename: Optional[str],
        start_time: float,
    ) -> MultiModalResult:
        """Analyze PDF and convert to unified result."""
        import time
        
        result = self.pdf_analyzer.analyze(data, filename)
        
        threats = [
            {
                "type": t.threat_type.value,
                "severity": t.severity,
                "confidence": t.confidence,
                "description": t.description,
                "location": t.location,
                "extracted_content": t.extracted_content,
            }
            for t in result.threats
        ]
        
        threat_summary = ", ".join(t.threat_type.value for t in result.threats[:3])
        summary = f"PDF analysis: {len(result.threats)} threats found" if result.threats else "PDF analysis: No threats detected"
        if threat_summary:
            summary += f" ({threat_summary})"
        
        return MultiModalResult(
            content_type=ContentType.PDF,
            is_safe=result.is_safe,
            risk_score=result.risk_score,
            summary=summary,
            threats=threats,
            extracted_text=result.extracted_text,
            file_info=result.file_info,
            analysis_time_ms=(time.time() - start_time) * 1000,
            warnings=result.warnings,
            pdf_result=result,
        )
    
    def _analyze_audio(
        self,
        data: bytes,
        filename: Optional[str],
        start_time: float,
    ) -> MultiModalResult:
        """Analyze audio and convert to unified result."""
        import time
        
        result = self.audio_analyzer.analyze(data, filename)
        
        threats = [
            {
                "type": t.threat_type.value,
                "severity": t.severity,
                "confidence": t.confidence,
                "description": t.description,
                "location": t.location,
                "extracted_content": t.extracted_content,
            }
            for t in result.threats
        ]
        
        threat_summary = ", ".join(t.threat_type.value for t in result.threats[:3])
        summary = f"Audio analysis: {len(result.threats)} threats found" if result.threats else "Audio analysis: No threats detected"
        if threat_summary:
            summary += f" ({threat_summary})"
        
        return MultiModalResult(
            content_type=ContentType.AUDIO,
            is_safe=result.is_safe,
            risk_score=result.risk_score,
            summary=summary,
            threats=threats,
            extracted_text=result.transcription,
            file_info=result.file_info,
            analysis_time_ms=(time.time() - start_time) * 1000,
            warnings=result.warnings,
            audio_result=result,
        )
    
    def _analyze_unknown(
        self,
        data: bytes,
        filename: Optional[str],
        start_time: float,
    ) -> MultiModalResult:
        """Handle unknown content types."""
        import time
        
        # Try to extract text if possible
        extracted_text = None
        try:
            extracted_text = data.decode('utf-8', errors='ignore')[:5000]
        except:
            pass
        
        return MultiModalResult(
            content_type=ContentType.UNKNOWN,
            is_safe=True,  # Can't assess unknown content
            risk_score=0,
            summary="Unknown content type - limited analysis performed",
            extracted_text=extracted_text,
            file_info={
                "size_bytes": len(data),
                "filename": filename,
            },
            analysis_time_ms=(time.time() - start_time) * 1000,
            warnings=["Unknown content type - could not perform full analysis"],
        )
    
    def get_capabilities(self) -> Dict[str, Dict[str, bool]]:
        """Return capabilities of all sub-analyzers."""
        return {
            "image": self.image_analyzer.get_capabilities(),
            "pdf": self.pdf_analyzer.capabilities,
            "audio": self.audio_analyzer.capabilities,
        }


# Convenience functions
def analyze_content(
    data: Union[bytes, str],
    filename: Optional[str] = None,
    text_analyzer: Optional[Any] = None,
) -> MultiModalResult:
    """
    Quick analysis of any supported content.
    
    Args:
        data: File bytes or base64 string
        filename: Optional filename
        text_analyzer: Optional Memgar analyzer
        
    Returns:
        MultiModalResult
    """
    analyzer = MultiModalAnalyzer(text_analyzer=text_analyzer)
    return analyzer.analyze(data, filename)
