"""
Memgar Multi-Modal Detection Module
====================================

Detects hidden threats in images, PDFs, audio, and other non-text content.

Attack Vectors Covered:
- Image steganography (LSB, DCT)
- PDF embedded payloads (JavaScript, forms, attachments)
- Audio hidden messages (spectrogram, ultrasonic)
- QR code malicious payloads
- EXIF/metadata injection
- OCR-based text extraction attacks

Usage:
    from memgar.multimodal import MultiModalAnalyzer
    
    analyzer = MultiModalAnalyzer()
    result = analyzer.analyze_image(image_bytes)
    result = analyzer.analyze_pdf(pdf_bytes)
    result = analyzer.analyze_audio(audio_bytes)
"""

from .image_analyzer import ImageAnalyzer
from .pdf_analyzer import PDFAnalyzer
from .audio_analyzer import AudioAnalyzer
from .multimodal_analyzer import MultiModalAnalyzer

__all__ = [
    "ImageAnalyzer",
    "PDFAnalyzer", 
    "AudioAnalyzer",
    "MultiModalAnalyzer",
]
