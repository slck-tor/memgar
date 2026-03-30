"""
Memgar Audio Analyzer
=====================

Detects hidden threats in audio files including:
- Ultrasonic hidden messages (>18kHz)
- Spectrogram hidden data
- Audio steganography (LSB in samples)
- Metadata injection
- Embedded text (speech-to-text + analysis)

Dependencies (optional):
- scipy: Signal processing
- numpy: Numerical analysis
- speech_recognition: Speech-to-text
- librosa: Audio analysis
"""

import io
import re
import struct
import base64
from typing import Optional, Dict, List, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Optional imports
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

try:
    from scipy import signal
    from scipy.io import wavfile
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

try:
    import speech_recognition as sr
    SR_AVAILABLE = True
except ImportError:
    SR_AVAILABLE = False


class AudioThreatType(Enum):
    """Types of audio-based threats."""
    ULTRASONIC_MESSAGE = "ultrasonic_message"
    SPECTROGRAM_HIDDEN = "spectrogram_hidden"
    STEGANOGRAPHY_LSB = "steganography_lsb"
    METADATA_INJECTION = "metadata_injection"
    SPEECH_INJECTION = "speech_injection"
    SUBLIMINAL_CONTENT = "subliminal_content"
    MALFORMED_AUDIO = "malformed_audio"


@dataclass
class AudioThreat:
    """Represents a detected audio threat."""
    threat_type: AudioThreatType
    severity: str
    confidence: float
    description: str
    location: Optional[str] = None
    extracted_content: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AudioAnalysisResult:
    """Result of audio analysis."""
    is_safe: bool
    risk_score: int
    threats: List[AudioThreat] = field(default_factory=list)
    file_info: Dict[str, Any] = field(default_factory=dict)
    transcription: Optional[str] = None
    analysis_time_ms: float = 0.0
    warnings: List[str] = field(default_factory=list)


class AudioAnalyzer:
    """
    Analyzes audio files for hidden threats.
    
    Features:
    - Ultrasonic frequency analysis (hidden commands)
    - LSB steganography detection
    - Metadata analysis
    - Speech-to-text with threat detection
    - Spectrogram anomaly detection
    
    Usage:
        analyzer = AudioAnalyzer()
        result = analyzer.analyze(audio_bytes)
    """
    
    # Malicious speech patterns
    SPEECH_THREAT_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?previous\s+instructions?",
        r"(?i)new\s+instruction\s*:",
        r"(?i)forward\s+(all\s+)?(data|credentials?|passwords?)",
        r"(?i)send\s+.{0,30}@[a-z0-9.-]+\.[a-z]{2,}",
        r"(?i)bypass\s+(all\s+)?(security|safety)",
        r"(?i)admin\s+mode\s+(enabled|activated)",
    ]
    
    # Ultrasonic frequency threshold
    ULTRASONIC_THRESHOLD_HZ = 18000
    
    def __init__(
        self,
        text_analyzer: Optional[Any] = None,
        enable_speech_recognition: bool = True,
        enable_ultrasonic_detection: bool = True,
        max_file_size_mb: float = 50.0,
    ):
        """
        Initialize AudioAnalyzer.
        
        Args:
            text_analyzer: Optional Memgar analyzer
            enable_speech_recognition: Enable speech-to-text
            enable_ultrasonic_detection: Enable ultrasonic analysis
            max_file_size_mb: Maximum file size
        """
        self.text_analyzer = text_analyzer
        self.enable_sr = enable_speech_recognition and SR_AVAILABLE
        self.enable_ultrasonic = enable_ultrasonic_detection and SCIPY_AVAILABLE
        self.max_size_bytes = int(max_file_size_mb * 1024 * 1024)
        
        self._patterns = [re.compile(p) for p in self.SPEECH_THREAT_PATTERNS]
        
        self.capabilities = {
            "numpy": NUMPY_AVAILABLE,
            "scipy": SCIPY_AVAILABLE,
            "speech_recognition": SR_AVAILABLE,
        }
    
    def analyze(
        self,
        audio_data: Union[bytes, str],
        filename: Optional[str] = None,
    ) -> AudioAnalysisResult:
        """
        Analyze audio for hidden threats.
        
        Args:
            audio_data: Audio bytes or base64 string
            filename: Optional filename
            
        Returns:
            AudioAnalysisResult
        """
        import time
        start_time = time.time()
        
        threats = []
        warnings = []
        file_info = {}
        transcription = None
        
        # Normalize input
        try:
            audio_bytes = self._normalize_input(audio_data)
        except Exception as e:
            return AudioAnalysisResult(
                is_safe=False,
                risk_score=30,
                threats=[AudioThreat(
                    threat_type=AudioThreatType.MALFORMED_AUDIO,
                    severity="medium",
                    confidence=0.5,
                    description=f"Failed to parse audio: {str(e)}",
                )],
                analysis_time_ms=(time.time() - start_time) * 1000,
            )
        
        # File info
        file_info = self._get_file_info(audio_bytes, filename)
        
        # Metadata analysis
        meta_threats = self._analyze_metadata(audio_bytes)
        threats.extend(meta_threats)
        
        # WAV-specific analysis
        if audio_bytes.startswith(b'RIFF') and b'WAVE' in audio_bytes[:20]:
            wav_result = self._analyze_wav(audio_bytes)
            threats.extend(wav_result.get("threats", []))
            file_info.update(wav_result.get("info", {}))
        
        # Scipy-based analysis
        if SCIPY_AVAILABLE and NUMPY_AVAILABLE:
            try:
                # Try to parse as WAV
                sample_rate, samples = self._load_audio(audio_bytes)
                
                if samples is not None:
                    file_info["sample_rate"] = sample_rate
                    file_info["duration_seconds"] = len(samples) / sample_rate
                    
                    # Ultrasonic detection
                    if self.enable_ultrasonic:
                        ultra_threats = self._detect_ultrasonic(samples, sample_rate)
                        threats.extend(ultra_threats)
                    
                    # LSB steganography
                    lsb_threats = self._detect_lsb_stego(samples)
                    threats.extend(lsb_threats)
                    
                    # Spectrogram analysis
                    spec_threats = self._analyze_spectrogram(samples, sample_rate)
                    threats.extend(spec_threats)
                    
            except Exception as e:
                warnings.append(f"Signal analysis failed: {str(e)}")
        else:
            warnings.append("Scipy not available - limited analysis")
        
        # Speech recognition
        if self.enable_sr:
            try:
                sr_result = self._transcribe_and_analyze(audio_bytes)
                transcription = sr_result.get("text")
                if sr_result.get("threats"):
                    threats.extend(sr_result["threats"])
            except Exception as e:
                warnings.append(f"Speech recognition failed: {str(e)}")
        
        # Calculate risk
        risk_score = self._calculate_risk_score(threats)
        is_safe = risk_score < 30 and not any(t.severity == "critical" for t in threats)
        
        return AudioAnalysisResult(
            is_safe=is_safe,
            risk_score=risk_score,
            threats=threats,
            file_info=file_info,
            transcription=transcription,
            analysis_time_ms=(time.time() - start_time) * 1000,
            warnings=warnings,
        )
    
    def _normalize_input(self, audio_data: Union[bytes, str]) -> bytes:
        """Convert input to bytes."""
        if isinstance(audio_data, bytes):
            return audio_data
        elif isinstance(audio_data, str):
            if audio_data.startswith("data:"):
                audio_data = audio_data.split(",", 1)[1]
            return base64.b64decode(audio_data)
        else:
            raise ValueError(f"Unsupported input type: {type(audio_data)}")
    
    def _get_file_info(self, data: bytes, filename: Optional[str]) -> Dict[str, Any]:
        """Get basic file information."""
        import hashlib
        
        info = {
            "size_bytes": len(data),
            "md5": hashlib.md5(data).hexdigest()[:16],
        }
        
        if filename:
            info["filename"] = filename
            
        # Detect format
        if data.startswith(b'RIFF'):
            info["format"] = "WAV"
        elif data.startswith(b'ID3') or data.startswith(b'\xff\xfb'):
            info["format"] = "MP3"
        elif data.startswith(b'OggS'):
            info["format"] = "OGG"
        elif data.startswith(b'fLaC'):
            info["format"] = "FLAC"
        
        return info
    
    def _analyze_metadata(self, data: bytes) -> List[AudioThreat]:
        """Analyze audio metadata for threats."""
        threats = []
        
        # ID3 tags (MP3)
        if data.startswith(b'ID3'):
            try:
                # Simple ID3v2 parsing
                # Check for suspicious content in tags
                content = data[:10000].decode('latin-1', errors='ignore')
                
                for pattern in self._patterns:
                    if pattern.search(content):
                        threats.append(AudioThreat(
                            threat_type=AudioThreatType.METADATA_INJECTION,
                            severity="critical",
                            confidence=0.85,
                            description="Malicious content in audio metadata",
                        ))
                        break
                        
                # Check for URLs in metadata
                if re.search(r'https?://[a-z0-9.-]+\.(ru|cn|tk)', content, re.I):
                    threats.append(AudioThreat(
                        threat_type=AudioThreatType.METADATA_INJECTION,
                        severity="medium",
                        confidence=0.7,
                        description="Suspicious URL in audio metadata",
                    ))
                    
            except Exception:
                pass
        
        return threats
    
    def _analyze_wav(self, data: bytes) -> Dict[str, Any]:
        """Analyze WAV file structure."""
        result = {"threats": [], "info": {}}
        
        try:
            # Parse RIFF header
            if len(data) < 44:
                return result
            
            riff, size, wave = struct.unpack('<4sI4s', data[:12])
            
            result["info"]["riff_size"] = size
            
            # Check for size mismatch (appended data)
            actual_size = len(data)
            expected_size = size + 8
            
            if actual_size > expected_size + 100:
                result["threats"].append(AudioThreat(
                    threat_type=AudioThreatType.STEGANOGRAPHY_LSB,
                    severity="high",
                    confidence=0.7,
                    description=f"Data appended after WAV: {actual_size - expected_size} bytes",
                    metadata={"extra_bytes": actual_size - expected_size},
                ))
            
            # Parse format chunk
            pos = 12
            while pos < len(data) - 8:
                chunk_id = data[pos:pos+4]
                chunk_size = struct.unpack('<I', data[pos+4:pos+8])[0]
                
                if chunk_id == b'fmt ':
                    if chunk_size >= 16:
                        fmt_data = data[pos+8:pos+8+16]
                        audio_format, channels, sample_rate, byte_rate, block_align, bits = \
                            struct.unpack('<HHIIHH', fmt_data)
                        
                        result["info"]["channels"] = channels
                        result["info"]["sample_rate"] = sample_rate
                        result["info"]["bits_per_sample"] = bits
                        
                pos += 8 + chunk_size
                if chunk_size % 2:  # Padding
                    pos += 1
                    
        except Exception:
            pass
        
        return result
    
    def _load_audio(self, data: bytes) -> Tuple[int, Optional["np.ndarray"]]:
        """Load audio data into numpy array."""
        if not SCIPY_AVAILABLE:
            return 0, None
        
        try:
            sample_rate, samples = wavfile.read(io.BytesIO(data))
            
            # Convert to mono if stereo
            if len(samples.shape) > 1:
                samples = samples.mean(axis=1)
            
            # Normalize
            samples = samples.astype(np.float32)
            if samples.max() > 1:
                samples = samples / 32768.0
            
            return sample_rate, samples
            
        except Exception:
            return 0, None
    
    def _detect_ultrasonic(
        self, 
        samples: "np.ndarray", 
        sample_rate: int
    ) -> List[AudioThreat]:
        """Detect ultrasonic hidden messages."""
        threats = []
        
        if sample_rate < 40000:  # Can't detect ultrasonic without high sample rate
            return threats
        
        try:
            # Apply high-pass filter at 18kHz
            nyquist = sample_rate / 2
            cutoff = self.ULTRASONIC_THRESHOLD_HZ / nyquist
            
            if cutoff < 1:
                b, a = signal.butter(5, cutoff, btype='high')
                ultrasonic = signal.filtfilt(b, a, samples)
                
                # Calculate energy in ultrasonic band
                ultrasonic_energy = np.mean(ultrasonic ** 2)
                total_energy = np.mean(samples ** 2)
                
                if total_energy > 0:
                    ratio = ultrasonic_energy / total_energy
                    
                    # Significant ultrasonic content is suspicious
                    if ratio > 0.01:  # More than 1% energy in ultrasonic
                        threats.append(AudioThreat(
                            threat_type=AudioThreatType.ULTRASONIC_MESSAGE,
                            severity="high",
                            confidence=min(0.5 + ratio * 10, 0.95),
                            description=f"Significant ultrasonic content detected ({ratio*100:.1f}% energy)",
                            metadata={"ultrasonic_ratio": float(ratio)},
                        ))
                    
                    # Check for patterns (encoded data)
                    if ratio > 0.001:
                        # Look for regular patterns
                        fft = np.fft.fft(ultrasonic[:sample_rate])  # 1 second
                        spectrum = np.abs(fft)
                        
                        # Find peaks in ultrasonic range
                        ultra_start = int(18000 * len(fft) / sample_rate)
                        ultra_end = int(22000 * len(fft) / sample_rate)
                        
                        if ultra_end > ultra_start:
                            ultra_spectrum = spectrum[ultra_start:ultra_end]
                            
                            # Check for narrow-band signals (potential data carrier)
                            peak_idx = np.argmax(ultra_spectrum)
                            peak_value = ultra_spectrum[peak_idx]
                            mean_value = np.mean(ultra_spectrum)
                            
                            if mean_value > 0 and peak_value / mean_value > 10:
                                threats.append(AudioThreat(
                                    threat_type=AudioThreatType.ULTRASONIC_MESSAGE,
                                    severity="critical",
                                    confidence=0.8,
                                    description="Narrowband ultrasonic signal detected (possible data carrier)",
                                    metadata={"peak_frequency_hz": 18000 + peak_idx * (4000 / len(ultra_spectrum))},
                                ))
                                
        except Exception:
            pass
        
        return threats
    
    def _detect_lsb_stego(self, samples: "np.ndarray") -> List[AudioThreat]:
        """Detect LSB steganography in audio samples."""
        threats = []
        
        try:
            # Convert to integer samples
            int_samples = (samples * 32767).astype(np.int16)
            
            # Extract LSBs
            lsbs = int_samples & 1
            
            # In natural audio, LSBs should be random
            # Check for patterns
            zeros = np.sum(lsbs == 0)
            ones = np.sum(lsbs == 1)
            total = len(lsbs)
            
            expected = total / 2
            chi_sq = ((zeros - expected) ** 2 + (ones - expected) ** 2) / expected
            
            # Very high chi-square suggests manipulation
            if chi_sq > 500:
                threats.append(AudioThreat(
                    threat_type=AudioThreatType.STEGANOGRAPHY_LSB,
                    severity="high",
                    confidence=min(0.5 + chi_sq / 2000, 0.9),
                    description=f"LSB distribution anomaly (χ²={chi_sq:.0f})",
                    metadata={"chi_square": float(chi_sq)},
                ))
            
            # Check for byte-aligned patterns (text encoding)
            sample_lsbs = lsbs[:10000]
            
            if len(sample_lsbs) >= 8:
                byte_samples = []
                for i in range(0, len(sample_lsbs) - 8, 8):
                    byte_val = sum(sample_lsbs[i + j] << j for j in range(8))
                    byte_samples.append(byte_val)
                
                # Check for ASCII content
                ascii_count = sum(1 for b in byte_samples if 32 <= b <= 126)
                ascii_ratio = ascii_count / len(byte_samples) if byte_samples else 0
                
                if ascii_ratio > 0.6:
                    hidden_text = ''.join(chr(b) for b in byte_samples if 32 <= b <= 126)
                    
                    threats.append(AudioThreat(
                        threat_type=AudioThreatType.STEGANOGRAPHY_LSB,
                        severity="critical",
                        confidence=0.85,
                        description="Hidden text detected in audio LSBs",
                        extracted_content=hidden_text[:100],
                    ))
                    
        except Exception:
            pass
        
        return threats
    
    def _analyze_spectrogram(
        self, 
        samples: "np.ndarray", 
        sample_rate: int
    ) -> List[AudioThreat]:
        """Analyze spectrogram for hidden visual data."""
        threats = []
        
        try:
            # Compute spectrogram
            f, t, Sxx = signal.spectrogram(samples, sample_rate, nperseg=1024)
            
            # Check for unusual patterns in high frequencies
            # (spectrogram steganography often uses high freq)
            high_freq_idx = f > 15000
            
            if np.any(high_freq_idx):
                high_freq_energy = Sxx[high_freq_idx, :].sum()
                total_energy = Sxx.sum()
                
                if total_energy > 0:
                    ratio = high_freq_energy / total_energy
                    
                    # Natural audio usually has little high-freq energy
                    if ratio > 0.1:
                        threats.append(AudioThreat(
                            threat_type=AudioThreatType.SPECTROGRAM_HIDDEN,
                            severity="medium",
                            confidence=0.6,
                            description=f"Unusual high-frequency content ({ratio*100:.1f}%)",
                            metadata={"high_freq_ratio": float(ratio)},
                        ))
            
            # Check for rectangular patterns (image data)
            # Would require more sophisticated analysis
            
        except Exception:
            pass
        
        return threats
    
    def _transcribe_and_analyze(self, audio_bytes: bytes) -> Dict[str, Any]:
        """Transcribe audio and analyze for threats."""
        result = {"text": None, "threats": []}
        
        if not SR_AVAILABLE:
            return result
        
        try:
            recognizer = sr.Recognizer()
            
            # Load audio
            audio = sr.AudioFile(io.BytesIO(audio_bytes))
            
            with audio as source:
                audio_data = recognizer.record(source, duration=60)  # Max 60 seconds
            
            # Transcribe
            try:
                text = recognizer.recognize_google(audio_data)
                result["text"] = text
                
                # Check for malicious patterns
                for pattern in self._patterns:
                    if pattern.search(text):
                        result["threats"].append(AudioThreat(
                            threat_type=AudioThreatType.SPEECH_INJECTION,
                            severity="critical",
                            confidence=0.9,
                            description="Malicious speech content detected",
                            extracted_content=text[:500],
                        ))
                        break
                
                # Use Memgar analyzer
                if self.text_analyzer and len(text) > 20:
                    try:
                        from ..models import MemoryEntry, Decision
                        entry = MemoryEntry(content=text)
                        analysis = self.text_analyzer.analyze(entry)
                        
                        if analysis.decision != Decision.ALLOW:
                            result["threats"].append(AudioThreat(
                                threat_type=AudioThreatType.SPEECH_INJECTION,
                                severity="critical",
                                confidence=0.95,
                                description=f"Memgar detected: {analysis.decision.value}",
                                metadata={"memgar_risk": analysis.risk_score},
                            ))
                    except Exception:
                        pass
                        
            except sr.UnknownValueError:
                pass  # No speech detected
            except sr.RequestError:
                pass  # Service unavailable
                
        except Exception:
            pass
        
        return result
    
    def _calculate_risk_score(self, threats: List[AudioThreat]) -> int:
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


def analyze_audio(
    audio_data: Union[bytes, str],
    text_analyzer: Optional[Any] = None,
) -> AudioAnalysisResult:
    """Quick audio analysis."""
    analyzer = AudioAnalyzer(text_analyzer=text_analyzer)
    return analyzer.analyze(audio_data)
