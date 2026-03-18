# Contributing to Memgar

Thank you for your interest in contributing to Memgar! This document provides guidelines and instructions for contributing.

## Ways to Contribute

### 1. Report Bugs
- Use GitHub Issues to report bugs
- Include Python version, OS, and steps to reproduce
- Provide error messages and stack traces

### 2. Suggest Features
- Open an issue with the "enhancement" label
- Describe the use case and expected behavior
- Explain why this would benefit other users

### 3. Add Threat Patterns
This is one of the most valuable contributions! To add a new threat pattern:

1. Edit `memgar/patterns.py`
2. Follow the existing pattern format:

```python
NEW_THREAT = Threat(
    id="CAT-XXX",  # Category prefix + number
    name="Human Readable Name",
    description="Detailed description of what this threat does",
    category=ThreatCategory.CATEGORY,
    severity=Severity.LEVEL,
    patterns=[
        r"(?i)regex\s+pattern\s+here",
    ],
    keywords=["keyword1", "keyword2"],
    examples=[
        "Example malicious content 1",
        "Example malicious content 2",
    ],
    mitre_attack="TXXXX",  # Optional MITRE ATT&CK ID
)
```

3. Add to the `PATTERNS` list at the bottom
4. Add tests in `tests/test_analyzer.py`
5. Submit a PR

### 4. Improve Documentation
- Fix typos or unclear explanations
- Add examples
- Translate to other languages

### 5. Write Code
- Fix bugs
- Add features
- Improve performance

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/memgar.git
cd memgar

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Format code
black memgar tests
ruff check memgar tests
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add/update tests as needed
5. Ensure all tests pass (`pytest tests/ -v`)
6. Format code (`black memgar tests`)
7. Commit with clear messages (`git commit -m 'Add: new threat pattern for XYZ'`)
8. Push to your fork (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## Commit Message Format

Use clear, descriptive commit messages:

- `Add: new feature or pattern`
- `Fix: bug description`
- `Update: existing feature`
- `Docs: documentation changes`
- `Test: test additions or fixes`
- `Refactor: code refactoring`

## Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for public functions
- Keep functions focused and small
- Add comments for complex logic

## Testing

- All new features need tests
- All bug fixes need regression tests
- Maintain or improve code coverage
- Tests should be fast and isolated

## Threat Pattern Guidelines

When adding threat patterns:

1. **Be specific**: Avoid patterns that match legitimate content
2. **Test thoroughly**: Check for false positives with common text
3. **Document well**: Explain what attack this prevents
4. **Provide examples**: Include real-world attack examples
5. **Set appropriate severity**: Follow existing severity guidelines

### Severity Guidelines

- **CRITICAL**: Immediate financial loss or credential theft
- **HIGH**: Data exfiltration or behavior modification
- **MEDIUM**: Detection evasion or manipulation
- **LOW**: Anomalous but not clearly malicious

## Questions?

- Open an issue for general questions
- Check existing issues and discussions
- Read the documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make AI agents more secure! 🛡️
