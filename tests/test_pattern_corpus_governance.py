from __future__ import annotations

from memgar.analyzer import Analyzer
from memgar.models import Severity, Threat, ThreatCategory
from memgar.pattern_corpus import (
    BASE_ATTACK_CASES,
    BASE_BENIGN_CASES,
    REQUIRED_ATTACK_VECTORS,
    PatternQualityGateProfile,
    analyze_pattern_library,
    build_quality_gate_cases,
    coverage_matrix,
    evaluate_corpus,
    generate_adversarial_variants,
    run_pattern_corpus_gate,
)
from memgar.patterns import PATTERNS


def test_pattern_library_report_tracks_real_corpus_size_and_hygiene():
    report = analyze_pattern_library(PATTERNS)

    assert report.total_patterns >= 700
    assert report.regex_count >= report.total_patterns
    assert report.invalid_regex_count == 0
    assert "critical" in report.by_severity
    assert "financial" in report.by_category
    assert "credential" in report.by_category
    assert "injection" in report.by_category


def test_pattern_library_report_flags_duplicate_ids_and_bad_regex():
    threats = [
        Threat(
            id="DUP-001",
            name="one",
            description="one",
            category=ThreatCategory.INJECTION,
            severity=Severity.HIGH,
            patterns=[r"valid.*pattern"],
        ),
        Threat(
            id="DUP-001",
            name="two",
            description="two",
            category=ThreatCategory.INJECTION,
            severity=Severity.HIGH,
            patterns=["("],
        ),
    ]

    report = analyze_pattern_library(threats)

    assert report.duplicate_ids == ["DUP-001"]
    assert report.invalid_regex_count == 1
    assert report.invalid_regex["DUP-001"] == ["("]


def test_quality_gate_cases_cover_required_attack_vectors_and_benign_controls():
    cases = build_quality_gate_cases(include_variants=False, include_benign=True)
    vectors = {case.vector for case in cases if case.is_attack}
    benign = [case for case in cases if not case.is_attack]

    assert set(REQUIRED_ATTACK_VECTORS).issubset(vectors)
    assert len(benign) == len(BASE_BENIGN_CASES)


def test_adversarial_variant_generation_is_traceable_and_unique():
    variants = generate_adversarial_variants(BASE_ATTACK_CASES[:2])
    ids = [case.case_id for case in variants]

    assert len(variants) == 6
    assert len(ids) == len(set(ids))
    assert all(case.source == "deterministic_variant" for case in variants)
    assert all("generated" in case.tags for case in variants)


def test_coverage_matrix_groups_vectors_sources_and_tags():
    cases = build_quality_gate_cases(include_variants=True, include_benign=True)
    matrix = coverage_matrix(cases)

    assert matrix["by_vector"]["memory_overwrite"] >= 1
    assert matrix["by_source"]["curated"] >= len(BASE_ATTACK_CASES)
    assert matrix["by_source"]["deterministic_variant"] >= 1
    assert matrix["by_tag"]["generated"] >= 1


def test_runtime_quality_gate_passes_curated_corpus_offline():
    analyzer = Analyzer(use_llm=False)
    profile = PatternQualityGateProfile(
        min_attack_recall=0.75,
        max_false_positive_rate=0.05,
        min_vector_coverage=14,
        include_variants=False,
    )

    result = run_pattern_corpus_gate(analyzer=analyzer, profile=profile)

    assert result.passed, result.to_json()
    assert result.evaluation.attack_recall >= profile.min_attack_recall
    assert result.evaluation.false_positive_rate <= profile.max_false_positive_rate


def test_evaluate_corpus_reports_misses_with_case_metadata():
    class AllowAllAnalyzer:
        def analyze(self, entry):
            from memgar.models import AnalysisResult, Decision

            return AnalysisResult(decision=Decision.ALLOW, risk_score=0)

    report = evaluate_corpus(AllowAllAnalyzer(), list(BASE_ATTACK_CASES[:2]) + list(BASE_BENIGN_CASES[:1]))

    assert report.attack_total == 2
    assert report.attack_detected == 0
    assert len(report.missed_cases) == 2
    assert report.false_positive_rate == 0.0
    assert report.missed_cases[0]["case_id"] == BASE_ATTACK_CASES[0].case_id
