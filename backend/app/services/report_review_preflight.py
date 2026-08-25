"""Deterministic preflight checks for the report Review Gate.

The evaluator is intentionally pure: it performs no network calls, reads no
database state, and does not consult an AI model.  Identical inputs produce
identical JSON-serialisable output.  Machine verdicts are supporting facts for
an analyst; they are never analyst decisions and are never promotion approval.

AI suggestions can be attached with :func:`merge_ai_advisory`.  That function
only adds bounded advisory details and cannot alter a machine or analyst
verdict, evidence reference, or evaluator identity.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit


PREFLIGHT_POLICY_VERSION = "report-review-preflight-v1"
PREFLIGHT_EVALUATOR = f"deterministic:{PREFLIGHT_POLICY_VERSION}"
GATE_KEYS = (
    "source_provenance",
    "publication_date",
    "procedure_relevance",
    "procedure_level_claim",
    "actor_identification",
)

_ATTACK_ID_RE = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|AML\.T\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_DATE_PREFIX_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:[T\s].*)?$")
_SPACE_RE = re.compile(r"\s+")
_ACTOR_NEGATION_RE = re.compile(
    r"\b(?:not\s+(?:attributed|linked)|no\s+(?:evidence|attribution)|unlikely\s+to\s+be|"
    r"cannot\s+(?:attribute|confirm)|unconfirmed|misattributed)\b",
    re.IGNORECASE,
)
_STRONG_PROCEDURE_RE = re.compile(
    r"\b(?:access(?:ed|ing)?|added|altered|bypass(?:ed|ing)?|captur(?:ed|ing)|"
    r"collect(?:ed|ing)?|connect(?:ed|ing)?|copied|creat(?:ed|ing)|decrypt(?:ed|ing)?|"
    r"delet(?:ed|ing)|deploy(?:ed|ing)?|discover(?:ed|ing)?|download(?:ed|ing)?|dump(?:ed|ing)?|"
    r"encrypt(?:ed|ing)?|enumerat(?:ed|ing)?|execut(?:ed|ing)|exfiltrat(?:ed|ing)?|extract(?:ed|ing)?|"
    r"harvest(?:ed|ing)?|inject(?:ed|ing)?|install(?:ed|ing)?|launch(?:ed|ing)?|load(?:ed|ing)?|"
    r"modif(?:ied|ying)|mov(?:ed|ing)|open(?:ed|ing)?|persist(?:ed|ing)?|quer(?:ied|ying)|"
    r"read|reconnoiter(?:ed|ing)?|redirect(?:ed|ing)?|registr(?:ed|ying)|remov(?:ed|ing)|"
    r"runn?(?:ing)?|sav(?:ed|ing)|schedul(?:ed|ing)|sent|spawn(?:ed|ing)?|stole|"
    r"upload(?:ed|ing)?|wrote|written)\b",
    re.IGNORECASE,
)
_GENERIC_TOOL_MENTION_RE = re.compile(
    r"\b(?:actor|adversary|attacker|campaign|group|threat\s+actor|they)\s+"
    r"(?:is\s+known\s+to\s+)?(?:uses?|used|leverages?|utili[sz]es?|employs?)\s+"
    r"(?:the\s+)?[\w.+#/-]+\s*[.!]?$",
    re.IGNORECASE,
)
_NON_ACTOR_NAMES = {
    "",
    "actor",
    "adversary",
    "attacker",
    "threat actor",
    "unknown",
    "unknown actor",
    "unknown adversary",
}
_EXPLICIT_ACTOR_BASES = {"explicit", "source_reported"}
_OVERLAP_ACTOR_BASES = {
    "attack_overlap",
    "inferred_from_similarity",
    "malware_overlap",
    "shared_tooling",
    "similarity",
    "tooling_overlap_only",
    "ttp_overlap",
}
_PUBLICATION_KEYS = {
    "date_published",
    "datepublished",
    "publication_date",
    "publicationdate",
    "published_at",
    "published_date",
}
_STRONG_DATE_SOURCE_TERMS = (
    "article:published_time",
    "datepublished",
    "date_published",
    "publication_date",
    "published_at",
    "publish-date",
    "date.issued",
)


def evaluate_report_preflight(
    source_text: str,
    source_metadata: dict,
    claims: list[dict],
    context: dict | None = None,
) -> dict[str, dict[str, Any]]:
    """Evaluate all five report gates using local, deterministic evidence.

    Args:
        source_text: The exact stored report text under review.
        source_metadata: Stored acquisition and publication metadata.  URL
            acquisitions should include ``source_url``, ``retrieved_url``,
            ``http_status``, ``content_sha256``, and ``retrieved_at``.
        claims: Candidate claims.  Procedure records may use ATT&CK extraction
            fields (``attack_id``, ``evidence``, evidence offsets) or structured
            claim fields.  Actor claims must state their attribution ``basis``.
        context: Optional deterministic analysis context.  Supported keys are
            ``analyzed_char_count`` or ``analyzed_ranges``, ``techniques``,
            ``procedure_claims``, ``actor_candidates``, ``apt_matches``, and
            ``publication_date_candidates``.  ``ai_advisory`` is deliberately
            ignored; attach it later with :func:`merge_ai_advisory`.

    Returns:
        A dictionary keyed by the five stable gate keys.  Every value contains
        ``machine_verdict``, ``details``, ``evidence_refs``, and ``evaluator``.
    """

    text = source_text if isinstance(source_text, str) else str(source_text or "")
    metadata = dict(source_metadata) if isinstance(source_metadata, Mapping) else {}
    ctx = dict(context) if isinstance(context, Mapping) else {}
    all_claims = _collect_claims(claims, ctx)
    coverage = _coverage_details(text, metadata, ctx)

    return {
        "source_provenance": _evaluate_source_provenance(text, metadata, ctx),
        "publication_date": _evaluate_publication_date(text, metadata, ctx),
        "procedure_relevance": _evaluate_procedure_relevance(text, all_claims, coverage),
        "procedure_level_claim": _evaluate_procedure_level_claim(text, all_claims, coverage),
        "actor_identification": _evaluate_actor_identification(text, all_claims, coverage, ctx),
    }


def merge_ai_advisory(
    preflight: Mapping[str, Mapping[str, Any]],
    ai_advisory: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Attach bounded AI suggestions without changing deterministic decisions.

    Only the ``details.ai_advisory`` namespace is written.  Existing machine
    fields, analyst fields a caller may have attached, and evidence references
    are preserved byte-for-byte by value.  Provider-supplied authority or
    verdict fields are ignored and ``authoritative`` is always forced false.
    """

    merged: dict[str, dict[str, Any]] = {
        key: copy.deepcopy(dict(value)) for key, value in preflight.items() if key in GATE_KEYS and isinstance(value, Mapping)
    }
    if not isinstance(ai_advisory, Mapping):
        return merged

    advisory_by_gate = _bounded_ai_advisory(ai_advisory)
    for gate_key, suggestion in advisory_by_gate.items():
        gate = merged.get(gate_key)
        if gate is None:
            continue
        details = copy.deepcopy(gate.get("details")) if isinstance(gate.get("details"), Mapping) else {}
        details["ai_advisory"] = suggestion
        gate["details"] = details
    return merged


def _evaluate_source_provenance(text: str, metadata: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    facts: list[dict[str, Any]] = []
    refs: list[dict[str, Any]] = []
    if text.strip():
        facts.append(_fact("source_text_present", "pass", "Stored source text is present."))
    else:
        facts.append(_fact("source_text_missing", "fail", "Stored source text is empty."))
        return _gate(
            "fail",
            "Source provenance cannot be assessed without stored source text.",
            facts,
            refs,
            {"source_char_count": len(text)},
        )

    source_url = _first_metadata_value(metadata, context, ("source_url", "url"))
    source_kind = _clean_string(_first_metadata_value(metadata, context, ("source_kind", "input_type", "kind")), 80).lower()
    source_checksum = _clean_string(_first_metadata_value(metadata, context, ("source_text_sha256", "source_checksum")), 64).lower()
    acquisition_text_checksum = _clean_string(
        _first_metadata_value(metadata, context, ("acquisition_text_sha256",)),
        64,
    ).lower()
    acquisition_content_checksum = _clean_string(
        _first_metadata_value(metadata, context, ("acquisition_content_sha256",)),
        64,
    ).lower()
    acquisition_time = _first_metadata_value(metadata, context, ("acquired_at",))
    acquisition_superseded = bool(
        _first_metadata_value(metadata, context, ("acquisition_superseded",))
    )
    calculated_checksum = hashlib.sha256(text.encode("utf-8")).hexdigest()

    if source_checksum:
        checksum_ref = _metadata_ref("source_text_sha256", source_checksum)
        refs.append(checksum_ref)
        if _SHA256_RE.fullmatch(source_checksum) and source_checksum == calculated_checksum:
            facts.append(_fact("source_checksum_match", "pass", "Stored text matches its SHA-256 fingerprint.", [checksum_ref]))
        elif _SHA256_RE.fullmatch(source_checksum):
            facts.append(_fact("source_checksum_mismatch", "fail", "Stored text does not match its SHA-256 fingerprint.", [checksum_ref]))
        else:
            facts.append(_fact("source_checksum_invalid", "fail", "Stored source checksum is not a SHA-256 value.", [checksum_ref]))

    if source_url:
        safe_url = _safe_url(str(source_url))
        url_ref = _metadata_ref("source_url", safe_url)
        refs.append(url_ref)
        url_error = _public_http_url_error(str(source_url))
        if url_error:
            facts.append(_fact("source_url_invalid", "fail", url_error, [url_ref]))
            return _gate(
                "fail",
                "The stored source URL is invalid or unsafe.",
                facts,
                refs,
                {"source_char_count": len(text), "source_kind": source_kind or "url"},
            )
        facts.append(_fact("source_url_valid", "pass", "Stored source URL has a public HTTP(S) origin.", [url_ref]))

        retrieved_url = _first_metadata_value(metadata, context, ("retrieved_url", "final_url"))
        http_status = _as_int(_first_metadata_value(metadata, context, ("http_status", "status_code")))
        content_checksum = _clean_string(
            _first_metadata_value(metadata, context, ("content_sha256", "retrieved_content_sha256")), 64
        ).lower()
        extracted_text_checksum = _clean_string(
            _first_metadata_value(metadata, context, ("extracted_text_sha256",)), 64
        ).lower()
        retrieved_at = _first_metadata_value(metadata, context, ("retrieved_at", "fetched_at"))
        receipt_superseded = bool(
            _first_metadata_value(metadata, context, ("retrieval_superseded", "superseded"))
        )
        receipt_refs = [url_ref]
        receipt_complete = True

        if receipt_superseded:
            receipt_complete = False
            facts.append(
                _fact(
                    "retrieval_receipt_superseded",
                    "fail",
                    "The stored receipt was superseded by a source text or URL edit.",
                    [url_ref],
                )
            )

        if retrieved_url:
            retrieved_ref = _metadata_ref("retrieved_url", _safe_url(str(retrieved_url)))
            receipt_refs.append(retrieved_ref)
            refs.append(retrieved_ref)
            if _public_http_url_error(str(retrieved_url)):
                receipt_complete = False
                facts.append(_fact("retrieved_url_invalid", "fail", "Retrieval receipt contains an invalid final URL.", [retrieved_ref]))
            elif _normalized_url_identity(str(retrieved_url)) != _normalized_url_identity(
                str(source_url)
            ):
                receipt_complete = False
                facts.append(
                    _fact(
                        "retrieval_url_source_mismatch",
                        "fail",
                        "The current source URL is not the final URL bound to the retrieval receipt.",
                        [url_ref, retrieved_ref],
                    )
                )
        else:
            receipt_complete = False
            facts.append(_fact("retrieved_url_missing", "warning", "Retrieval receipt has no final URL."))

        if http_status is not None:
            status_ref = _metadata_ref("http_status", http_status)
            receipt_refs.append(status_ref)
            refs.append(status_ref)
            if 200 <= http_status < 300:
                facts.append(_fact("retrieval_http_success", "pass", f"Stored retrieval returned HTTP {http_status}.", [status_ref]))
            elif http_status >= 400:
                receipt_complete = False
                facts.append(_fact("retrieval_http_failure", "fail", f"Stored retrieval returned HTTP {http_status}.", [status_ref]))
            else:
                receipt_complete = False
                facts.append(
                    _fact(
                        "retrieval_http_not_final",
                        "warning",
                        f"Stored retrieval status {http_status} is not a final success response.",
                        [status_ref],
                    )
                )
        else:
            receipt_complete = False
            facts.append(_fact("retrieval_http_status_missing", "warning", "Retrieval receipt has no HTTP status."))

        if content_checksum and _SHA256_RE.fullmatch(content_checksum):
            checksum_ref = _metadata_ref("content_sha256", content_checksum)
            receipt_refs.append(checksum_ref)
            refs.append(checksum_ref)
            facts.append(
                _fact("retrieved_content_fingerprinted", "pass", "Retrieved bytes have a stored SHA-256 fingerprint.", [checksum_ref])
            )
        else:
            receipt_complete = False
            code = "retrieved_content_checksum_invalid" if content_checksum else "retrieved_content_checksum_missing"
            facts.append(_fact(code, "warning", "Retrieval receipt has no valid content SHA-256 fingerprint."))

        if extracted_text_checksum and _SHA256_RE.fullmatch(extracted_text_checksum):
            text_checksum_ref = _metadata_ref(
                "extracted_text_sha256",
                extracted_text_checksum,
            )
            receipt_refs.append(text_checksum_ref)
            refs.append(text_checksum_ref)
            if extracted_text_checksum == calculated_checksum:
                facts.append(
                    _fact(
                        "retrieved_text_checksum_match",
                        "pass",
                        "The current stored text matches the normalized text bound to the receipt.",
                        [text_checksum_ref],
                    )
                )
            else:
                receipt_complete = False
                facts.append(
                    _fact(
                        "retrieved_text_checksum_mismatch",
                        "fail",
                        "The current stored text does not match the normalized text bound to the receipt.",
                        [text_checksum_ref],
                    )
                )
        else:
            receipt_complete = False
            facts.append(
                _fact(
                    "retrieved_text_checksum_missing_or_invalid",
                    "warning",
                    "Retrieval receipt does not bind the normalized stored text.",
                )
            )

        retrieved_date = _parse_date(retrieved_at)
        if retrieved_date is not None:
            retrieved_at_ref = _metadata_ref("retrieved_at", _clean_string(retrieved_at, 80))
            receipt_refs.append(retrieved_at_ref)
            refs.append(retrieved_at_ref)
            facts.append(_fact("retrieval_time_recorded", "pass", "Retrieval receipt includes a valid timestamp.", [retrieved_at_ref]))
        else:
            receipt_complete = False
            facts.append(_fact("retrieval_time_missing_or_invalid", "warning", "Retrieval receipt has no valid timestamp."))

        if any(fact["outcome"] == "fail" for fact in facts):
            verdict = "fail"
            summary = "Stored acquisition facts contradict valid source provenance."
        elif receipt_complete:
            verdict = "pass"
            summary = "A valid source URL and complete point-in-time retrieval receipt are stored."
        else:
            verdict = "warning"
            summary = "The source URL is valid, but its stored retrieval receipt is incomplete."
        return _gate(
            verdict,
            summary,
            facts,
            refs,
            {"source_char_count": len(text), "source_kind": source_kind or "url"},
        )

    if source_kind in {"url", "url-report", "remote", "web"}:
        facts.append(_fact("source_url_missing", "fail", "URL-origin source has no stored source URL."))
        verdict = "fail"
        summary = "URL-origin provenance is incomplete."
    elif source_kind in {"file", "upload"}:
        filename = _first_metadata_value(metadata, context, ("filename", "source_name", "name"))
        receipt_complete = True
        if filename:
            name_ref = _metadata_ref("filename", _clean_string(filename, 500))
            refs.append(name_ref)
            facts.append(_fact("uploaded_file_identified", "pass", "Uploaded source filename is recorded.", [name_ref]))
        else:
            receipt_complete = False
            facts.append(_fact("uploaded_file_name_missing", "warning", "Uploaded source filename is not recorded."))

        if acquisition_superseded:
            receipt_complete = False
            facts.append(
                _fact(
                    "file_acquisition_superseded",
                    "fail",
                    "The uploaded-file acquisition receipt was superseded by a source edit.",
                )
            )

        if acquisition_text_checksum and _SHA256_RE.fullmatch(acquisition_text_checksum):
            text_ref = _metadata_ref("acquisition_text_sha256", acquisition_text_checksum)
            refs.append(text_ref)
            if acquisition_text_checksum == calculated_checksum:
                facts.append(
                    _fact(
                        "uploaded_text_checksum_match",
                        "pass",
                        "Stored text matches the text extracted at file acquisition.",
                        [text_ref],
                    )
                )
            else:
                receipt_complete = False
                facts.append(
                    _fact(
                        "uploaded_text_checksum_mismatch",
                        "fail",
                        "Stored text no longer matches the text extracted at file acquisition.",
                        [text_ref],
                    )
                )
        else:
            receipt_complete = False
            facts.append(
                _fact(
                    "uploaded_text_checksum_missing_or_invalid",
                    "warning",
                    "Uploaded-file receipt does not bind the extracted source text.",
                )
            )

        if acquisition_content_checksum and _SHA256_RE.fullmatch(acquisition_content_checksum):
            content_ref = _metadata_ref(
                "acquisition_content_sha256",
                acquisition_content_checksum,
            )
            refs.append(content_ref)
            facts.append(
                _fact(
                    "uploaded_content_fingerprinted",
                    "pass",
                    "Original uploaded bytes have a stored SHA-256 fingerprint.",
                    [content_ref],
                )
            )
        else:
            receipt_complete = False
            facts.append(
                _fact(
                    "uploaded_content_checksum_missing_or_invalid",
                    "warning",
                    "Uploaded-file receipt has no valid original-byte fingerprint.",
                )
            )

        if _parse_date(acquisition_time) is not None:
            acquired_ref = _metadata_ref("acquired_at", _clean_string(acquisition_time, 80))
            refs.append(acquired_ref)
            facts.append(_fact("file_acquisition_time_recorded", "pass", "File acquisition time is recorded.", [acquired_ref]))
        else:
            receipt_complete = False
            facts.append(_fact("file_acquisition_time_missing", "warning", "File acquisition time is not recorded."))

        if any(fact["outcome"] == "fail" for fact in facts):
            verdict = "fail"
            summary = "Uploaded-file acquisition facts contradict the current stored source."
        elif receipt_complete:
            verdict = "pass"
            summary = "Uploaded-file provenance is bound to a complete point-in-time acquisition receipt."
        else:
            verdict = "warning"
            summary = "Uploaded-file provenance is incomplete."
    elif source_kind in {"text", "paste", "manual"}:
        if acquisition_superseded:
            facts.append(
                _fact(
                    "manual_text_acquisition_superseded",
                    "fail",
                    "The original pasted-text receipt was superseded by a source edit.",
                )
            )
            verdict = "fail"
            summary = "Current pasted text is not bound to the original acquisition receipt."
        elif acquisition_text_checksum and _SHA256_RE.fullmatch(acquisition_text_checksum):
            acquisition_ref = _metadata_ref(
                "acquisition_text_sha256",
                acquisition_text_checksum,
            )
            refs.append(acquisition_ref)
            if acquisition_text_checksum != calculated_checksum:
                facts.append(
                    _fact(
                        "manual_text_checksum_mismatch",
                        "fail",
                        "Stored text no longer matches the original pasted-text fingerprint.",
                        [acquisition_ref],
                    )
                )
                verdict = "fail"
                summary = "Current pasted text is not bound to the original acquisition receipt."
            else:
                facts.append(
                    _fact(
                        "manual_text_checksum_match",
                        "pass",
                        "Stored text matches the original pasted-text fingerprint.",
                        [acquisition_ref],
                    )
                )
                facts.append(_fact("manual_text_origin", "warning", "Pasted text has no independently retrievable source origin."))
                verdict = "warning"
                summary = "Manual text is unchanged, but its external provenance requires analyst confirmation."
        else:
            facts.append(_fact("manual_text_origin", "warning", "Pasted text has no independently retrievable source origin."))
            facts.append(
                _fact(
                    "manual_text_acquisition_missing",
                    "warning",
                    "No original pasted-text fingerprint is stored.",
                )
            )
            verdict = "warning"
            summary = "Manual text is stored, but its acquisition receipt is incomplete."
    else:
        facts.append(_fact("source_origin_unspecified", "warning", "Source origin type is not recorded."))
        verdict = "warning"
        summary = "Stored content is present, but source origin is unspecified."

    if any(fact["outcome"] == "fail" for fact in facts):
        verdict = "fail"
    return _gate(verdict, summary, facts, refs, {"source_char_count": len(text), "source_kind": source_kind or "unknown"})


def _evaluate_publication_date(text: str, metadata: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    facts: list[dict[str, Any]] = []
    refs: list[dict[str, Any]] = []
    candidates = _publication_candidates(text, metadata, context)
    valid: list[tuple[date, str, dict[str, Any], bool]] = []
    invalid_count = 0

    for candidate in candidates:
        parsed = _parse_date(candidate["value"])
        ref = candidate["ref"]
        refs.append(ref)
        if parsed is None:
            invalid_count += 1
            facts.append(_fact("publication_date_invalid", "warning", "Publication-date candidate is not a valid calendar date.", [ref]))
            continue
        source_label = candidate["source"].lower()
        strong = any(term in source_label for term in _STRONG_DATE_SOURCE_TERMS)
        valid.append((parsed, source_label, ref, strong))

    if not valid:
        facts.append(_fact("publication_date_missing", "fail", "No valid publication-date candidate is stored."))
        return _gate(
            "fail",
            "Publication date is missing or invalid.",
            facts,
            refs,
            {"candidate_count": len(candidates), "valid_candidate_count": 0},
        )

    unique_dates = sorted({item[0] for item in valid})
    for parsed, source_label, ref, _ in valid:
        facts.append(
            _fact(
                "publication_date_valid",
                "pass",
                f"Valid publication date {parsed.isoformat()} from {source_label or 'stored metadata'}.",
                [ref],
            )
        )

    retrieved_at = _first_metadata_value(metadata, context, ("retrieved_at", "fetched_at"))
    retrieved_date = _parse_date(retrieved_at)
    future_dates = [item for item in unique_dates if retrieved_date is not None and item > retrieved_date]
    if future_dates:
        facts.append(
            _fact(
                "publication_after_retrieval",
                "fail",
                "A publication date is later than the stored retrieval date.",
                [_metadata_ref("retrieved_at", _clean_string(retrieved_at, 80))],
            )
        )

    if len(unique_dates) > 1:
        facts.append(
            _fact(
                "publication_date_conflict",
                "warning",
                f"Stored metadata contains {len(unique_dates)} distinct publication dates.",
                [item[2] for item in valid],
            )
        )

    strong_count = sum(1 for item in valid if item[3])
    if strong_count == 0:
        facts.append(_fact("publication_date_source_weak", "warning", "No candidate comes from an explicit publication-date field."))

    if future_dates:
        verdict = "fail"
        summary = "Publication-date metadata contradicts the acquisition timeline."
    elif len(unique_dates) > 1 or invalid_count or strong_count == 0:
        verdict = "warning"
        summary = "Publication-date candidates require analyst resolution."
    else:
        verdict = "pass"
        summary = f"Publication date {unique_dates[0].isoformat()} is valid and internally consistent."
    return _gate(
        verdict,
        summary,
        facts,
        refs,
        {
            "candidate_count": len(candidates),
            "valid_candidate_count": len(valid),
            "distinct_valid_dates": [item.isoformat() for item in unique_dates],
        },
    )


def _evaluate_procedure_relevance(text: str, claims: list[dict[str, Any]], coverage: dict[str, Any]) -> dict[str, Any]:
    facts: list[dict[str, Any]] = []
    refs: list[dict[str, Any]] = []
    candidates = [claim for claim in claims if _claim_kind(claim) == "procedure" and not _is_ai_advisory_claim(claim)]
    bound: list[tuple[dict[str, Any], dict[str, Any]]] = []
    invalid_attack_ids = 0
    unbound = 0

    for index, claim in enumerate(candidates):
        attack_id = _clean_string(claim.get("attack_id"), 30).upper()
        if attack_id and not _ATTACK_ID_RE.fullmatch(attack_id):
            invalid_attack_ids += 1
            continue
        evidence_ref, _ = _bind_claim_evidence(text, claim, index)
        if evidence_ref is None:
            unbound += 1
            continue
        bound.append((claim, evidence_ref))
        refs.append(evidence_ref)

    if not candidates:
        facts.append(_fact("procedure_candidates_missing", "fail", "No procedure or ATT&CK candidates were supplied."))
        verdict = "fail"
        summary = "The analysis does not contain procedure-relevant candidates."
    elif not bound:
        facts.append(_fact("procedure_evidence_unbound", "fail", "No procedure candidate has exact evidence in the stored source."))
        verdict = "fail"
        summary = "Procedure relevance is not supported by source-bound evidence."
    else:
        facts.append(
            _fact(
                "procedure_evidence_bound",
                "pass",
                f"{len(bound)} procedure candidate(s) have exact source evidence.",
                [item[1] for item in bound],
            )
        )
        if coverage["coverage_complete"]:
            verdict = "pass"
            summary = "Source-bound procedure candidates are present across a completely analysed source."
        else:
            verdict = "warning"
            summary = "Procedure evidence is present, but analysis coverage is incomplete or unknown."

    if unbound:
        facts.append(
            _fact(
                "procedure_candidates_unbound",
                "warning",
                f"{unbound} procedure candidate(s) have missing, ambiguous, or mismatched evidence.",
            )
        )
        if verdict == "pass":
            verdict = "warning"
    if invalid_attack_ids:
        facts.append(
            _fact(
                "procedure_attack_ids_invalid", "warning", f"{invalid_attack_ids} candidate(s) contain an invalid ATT&CK/ATLAS identifier."
            )
        )
        if verdict == "pass":
            verdict = "warning"
    facts.extend(_coverage_facts(coverage))
    return _gate(
        verdict,
        summary,
        facts,
        refs,
        {
            "candidate_count": len(candidates),
            "source_bound_count": len(bound),
            "unbound_count": unbound,
            "invalid_attack_id_count": invalid_attack_ids,
            "coverage": coverage,
        },
    )


def _evaluate_procedure_level_claim(text: str, claims: list[dict[str, Any]], coverage: dict[str, Any]) -> dict[str, Any]:
    facts: list[dict[str, Any]] = []
    refs: list[dict[str, Any]] = []
    candidates = [claim for claim in claims if _claim_kind(claim) == "procedure" and not _is_ai_advisory_claim(claim)]
    specific: list[dict[str, Any]] = []
    generic_count = 0
    unbound_specific_count = 0

    for index, claim in enumerate(candidates):
        evidence_ref, evidence_text = _bind_claim_evidence(text, claim, index)
        is_specific = _is_specific_procedure_claim(claim, evidence_text or _claim_evidence_text(claim))
        if is_specific and evidence_ref is not None:
            specific.append(evidence_ref)
            refs.append(evidence_ref)
        elif is_specific:
            unbound_specific_count += 1
        elif evidence_ref is not None:
            generic_count += 1

    if specific:
        facts.append(
            _fact(
                "procedure_level_claim_present",
                "pass",
                f"{len(specific)} source-bound candidate(s) describe a concrete action and affected object.",
                specific,
            )
        )
        if coverage["coverage_complete"]:
            verdict = "pass"
            summary = "At least one concrete, source-bound procedure-level claim is present."
        else:
            verdict = "warning"
            summary = "A procedure-level claim is present, but analysis coverage is incomplete or unknown."
    else:
        facts.append(
            _fact(
                "procedure_level_claim_missing",
                "fail",
                "No source-bound candidate describes a concrete action and affected object; a tool association alone is insufficient.",
            )
        )
        verdict = "fail"
        summary = "No supported procedure-level claim is available."

    if generic_count:
        facts.append(
            _fact("generic_tool_mentions", "warning", f"{generic_count} source-bound candidate(s) are generic tool or technique mentions.")
        )
    if unbound_specific_count:
        facts.append(
            _fact(
                "specific_claims_unbound", "warning", f"{unbound_specific_count} apparently specific claim(s) lack exact source evidence."
            )
        )
    facts.extend(_coverage_facts(coverage))
    return _gate(
        verdict,
        summary,
        facts,
        refs,
        {
            "candidate_count": len(candidates),
            "source_bound_specific_count": len(specific),
            "generic_bound_count": generic_count,
            "unbound_specific_count": unbound_specific_count,
            "coverage": coverage,
        },
    )


def _evaluate_actor_identification(
    text: str,
    claims: list[dict[str, Any]],
    coverage: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    facts: list[dict[str, Any]] = []
    refs: list[dict[str, Any]] = []
    candidates = [claim for claim in claims if _claim_kind(claim) == "actor" and not _is_ai_advisory_claim(claim)]
    explicit: list[dict[str, Any]] = []
    overlap_only = 0
    inferred = 0
    unsupported = 0
    conflicting = 0

    for index, claim in enumerate(candidates):
        basis = _actor_basis(claim)
        actor_name = _actor_name(claim)
        evidence_ref, evidence_text = _bind_claim_evidence(text, claim, index)
        if basis in _OVERLAP_ACTOR_BASES:
            overlap_only += 1
            continue
        if basis in {"conflicting", "disputed"}:
            conflicting += 1
            continue
        if basis in _EXPLICIT_ACTOR_BASES:
            if (
                evidence_ref is not None
                and actor_name.casefold() not in _NON_ACTOR_NAMES
                and actor_name.casefold() in (evidence_text or "").casefold()
                and not _ACTOR_NEGATION_RE.search(evidence_text or "")
            ):
                explicit.append(evidence_ref)
                refs.append(evidence_ref)
            else:
                unsupported += 1
            continue
        if basis in {"inferred", "analytic_inference", "behavioral_inference"}:
            inferred += 1
        else:
            unsupported += 1

    apt_matches = context.get("apt_matches") if isinstance(context.get("apt_matches"), list) else []
    if apt_matches:
        facts.append(
            _fact(
                "similarity_leads_excluded",
                "info",
                f"{len(apt_matches)} ATT&CK similarity/overlap lead(s) were excluded from actor identification.",
            )
        )

    if explicit:
        facts.append(
            _fact(
                "actor_explicit_in_source",
                "pass",
                f"{len(explicit)} actor identification claim(s) are explicit and source-bound.",
                explicit,
            )
        )
        if overlap_only or inferred or unsupported or conflicting or not coverage["coverage_complete"]:
            verdict = "warning"
            summary = "Explicit actor evidence exists, but competing, unsupported, or coverage concerns require review."
        else:
            verdict = "pass"
            summary = "Actor identification is explicit, source-bound, and not derived from similarity."
    elif overlap_only:
        facts.append(
            _fact(
                "actor_based_on_overlap_only",
                "fail",
                "Actor identification is based only on shared tooling, malware, ATT&CK overlap, or similarity.",
            )
        )
        verdict = "fail"
        summary = "Similarity and shared tooling are leads, not actor attribution."
    elif inferred:
        facts.append(_fact("actor_inferred", "warning", "Actor identification is an analytic inference, not an explicit source statement."))
        verdict = "warning"
        summary = "Inferred actor identification requires an explicit analyst decision and rationale."
    elif candidates:
        facts.append(
            _fact(
                "actor_evidence_unsupported", "fail", "Actor candidates are missing an allowed basis, actor name, or exact source evidence."
            )
        )
        verdict = "fail"
        summary = "Actor identification is unsupported by exact source evidence."
    else:
        facts.append(
            _fact(
                "actor_not_identified",
                "warning",
                "No actor identification claim is present; the analyst may mark this gate not applicable.",
            )
        )
        verdict = "warning"
        summary = "The source does not identify an actor."

    if overlap_only and explicit:
        facts.append(
            _fact("actor_overlap_claim_rejected", "warning", f"{overlap_only} overlap-only actor claim(s) cannot support attribution.")
        )
    if inferred:
        facts.append(_fact("actor_inference_present", "warning", f"{inferred} inferred actor claim(s) require analyst assessment."))
    if unsupported:
        facts.append(
            _fact("actor_claims_unbound", "warning", f"{unsupported} actor claim(s) are missing exact, affirmative source support.")
        )
    if conflicting:
        facts.append(_fact("actor_claims_conflicting", "warning", f"{conflicting} actor claim(s) are marked disputed or conflicting."))
    facts.extend(_coverage_facts(coverage))
    return _gate(
        verdict,
        summary,
        facts,
        refs,
        {
            "candidate_count": len(candidates),
            "explicit_source_bound_count": len(explicit),
            "overlap_only_count": overlap_only,
            "inferred_count": inferred,
            "unsupported_count": unsupported,
            "similarity_leads_excluded": len(apt_matches),
            "coverage": coverage,
        },
    )


def _collect_claims(claims: Any, context: dict[str, Any]) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    sources: list[Any] = [claims]
    for key in ("techniques", "procedure_claims", "actor_candidates"):
        sources.append(context.get(key))
    for source in sources:
        if not isinstance(source, list):
            continue
        for item in source[:1000]:
            if isinstance(item, Mapping):
                collected.append(dict(item))
    return collected


def _coverage_details(text: str, metadata: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    source_chars = len(text)
    raw_ranges = context.get("analyzed_ranges")
    if not isinstance(raw_ranges, list):
        raw_ranges = metadata.get("analyzed_ranges")
    ranges = _normalise_ranges(raw_ranges, source_chars)
    if ranges:
        analyzed_chars = sum(end - start for start, end in ranges)
        coverage_known = True
        complete = source_chars == 0 or (ranges[0][0] == 0 and ranges[-1][1] == source_chars and analyzed_chars == source_chars)
    else:
        raw_count = _first_metadata_value(metadata, context, ("analyzed_char_count", "analysis_char_count", "coverage_chars"))
        count = _as_int(raw_count)
        coverage_known = count is not None
        analyzed_chars = min(source_chars, max(0, count or 0))
        complete = coverage_known and analyzed_chars >= source_chars

    declared_complete = _first_metadata_value(metadata, context, ("coverage_complete", "complete_coverage"))
    if isinstance(declared_complete, bool):
        complete = complete and declared_complete
    percent = 100.0 if source_chars == 0 and coverage_known else round((analyzed_chars / source_chars) * 100, 2) if source_chars else 0.0
    return {
        "source_char_count": source_chars,
        "analyzed_char_count": analyzed_chars if coverage_known else None,
        "coverage_percent": percent if coverage_known else None,
        "coverage_complete": bool(complete),
        "coverage_known": coverage_known,
        "analyzed_ranges": [[start, end] for start, end in ranges],
    }


def _normalise_ranges(value: Any, source_chars: int) -> list[tuple[int, int]]:
    if not isinstance(value, list):
        return []
    parsed: list[tuple[int, int]] = []
    for item in value[:1000]:
        if isinstance(item, Mapping):
            start, end = _as_int(item.get("start")), _as_int(item.get("end"))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            start, end = _as_int(item[0]), _as_int(item[1])
        else:
            continue
        if start is None or end is None or start < 0 or end <= start or start >= source_chars:
            continue
        parsed.append((start, min(end, source_chars)))
    parsed.sort()
    merged: list[tuple[int, int]] = []
    for start, end in parsed:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def _coverage_facts(coverage: dict[str, Any]) -> list[dict[str, Any]]:
    if coverage["coverage_complete"]:
        return [_fact("analysis_coverage_complete", "pass", "The complete stored source was analysed.")]
    if coverage["coverage_known"]:
        return [
            _fact(
                "analysis_coverage_partial",
                "warning",
                f"Only {coverage['analyzed_char_count']} of {coverage['source_char_count']} stored characters were analysed.",
            )
        ]
    return [_fact("analysis_coverage_unknown", "warning", "Analysis coverage of the stored source is not recorded.")]


def _publication_candidates(text: str, metadata: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    def add(value: Any, source: str, path: str, evidence: Any = None) -> None:
        clean = _clean_string(value, 160)
        if not clean:
            return
        evidence_ref, _ = _bind_evidence_value(text, evidence, len(candidates), path)
        ref = evidence_ref or _metadata_ref(path, clean)
        candidates.append({"value": clean, "source": _clean_string(source, 160) or path, "ref": ref})

    def visit(node: Any, path: str, depth: int) -> None:
        if depth > 4:
            return
        if isinstance(node, Mapping):
            for raw_key in sorted(node, key=lambda item: str(item)):
                key = str(raw_key)
                value = node[raw_key]
                child_path = f"{path}.{key}" if path else key
                key_normalized = key.lower().replace("-", "_")
                if key_normalized == "publication_date_candidates" and isinstance(value, list):
                    for index, item in enumerate(value[:50]):
                        if isinstance(item, Mapping):
                            add(
                                item.get("value") or item.get("date"),
                                _clean_string(item.get("source"), 160) or child_path,
                                f"{child_path}[{index}]",
                                item.get("evidence") or item.get("quote"),
                            )
                        else:
                            add(item, child_path, f"{child_path}[{index}]")
                elif key_normalized in _PUBLICATION_KEYS:
                    if isinstance(value, Mapping):
                        add(value.get("value") or value.get("date"), value.get("source") or child_path, child_path, value.get("evidence"))
                    elif not isinstance(value, (list, dict)):
                        add(value, child_path, child_path)
                elif isinstance(value, (Mapping, list)):
                    visit(value, child_path, depth + 1)
        elif isinstance(node, list):
            for index, item in enumerate(node[:100]):
                visit(item, f"{path}[{index}]", depth + 1)

    visit(metadata, "source_metadata", 0)
    for key in ("publication_date", "publication_date_candidates"):
        if key in context:
            visit({key: context[key]}, "context", 0)

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        marker = (candidate["value"], candidate["source"])
        if marker not in seen:
            seen.add(marker)
            deduped.append(candidate)
    return deduped[:100]


def _claim_kind(claim: Mapping[str, Any]) -> str:
    kind = _clean_string(claim.get("claim_type") or claim.get("type") or claim.get("kind"), 40).lower().replace("-", "_")
    if kind in {"procedure", "technique", "ttp", "procedure_claim"}:
        return "procedure"
    if kind in {"actor", "threat_actor", "attribution", "actor_identification"}:
        return "actor"
    if claim.get("attack_id") or claim.get("technique_id"):
        return "procedure"
    if claim.get("actor_id") or claim.get("actor_name") or claim.get("attribution_basis"):
        return "actor"
    return kind


def _claim_evidence_text(claim: Mapping[str, Any]) -> str:
    evidence = claim.get("evidence")
    if isinstance(evidence, Mapping):
        evidence = evidence.get("quote") or evidence.get("text")
    return _clean_string(claim.get("evidence_text") or evidence or claim.get("quote"), 5000, collapse=False)


def _bind_claim_evidence(text: str, claim: Mapping[str, Any], index: int) -> tuple[dict[str, Any] | None, str]:
    evidence = _claim_evidence_text(claim)
    if not evidence:
        return None, ""
    nested = claim.get("evidence") if isinstance(claim.get("evidence"), Mapping) else {}
    start = _as_int(claim.get("evidence_start"))
    end = _as_int(claim.get("evidence_end"))
    if start is None:
        start = _as_int(nested.get("start"))
    if end is None:
        end = _as_int(nested.get("end"))
    claim_key = _clean_string(claim.get("claim_key") or claim.get("id") or claim.get("attack_id"), 100) or f"candidate-{index}"

    if start is not None or end is not None:
        if start is None or end is None or start < 0 or end <= start or end > len(text):
            return None, evidence
        if text[start:end] != evidence:
            return None, evidence
        return _source_ref(text, start, end, claim_key), evidence

    first = text.find(evidence)
    if first < 0 or text.find(evidence, first + 1) >= 0:
        return None, evidence
    return _source_ref(text, first, first + len(evidence), claim_key), evidence


def _bind_evidence_value(text: str, evidence: Any, index: int, key: str) -> tuple[dict[str, Any] | None, str]:
    if isinstance(evidence, Mapping):
        claim = {
            "claim_key": key,
            "evidence_text": evidence.get("quote") or evidence.get("text"),
            "evidence_start": evidence.get("start"),
            "evidence_end": evidence.get("end"),
        }
    else:
        claim = {"claim_key": key, "evidence_text": evidence}
    return _bind_claim_evidence(text, claim, index)


def _is_specific_procedure_claim(claim: Mapping[str, Any], evidence: str) -> bool:
    compact_evidence = _SPACE_RE.sub(" ", evidence).strip()
    if not compact_evidence or _GENERIC_TOOL_MENTION_RE.fullmatch(compact_evidence):
        return False
    action = _clean_string(claim.get("action") or claim.get("predicate"), 500)
    object_ = _clean_string(claim.get("object") or claim.get("target"), 500)
    statement = _clean_string(claim.get("statement"), 1000)
    searchable = " ".join(item for item in (action, statement, compact_evidence) if item)
    has_concrete_action = bool(_STRONG_PROCEDURE_RE.search(searchable))
    if action and object_:
        return has_concrete_action
    # ATT&CK extraction records are often unstructured.  A locally bound quote
    # can still be specific when it contains a concrete action and context,
    # but a bare "uses PowerShell" association cannot pass.
    return has_concrete_action and len(re.findall(r"[A-Za-z0-9]+", compact_evidence)) >= 4


def _actor_basis(claim: Mapping[str, Any]) -> str:
    metadata_value = claim.get("metadata") or claim.get("claim_metadata")
    metadata = metadata_value if isinstance(metadata_value, Mapping) else {}
    basis = (
        _clean_string(
            claim.get("basis")
            or claim.get("attribution_basis")
            or claim.get("actor_basis")
            or metadata.get("basis")
            or metadata.get("attribution_basis"),
            80,
        )
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )
    aliases = {
        "explicit_in_source": "explicit",
        "report_explicit": "explicit",
        "reported_by_source": "source_reported",
        "source_report": "source_reported",
        "shared_tooling_only": "tooling_overlap_only",
        "tool_overlap": "tooling_overlap_only",
        "ttp_similarity": "similarity",
    }
    return aliases.get(basis, basis)


def _actor_name(claim: Mapping[str, Any]) -> str:
    metadata_value = claim.get("metadata") or claim.get("claim_metadata")
    metadata = metadata_value if isinstance(metadata_value, Mapping) else {}
    actor_ids = claim.get("actor_ids") if isinstance(claim.get("actor_ids"), list) else []
    subject = _clean_string(claim.get("subject"), 300)
    object_ = _clean_string(claim.get("object"), 300)
    predicate = _clean_string(claim.get("predicate") or claim.get("action"), 300).casefold()
    attributed_object = object_ if any(term in predicate for term in ("attribute", "identify", "link")) else ""
    return _clean_string(
        claim.get("actor_name")
        or metadata.get("actor_name")
        or attributed_object
        or claim.get("actor_id")
        or (actor_ids[0] if actor_ids else "")
        or subject,
        300,
    )


def _is_ai_advisory_claim(claim: Mapping[str, Any]) -> bool:
    origin = " ".join(_clean_string(claim.get(key), 100).lower() for key in ("source", "extraction_method", "origin"))
    return "ai-advisory" in origin or "ai_advisory" in origin or claim.get("authoritative") is False


def _bounded_ai_advisory(ai_advisory: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    parts = ai_advisory.get("parts")
    if not isinstance(parts, list):
        parts = [ai_advisory]
    parts = [part for part in parts[:10] if isinstance(part, Mapping)]
    common = {
        "authoritative": False,
        "source": "ai-assistant",
        "provider": _clean_string(ai_advisory.get("provider"), 40),
        "model": _clean_string(ai_advisory.get("model"), 100),
        "prompt_version": _clean_string(ai_advisory.get("prompt_version"), 100),
        "coverage_chars": _as_int(ai_advisory.get("coverage_chars")),
        "source_chars": _as_int(ai_advisory.get("source_chars")),
        "complete_coverage": ai_advisory.get("complete_coverage") is True,
    }

    relevance: list[dict[str, str]] = []
    procedure_claims: list[dict[str, Any]] = []
    actor: list[dict[str, str]] = []
    dates: list[dict[str, str]] = []
    for part in parts:
        relevance_in = part.get("procedure_relevance")
        if isinstance(relevance_in, Mapping):
            relevance.append(
                {
                    "suggestion": _clean_string(relevance_in.get("verdict"), 40),
                    "rationale": _clean_string(relevance_in.get("rationale"), 800),
                }
            )
        for item in list(part.get("procedure_claims") or [])[:20]:
            if not isinstance(item, Mapping):
                continue
            procedure_claims.append(
                {
                    "subject": _clean_string(item.get("subject"), 200),
                    "action": _clean_string(item.get("action"), 300),
                    "object": _clean_string(item.get("object"), 300),
                    "context": _clean_string(item.get("context"), 500),
                    "attack_id": _clean_string(item.get("attack_id"), 30),
                    "evidence": _bounded_advisory_evidence(item.get("evidence")),
                }
            )
        actor_in = part.get("actor_identification")
        if isinstance(actor_in, Mapping):
            actor.append(
                {
                    "suggestion": _clean_string(actor_in.get("verdict"), 40),
                    "basis": _clean_string(actor_in.get("basis"), 80),
                    "actor_name": _clean_string(actor_in.get("actor_name"), 200),
                    "rationale": _clean_string(actor_in.get("rationale"), 800),
                }
            )
        for item in list(part.get("publication_date_candidates") or [])[:10]:
            if isinstance(item, Mapping):
                dates.append(
                    {
                        "value": _clean_string(item.get("value"), 40),
                        "source": "ai-assistant",
                    }
                )

    return {
        "procedure_relevance": {**common, "suggestions": relevance[:20]},
        "procedure_level_claim": {**common, "suggestions": procedure_claims[:50]},
        "actor_identification": {**common, "suggestions": actor[:20]},
        "publication_date": {**common, "suggestions": dates[:50]},
    }


def _bounded_advisory_evidence(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    start, end = _as_int(value.get("start")), _as_int(value.get("end"))
    if start is None or end is None or start < 0 or end <= start:
        return None
    return {
        "start": start,
        "end": end,
        "quote": _clean_string(value.get("quote"), 240, collapse=False),
        "source": "ai-advisory-source-bound",
    }


def _first_metadata_value(metadata: Mapping[str, Any], context: Mapping[str, Any], keys: Iterable[str]) -> Any:
    # Caller order is a deterministic precedence contract. In particular, a
    # raw source-text digest must win over the composite review fingerprint.
    wanted = tuple(dict.fromkeys(str(key).lower() for key in keys))
    for key in wanted:
        for root in (context, metadata):
            direct = _find_metadata_value(root, key, 0)
            if direct is not None and direct != "":
                return direct
    return None


def _find_metadata_value(node: Any, wanted: str, depth: int) -> Any:
    if depth > 4 or not isinstance(node, Mapping):
        return None
    lowered = {str(key).lower(): key for key in node}
    direct_key = lowered.get(wanted)
    if direct_key is not None and not isinstance(node[direct_key], (Mapping, list)):
        return node[direct_key]
    for raw_key in sorted(node, key=lambda item: str(item)):
        value = node[raw_key]
        if isinstance(value, Mapping):
            found = _find_metadata_value(value, wanted, depth + 1)
            if found is not None and found != "":
                return found
    return None


def _parse_date(value: Any) -> date | None:
    clean = _clean_string(value, 160)
    if not clean:
        return None
    match = _DATE_PREFIX_RE.fullmatch(clean)
    if match:
        try:
            return date.fromisoformat(match.group(1))
        except ValueError:
            return None
    try:
        return datetime.fromisoformat(clean.replace("Z", "+00:00")).date()
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(clean).date()
    except (TypeError, ValueError, OverflowError):
        return None


def _public_http_url_error(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return "Stored source URL cannot be parsed."
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        return "Stored source URL must use HTTP(S) and include a host."
    if port == 0:
        return "Stored source URL contains an invalid network port."
    if parsed.username or parsed.password:
        return "Stored source URL contains embedded credentials."
    if any(character.isspace() for character in value):
        return "Stored source URL contains whitespace."
    if hostname.lower() == "localhost" or hostname.lower().endswith(".local"):
        return "Stored source URL targets a local hostname."
    try:
        address = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return ""
    if not address.is_global:
        return "Stored source URL targets a non-public IP address."
    return ""


def _safe_url(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError:
        return "[invalid URL]"
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname
    if port:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, "", ""))[:1000]


def _normalized_url_identity(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError:
        return ""
    hostname = (parsed.hostname or "").casefold()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    default_port = (parsed.scheme.casefold() == "http" and port == 80) or (
        parsed.scheme.casefold() == "https" and port == 443
    )
    netloc = hostname if not port or default_port else f"{hostname}:{port}"
    return urlunsplit(
        (
            parsed.scheme.casefold(),
            netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def _source_ref(text: str, start: int, end: int, claim_key: str) -> dict[str, Any]:
    return {
        "type": "source_span",
        "claim_key": claim_key,
        "start": start,
        "end": end,
        "quote": text[start:end][:240],
    }


def _metadata_ref(path: str, value: Any) -> dict[str, Any]:
    if isinstance(value, (str, int, float, bool)) or value is None:
        safe_value = value
    else:
        safe_value = _clean_string(value, 500)
    return {"type": "metadata", "path": path[:300], "value": safe_value}


def _fact(code: str, outcome: str, message: str, evidence_refs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    fact: dict[str, Any] = {"code": code, "outcome": outcome, "message": message}
    if evidence_refs:
        fact["evidence_refs"] = _dedupe_refs(evidence_refs)
    return fact


def _gate(
    verdict: str,
    summary: str,
    facts: list[dict[str, Any]],
    refs: list[dict[str, Any]],
    metrics: dict[str, Any],
) -> dict[str, Any]:
    fact_refs = [ref for fact in facts for ref in fact.get("evidence_refs", []) if isinstance(ref, dict)]
    return {
        "machine_verdict": verdict,
        "details": {
            "policy_version": PREFLIGHT_POLICY_VERSION,
            "summary": summary,
            "facts": facts,
            "metrics": metrics,
        },
        "evidence_refs": _dedupe_refs([*refs, *fact_refs]),
        "evaluator": PREFLIGHT_EVALUATOR,
    }


def _dedupe_refs(refs: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ref in refs:
        marker = json.dumps(ref, sort_keys=True, separators=(",", ":"), default=str)
        if marker not in seen:
            seen.add(marker)
            result.append(ref)
    return result


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _clean_string(value: Any, limit: int, *, collapse: bool = True) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        return ""
    clean = str(value).replace("\x00", "").strip()
    if collapse:
        clean = _SPACE_RE.sub(" ", clean)
    return clean[:limit]
