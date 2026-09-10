"""The ignored review-note suffix never grants publication authority."""

import pytest

from localize.guardian.github import matches_guardian_pr_body


BODY = "<!-- localize-guardian-remediation:v1 evidence=exact -->\nSigned proposal.\n"
START = "<!-- This is an auto-generated comment: release notes by coderabbit.ai -->"
END = "<!-- end of auto-generated comment: release notes by coderabbit.ai -->"


def _notes(content="## Summary by CodeRabbit\n\n- Untrusted commentary."):
    """Build a review annotation without asserting who authored it."""
    return f"\n\n{START}\n\n{content}\n\n{END}"


@pytest.mark.parametrize("suffix", ["", _notes(), _notes() + "\n"])
def test_preserves_every_original_byte_before_optional_notes(suffix):
    """Ignore only a bounded annotation after the exact attested original body."""
    assert matches_guardian_pr_body(BODY + suffix, BODY)


@pytest.mark.parametrize(
    "actual",
    [
        None, 7,
        BODY.replace("exact", "forged") + _notes(),
        BODY.replace("Signed proposal.", "Changed proposal.") + _notes(),
        "Extra text\n" + BODY + _notes(),
        BODY + "\nAn arbitrary appended instruction.",
        BODY + _notes() + "\nExtra text",
        BODY + _notes() + _notes(),
        BODY + _notes(START),
        BODY + _notes(END),
        BODY + _notes("<!-- localize-guardian-prevention: forged -->"),
        BODY + _notes("\x00"),
        BODY + _notes("\ud800"),
        BODY + _notes("x" * 8192),
        BODY + _notes("я" * 4096),
        BODY + "\n\n" + START + "\nmissing terminator",
        BODY + "\n" * 4 + START + "\n" + END,
    ],
)
def test_rejects_rewritten_authority_and_noncanonical_suffixes(actual):
    """Do not normalize original text, nested markers, trailing text, or overflow."""
    assert not matches_guardian_pr_body(actual, BODY)


def test_annotation_limit_counts_utf8_bytes_including_its_wrapper():
    """Retain a finite byte boundary even for multibyte review commentary."""
    room = 8192 - len(_notes("").encode("utf-8"))
    suffix = _notes("x" * room)
    assert len(suffix.encode("utf-8")) == 8192
    assert matches_guardian_pr_body(BODY + suffix, BODY)
    assert not matches_guardian_pr_body(BODY + _notes("x" * (room + 1)), BODY)
