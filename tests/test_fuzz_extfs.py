"""Structure-aware, repeatable fuzzing suite for :mod:`dissect.extfs`.

These tests synthesize small valid ext2/ext4 images and mutate their superblock
geometry, group descriptors and extent subtrees (not just their leading bytes).
Every case runs under explicit read and wall-clock budgets and is classified
into format rejection, out-of-bounds access, non-termination or an unexpected
parser bug.  Failing samples are persisted, reducible and replayable.
"""
from __future__ import annotations

import gzip
import logging
from pathlib import Path

import pytest

from tests.fuzz import control_samples
from tests.fuzz.fuzzer import (
    generate_cases,
    read_artifact,
    reduce_case,
    replay_file,
    run_campaign,
    write_artifact,
)
from tests.fuzz.harness import BUG, OOB, REJECTED, TIMEOUT, FAILURE_OUTCOMES, run_case
from tests.fuzz.image_builder import EXT2, EXT4, build_seed
from tests.fuzz.mutators import mutators_for

# Keep parser-internal critical logging out of the captured test output.
logging.getLogger("dissect.extfs.extfs").disabled = True

FUZZ_SEED = 20261113
READ_BUDGET = 1 << 20
TIME_BUDGET = 2.0


def test_seed_images_are_valid() -> None:
    """The unmutated seeds must parse and read cleanly (the fuzzing baseline)."""
    for flavour in (EXT4, EXT2):
        image = build_seed(flavour)
        outcome = run_case(f"seed-{flavour}", bytes(image.data))
        assert outcome.outcome == "ok", outcome.as_dict()


def test_campaign_is_deterministic() -> None:
    """A fixed seed must always produce the identical byte-level cases."""
    first = generate_cases(FUZZ_SEED)
    second = generate_cases(FUZZ_SEED)
    assert len(first) == len(second)
    assert [case.data for case in first] == [case.data for case in second]
    assert [case.label() for case in first] == [case.label() for case in second]


def test_every_mutator_is_represented() -> None:
    """The campaign must exercise every structure-aware mutator per flavour."""
    cases = generate_cases(FUZZ_SEED)
    for flavour in (EXT4, EXT2):
        expected = {mutator.__name__ for mutator in mutators_for(flavour)}
        seen = {case.mutator for case in cases if case.flavour == flavour}
        assert expected <= seen


def test_mutations_are_structure_aware_not_leading_bytes() -> None:
    """Mutations must land deep in metadata, leaving the boot area untouched.

    This guards against the suite degenerating into header-byte flipping: every
    generated case differs from its seed only at offsets inside or after the
    superblock (>= 1024), never in the leading boot block.
    """
    for case in generate_cases(FUZZ_SEED):
        seed = build_seed(case.flavour)
        diffs = [idx for idx, (a, b) in enumerate(zip(seed.data, case.data)) if a != b]
        assert diffs, f"{case.label()} did not mutate anything"
        assert min(diffs) >= 1024, f"{case.label()} mutated the boot/header prefix"


@pytest.mark.parametrize("control_builder", control_samples.ALL_CONTROLS)
def test_control_samples_raise_expected_alarms(control_builder) -> None:
    """Known-malicious controls must trip their specific failure class."""
    data, control = control_builder()
    outcome = run_case(control.name, data, read_budget=READ_BUDGET, time_budget=TIME_BUDGET)
    assert outcome.outcome == control.expected_outcome, (
        f"{control.name}: expected {control.expected_outcome}, got {outcome.as_dict()}"
    )


def test_watchdog_interrupts_non_termination() -> None:
    """The timer must stop a genuine infinite loop instead of hanging pytest."""
    control_samples.watchdog_control()


def test_run_case_classifies_timeout() -> None:
    """A non-terminating worker path must be reported as TIMEOUT, not swallowed."""
    image = build_seed(EXT4)

    def never_returns(_extfs) -> None:
        while True:
            pass

    outcome = run_case("stalling-worker", bytes(image.data), time_budget=0.2, exercise=never_returns)
    assert outcome.outcome == TIMEOUT
    assert outcome.exception_type == "TimeBudgetExceeded"
    assert outcome.is_failure


def test_rejection_is_distinct_from_failure() -> None:
    """A format rejection must never be counted as a safe pass silently, nor as a bug."""
    data, control = control_samples.invalid_magic_control()
    outcome = run_case(control.name, data)
    assert outcome.outcome == REJECTED
    assert not outcome.is_failure
    assert outcome.exception_type == "Error"


def test_campaign_classifies_and_persists_failures(tmp_path: Path) -> None:
    """Run the fixed small batch and verify failures are persisted, not swallowed."""
    cases = generate_cases(FUZZ_SEED, cases_per_mutator=2)
    results = run_campaign(
        cases,
        tmp_path,
        read_budget=READ_BUDGET,
        time_budget=TIME_BUDGET,
    )

    assert len(results) == len(cases)
    observed = {outcome.outcome for _, outcome in results}
    # A healthy campaign sees clean rejections and at least one hard failure;
    # every outcome must be one of the known, explicitly-handled classes.
    assert observed <= {"ok", REJECTED, OOB, TIMEOUT, BUG}
    failures = [(case, outcome) for case, outcome in results if outcome.is_failure]
    assert failures, "campaign detected no failures; the harness may be too permissive"

    artifacts = sorted(tmp_path.glob("*.gz"))
    assert len(artifacts) == len(failures)
    for case, outcome in failures:
        assert outcome.outcome in FAILURE_OUTCOMES
        matching = [path for path in artifacts if case.label() in path.name]
        assert matching, f"no artifact persisted for {case.label()}"


def test_artifact_roundtrip_and_replay(tmp_path: Path) -> None:
    """A persisted failure must reload and reproduce the same classification."""
    cases = generate_cases(FUZZ_SEED)
    results = run_campaign(cases, tmp_path, read_budget=READ_BUDGET, time_budget=TIME_BUDGET)
    failing = [(case, outcome) for case, outcome in results if outcome.is_failure]
    assert failing

    case, original = failing[0]
    artifact = tmp_path / f"{case.label()}-{original.outcome}.gz"
    metadata, raw = read_artifact(artifact)
    assert metadata["outcome"]["outcome"] == original.outcome
    assert raw == case.data

    replayed = replay_file(artifact, read_budget=READ_BUDGET, time_budget=TIME_BUDGET)
    assert replayed.outcome == original.outcome


def test_reducer_preserves_failure_class(tmp_path: Path) -> None:
    """Delta debugging must shrink a failing sample without changing its class."""
    cases = generate_cases(FUZZ_SEED)
    results = run_campaign(cases, tmp_path, read_budget=READ_BUDGET, time_budget=TIME_BUDGET)
    case, original = next((c, o) for c, o in results if o.is_failure)

    reduced = reduce_case(
        bytes(case.data),
        original.outcome,
        read_budget=READ_BUDGET,
        time_budget=TIME_BUDGET,
    )
    reduced_outcome = run_case(case.label(), reduced, read_budget=READ_BUDGET, time_budget=TIME_BUDGET)
    assert reduced_outcome.outcome == original.outcome
    assert len(reduced) == len(case.data)
    assert sum(byte != 0 for byte in reduced) <= sum(byte != 0 for byte in case.data)

    # The minimized sample is itself a replayable artifact.
    reduced_path = tmp_path / "reduced.gz"
    write_artifact(reduced_path, case, reduced_outcome)
    with gzip.open(reduced_path, "rb") as fh:
        assert fh.read(len(b"EXTFuzzV1")) == b"EXTFuzzV1"


def test_unexpected_exception_is_bug_not_rejection() -> None:
    """Defense in depth: an unrecognized exception must classify as BUG.

    Drives a case known to raise a non-rejection exception (a directory entry
    file_type outside the FILETYPES map yields KeyError) and confirms it is
    never folded into the safe REJECTED bucket.
    """
    image = build_seed(EXT4)
    from dissect.extfs.c_ext import c_ext

    from tests.fuzz.image_builder import direntry_field

    data = bytearray(image.data)
    entry_pos = image.root_dir_block * image.block_size + 24
    data[entry_pos + direntry_field("file_type")] = 0xFF
    outcome = run_case("bad-filetype", bytes(data))
    assert outcome.outcome == BUG
    assert outcome.exception_type == "KeyError"
    assert not outcome.outcome == REJECTED
