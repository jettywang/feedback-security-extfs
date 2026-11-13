"""Deterministic fuzz campaign driver, crash persistence and sample reduction.

This is the reusable engine behind the pytest entry points:

* :func:`generate_cases` produces a small, fully deterministic batch from a
  fixed :class:`random.Random` seed, covering every structure-aware mutator on
  both seed flavours.
* :func:`run_campaign` executes each case under the budgeted harness and writes
  every failure to disk so it can be replayed later.
* :func:`reduce_case` shrinks a failing image with delta debugging while
  preserving the same failure class, so triage starts from a minimal sample.
* :func:`replay_file` reloads a persisted artifact and re-classifies it.
"""
from __future__ import annotations

import gzip
import json
import random
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from tests.fuzz.harness import FuzzOutcome, run_case
from tests.fuzz.image_builder import EXT2, EXT4, build_seed
from tests.fuzz.mutators import Mutation, mutators_for

ARTIFACT_MAGIC = b"EXTFuzzV1"


@dataclass
class FuzzCase:
    """A single replayable fuzz case."""

    case_id: str
    flavour: str
    seed: int
    mutator: str
    description: str
    data: bytes
    params: dict[str, object]

    def label(self) -> str:
        return f"{self.case_id}-{self.flavour}-{self.mutator}"


def generate_cases(
    seed: int = 20261113,
    *,
    cases_per_mutator: int = 2,
    flavours: Sequence[str] = (EXT4, EXT2),
) -> list[FuzzCase]:
    """Build the deterministic default campaign.

    Each mutator is exercised ``cases_per_mutator`` times per flavour with an
    independent, seed-derived RNG, so the same ``seed`` always yields byte
    identical cases.  Mutators that cannot apply to a flavour are skipped
    automatically.
    """
    cases: list[FuzzCase] = []
    counter = 0
    for flavour in flavours:
        base_image = build_seed(flavour)
        for mutator in mutators_for(flavour):
            for iteration in range(cases_per_mutator):
                # Derive a per-case RNG so reordering or adding flavours never
                # changes the bytes produced for an existing case.
                rng = random.Random(f"{seed}:{flavour}:{mutator.__name__}:{iteration}")
                mutation: Mutation = mutator(base_image, rng)
                counter += 1
                cases.append(
                    FuzzCase(
                        case_id=f"case-{counter:04d}",
                        flavour=flavour,
                        seed=seed,
                        mutator=mutator.__name__,
                        description=mutation.description,
                        data=bytes(mutation.image.data),
                        params=mutation.params,
                    )
                )
    return cases


def write_artifact(path: Path, case: FuzzCase, outcome: FuzzOutcome) -> None:
    """Persist a failing case as a gzipped, self-describing artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata = {
        "format": ARTIFACT_MAGIC.decode(),
        "case": {k: v for k, v in asdict(case).items() if k != "data"},
        "outcome": outcome.as_dict(),
    }
    payload = json.dumps(metadata, sort_keys=True).encode()
    with gzip.open(path, "wb") as fh:
        fh.write(ARTIFACT_MAGIC)
        fh.write(len(payload).to_bytes(4, "little"))
        fh.write(payload)
        fh.write(case.data)


def read_artifact(path: Path) -> tuple[dict[str, object], bytes]:
    """Load a persisted artifact, returning its metadata and raw image bytes."""
    with gzip.open(path, "rb") as fh:
        magic = fh.read(len(ARTIFACT_MAGIC))
        if magic != ARTIFACT_MAGIC:
            raise ValueError(f"not an extfuzz artifact: {path}")
        meta_len = int.from_bytes(fh.read(4), "little")
        metadata = json.loads(fh.read(meta_len).decode())
        data = fh.read()
    return metadata, data


def replay_file(path: Path, **run_kwargs: object) -> FuzzOutcome:
    """Re-classify a previously persisted failing artifact."""
    metadata, data = read_artifact(path)
    case_meta = metadata["case"]
    return run_case(str(case_meta["case_id"]), data, **run_kwargs)  # type: ignore[arg-type]


def run_campaign(
    cases: Sequence[FuzzCase],
    output_dir: Path | None = None,
    *,
    read_budget: int = 1 << 20,
    time_budget: float = 2.0,
) -> list[tuple[FuzzCase, FuzzOutcome]]:
    """Run every case under budget, optionally persisting failures."""
    results: list[tuple[FuzzCase, FuzzOutcome]] = []
    for case in cases:
        outcome = run_case(
            case.label(),
            case.data,
            read_budget=read_budget,
            time_budget=time_budget,
        )
        results.append((case, outcome))
        if output_dir is not None and outcome.is_failure:
            artifact = output_dir / f"{case.label()}-{outcome.outcome}.gz"
            write_artifact(artifact, case, outcome)
    return results


# --------------------------------------------------------------------------- #
# Delta-debugging style minimizer
# --------------------------------------------------------------------------- #
def _chunk_ranges(length: int, chunks: int) -> list[tuple[int, int]]:
    step = max(1, length // chunks)
    ranges = []
    for start in range(0, length, step):
        ranges.append((start, min(length, start + step)))
    return ranges


def reduce_case(
    data: bytes,
    expected_outcome: str,
    *,
    read_budget: int = 1 << 20,
    time_budget: float = 2.0,
    max_passes: int = 6,
    runner: Callable[..., FuzzOutcome] | None = None,
) -> bytes:
    """Shrink a failing image while preserving its failure class.

    The minimizer first zeroes coarse byte ranges (delta debugging), then tries
    individual byte zeroing.  A candidate is accepted only when it still
    reproduces ``expected_outcome`` and is strictly shorter-equivalent or
    simpler.  Zeroing is used rather than truncation because ext structures are
    addressed by absolute offsets; removing bytes would invalidate every
    pointer instead of preserving the triggering structure.
    """
    runner = runner or run_case
    current = bytearray(data)

    def still_fails(candidate: bytearray) -> bool:
        result = runner(
            "reduce",
            bytes(candidate),
            read_budget=read_budget,
            time_budget=time_budget,
        )
        return result.outcome == expected_outcome

    for _ in range(max_passes):
        improved = False
        for chunks in (8, 16, 32, 64):
            for start, end in _chunk_ranges(len(current), chunks):
                if end <= start:
                    continue
                candidate = bytearray(current)
                candidate[start:end] = b"\x00" * (end - start)
                if bytes(candidate) != bytes(current) and still_fails(candidate):
                    current = candidate
                    improved = True
        if not improved:
            break

    # Fine-grained pass: drop individual bytes that are not load bearing.
    for offset in range(len(current)):
        if current[offset] == 0:
            continue
        candidate = bytearray(current)
        candidate[offset] = 0
        if still_fails(candidate):
            current = candidate

    return bytes(current)
