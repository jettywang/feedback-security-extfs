"""Command-line entry point for the deterministic extfs fuzz campaign.

Examples
--------
Run the fixed-seed small batch and write failures to ``./fuzz-out``::

    python -m tests.fuzz run --seed 20261113 --cases-per-mutator 2 --out fuzz-out

Replay a previously persisted failing artifact::

    python -m tests.fuzz replay fuzz-out/case-0009-ext4-mutate_inode_size_flags-oob.gz

Reduce an artifact to a minimal, still-failing sample::

    python -m tests.fuzz reduce fuzz-out/some-case-oob.gz
"""
from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter
from pathlib import Path

from tests.fuzz.fuzzer import (
    generate_cases,
    read_artifact,
    reduce_case,
    replay_file,
    run_campaign,
    write_artifact,
)
from tests.fuzz.harness import FAILURE_OUTCOMES

logging.disable(logging.CRITICAL)


def _cmd_run(args: argparse.Namespace) -> int:
    cases = generate_cases(args.seed, cases_per_mutator=args.cases_per_mutator)
    output_dir = Path(args.out) if args.out else None
    results = run_campaign(
        cases,
        output_dir,
        read_budget=args.read_budget,
        time_budget=args.time_budget,
    )
    counts = Counter(outcome.outcome for _, outcome in results)
    print(f"seed={args.seed} cases={len(results)} outcomes={dict(counts)}")
    for case, outcome in results:
        if outcome.is_failure:
            print(f"  {outcome.outcome.upper():7} {case.label()} {outcome.exception_type}: {outcome.detail}")
    failures = sum(1 for _, outcome in results if outcome.outcome in FAILURE_OUTCOMES)
    if output_dir is not None:
        print(f"artifacts written to {output_dir}")
    return 1 if failures and args.strict else 0


def _cmd_replay(args: argparse.Namespace) -> int:
    outcome = replay_file(Path(args.artifact), read_budget=args.read_budget, time_budget=args.time_budget)
    print(outcome.as_dict())
    return 1 if outcome.is_failure else 0


def _cmd_reduce(args: argparse.Namespace) -> int:
    path = Path(args.artifact)
    metadata, data = read_artifact(path)
    expected = metadata["outcome"]["outcome"]
    reduced = reduce_case(data, expected, read_budget=args.read_budget, time_budget=args.time_budget)
    nonzero = sum(byte != 0 for byte in reduced)
    print(f"reduced from {len(data)} bytes ({sum(b != 0 for b in data)} nonzero) "
          f"to {nonzero} nonzero bytes; outcome stays {expected!r}")
    if args.out:
        from tests.fuzz.fuzzer import FuzzCase

        case = FuzzCase(
            case_id=metadata["case"]["case_id"],
            flavour=metadata["case"]["flavour"],
            seed=metadata["case"]["seed"],
            mutator=metadata["case"]["mutator"],
            description=metadata["case"]["description"],
            data=reduced,
            params=metadata["case"]["params"],
        )
        write_artifact(Path(args.out), case, replay_file(path))
        print(f"wrote reduced artifact to {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m tests.fuzz", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a fixed-seed fuzz campaign")
    run.add_argument("--seed", type=int, default=20261113)
    run.add_argument("--cases-per-mutator", type=int, default=2)
    run.add_argument("--out", default=None, help="directory for failure artifacts")
    run.add_argument("--read-budget", type=int, default=1 << 20)
    run.add_argument("--time-budget", type=float, default=2.0)
    run.add_argument("--strict", action="store_true", help="exit non-zero when any case fails")
    run.set_defaults(func=_cmd_run)

    replay = sub.add_parser("replay", help="replay a failure artifact")
    replay.add_argument("artifact")
    replay.add_argument("--read-budget", type=int, default=1 << 20)
    replay.add_argument("--time-budget", type=float, default=2.0)
    replay.set_defaults(func=_cmd_replay)

    reduce_parser = sub.add_parser("reduce", help="minimize a failure artifact")
    reduce_parser.add_argument("artifact")
    reduce_parser.add_argument("--out", default=None)
    reduce_parser.add_argument("--read-budget", type=int, default=1 << 20)
    reduce_parser.add_argument("--time-budget", type=float, default=2.0)
    reduce_parser.set_defaults(func=_cmd_reduce)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
