"""Pytest configuration for the offline JBD2 compatibility suite.

The ``jbd2_gap`` marker documents inputs the current reader does not handle. Each
mark carries a ``category`` so test reports distinguish:

* ``parse_misalignment``: the reader accepts the input but maps tags/blocks wrongly;
* ``unsupported_format``: the on-disk layout is valid but not implemented.

Gap tests run as strict ``xfail``: they keep the suite green today and fail loudly
(``XPASS``) the moment the underlying reader learns to reject or parse the format.
"""

from __future__ import annotations

import pytest

GAP_CATEGORIES = ("parse_misalignment", "unsupported_format")


def pytest_configure(config: pytest.Config) -> None:
    for category in GAP_CATEGORIES:
        config.addinivalue_line("markers", f"{category}: JBD2 reader gap ({category})")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> pytest.TestReport:
    outcome = yield
    report = outcome.get_result()
    marker = item.get_closest_marker("jbd2_gap")
    if marker is not None:
        report.jbd2_gap_category = marker.kwargs.get("category")


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    gaps: dict[str, list[str]] = {category: [] for category in GAP_CATEGORIES}
    for report in terminalreporter.stats.get("xfailed", []):
        category = getattr(report, "jbd2_gap_category", None)
        if category in gaps:
            gaps[category].append(report.nodeid)
    if not any(gaps.values()):
        return
    terminalreporter.write_sep("-", "JBD2 compatibility gaps (documented, tracked separately)")
    for category, node_ids in gaps.items():
        for node_id in node_ids:
            terminalreporter.write_line(f"{category:20s} {node_id}")
