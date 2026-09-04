from pathlib import Path

import pytest

from ecdat.collectors.base import Target
from ecdat.collectors.opengrep import OpenGrepCollector
from ecdat.knowledge import KnowledgeBase

ZOO = Path(__file__).parent / "fixtures" / "zoo" / "src"
kb = KnowledgeBase()


@pytest.mark.skipif(not OpenGrepCollector().available(), reason="opengrep not installed")
def test_opengrep_finds_md5_in_python_zoo():
    fs = OpenGrepCollector().collect(Target("dir", str(ZOO / "python"), "py", "internal"), kb)
    assert fs, "opengrep returned nothing"
    names = {f.name for f in fs}
    assert "MD5" in names
    md5 = [f for f in fs if f.name == "MD5"][0]
    assert md5.collector == "opengrep" and md5.props["rule"] and md5.line > 0


@pytest.mark.skipif(not OpenGrepCollector().available(), reason="opengrep not installed")
def test_opengrep_js_runs_and_maps_to_canonical_names():
    fs = OpenGrepCollector().collect(Target("dir", str(ZOO / "js"), "js", "external"), kb)
    assert isinstance(fs, list)
    for f in fs:  # whatever the JS rule set flags must map to a canonical algorithm or protocol
        assert f.name in kb.algorithms and f.collector == "opengrep" and f.context["zone"] == "external"
