from pathlib import Path

import pytest

from ecdat.collectors.base import Target
from ecdat.collectors.container import ContainerCollector, extract_image
from ecdat.knowledge import KnowledgeBase

kb = KnowledgeBase()


@pytest.fixture(scope="module")
def image(tmp_path_factory):
    from scripts.build_zoo import build_binaries, build_certs, build_image
    base = tmp_path_factory.mktemp("zoo")
    build_certs(base / "certs")
    build_binaries(base / "bin")
    build_image(base / "images", base / "certs", base / "bin")
    return base / "images"


def test_extract_oci_and_docker(image, tmp_path):
    meta = extract_image(image / "zoo-oci.tar", tmp_path / "oci")
    assert meta["format"] == "oci" and meta["layers"] == 1 and (tmp_path / "oci" / "etc" / "nginx" / "nginx.conf").exists()
    meta2 = extract_image(image / "zoo-docker.tar", tmp_path / "docker")
    assert meta2["format"] == "docker" and (tmp_path / "docker" / "etc" / "ssl" / "certs" / "pay.crt").exists()


def test_container_collector_reruns_file_collectors(image):
    t = Target("image", str(image / "zoo-oci.tar"), "pay-image", "external", props={"use_theia": False, "use_syft": False})
    fs = ContainerCollector().collect(t, kb)
    assert all(f.location.startswith("image://pay-image/") for f in fs)
    certs = [f for f in fs if f.asset_type == "certificate"]
    assert any(f.props.get("cn") == "pay.zoo.local" for f in certs) and any(f.props.get("expired") for f in certs)
    assert any(f.asset_type == "protocol" and "TLSv1.2" in f.props.get("versions", []) for f in fs)
    assert any(f.asset_type == "library" and f.name == "openssl" and f.props.get("version") == "1.1.1w" for f in fs)
    assert any(f.asset_type == "library" and f.name == "cryptography" for f in fs)
    assert any(f.asset_type == "algorithm" and f.name == "RSA" and f.collector == "source" for f in fs)
    meta = [f for f in fs if f.name == "image:pay-image"][0]
    assert meta.props["image"]["os"] == "linux" and all(f.context.get("container") for f in fs)
