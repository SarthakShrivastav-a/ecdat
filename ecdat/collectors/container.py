"""Container collector: docker-save / OCI image tars (or OCI layout dirs) -> merged rootfs -> re-run the file
collectors with an image:// location prefix. crane (optional) pulls remote refs to a tar without a Docker daemon."""
from __future__ import annotations

import gzip
import io
import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from ecdat import tools
from ecdat.collectors.base import Collector, Target
from ecdat.knowledge import KnowledgeBase
from ecdat.model import RawFinding


def _safe_members(tf: tarfile.TarFile):
    for m in tf.getmembers():
        n = m.name.replace("\\", "/")
        if n.startswith("/") or ".." in n.split("/"):
            continue
        yield m


def _extract_layer(layer_bytes: bytes, rootfs: Path) -> None:
    if layer_bytes[:2] == b"\x1f\x8b":
        layer_bytes = gzip.decompress(layer_bytes)
    with tarfile.open(fileobj=io.BytesIO(layer_bytes)) as tf:
        for m in _safe_members(tf):
            name = m.name.replace("\\", "/").lstrip("./")
            if not name:
                continue
            base = name.rsplit("/", 1)[-1]
            parent = rootfs / name.rsplit("/", 1)[0] if "/" in name else rootfs
            if base == ".wh..wh..opq":          # opaque whiteout: clear the directory from lower layers
                if parent.exists():
                    for child in parent.iterdir():
                        shutil.rmtree(child, ignore_errors=True) if child.is_dir() else child.unlink(missing_ok=True)
                continue
            if base.startswith(".wh."):          # whiteout: delete the named entry
                victim = parent / base[4:]
                if victim.is_dir():
                    shutil.rmtree(victim, ignore_errors=True)
                elif victim.exists():
                    victim.unlink()
                continue
            dest = rootfs / name
            if m.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            elif m.isfile():
                dest.parent.mkdir(parents=True, exist_ok=True)
                f = tf.extractfile(m)
                if f is not None:
                    dest.write_bytes(f.read())
            # symlinks / devices are skipped on purpose (Windows + safety)


def extract_image(tar_path: Path, rootfs: Path) -> dict:
    """Returns image metadata {os, architecture, created, layers, tags, format}."""
    meta = {"format": "unknown", "layers": 0}
    with tarfile.open(tar_path) as tf:
        names = {m.name.replace("\\", "/").lstrip("./"): m for m in tf.getmembers()}

        def read(n: str) -> bytes:
            f = tf.extractfile(names[n])
            return f.read() if f else b""

        if "manifest.json" in names:                          # docker save format
            meta["format"] = "docker"
            manifest = json.loads(read("manifest.json"))[0]
            meta["tags"] = manifest.get("RepoTags") or []
            cfg = json.loads(read(manifest["Config"])) if manifest.get("Config") in names else {}
            layers = manifest.get("Layers", [])
        elif "index.json" in names:                           # OCI layout
            meta["format"] = "oci"
            index = json.loads(read("index.json"))
            m0 = index["manifests"][0]
            meta["tags"] = [m0.get("annotations", {}).get("org.opencontainers.image.ref.name", "")]
            manifest = json.loads(read("blobs/" + m0["digest"].replace(":", "/")))
            cfg = json.loads(read("blobs/" + manifest["config"]["digest"].replace(":", "/")))
            layers = ["blobs/" + layer["digest"].replace(":", "/") for layer in manifest["layers"]]
        else:
            raise ValueError("not a docker-save or OCI image tar")
        meta.update({"os": cfg.get("os"), "architecture": cfg.get("architecture"), "created": cfg.get("created"),
                     "env": (cfg.get("config") or {}).get("Env", []), "layers": len(layers)})
        rootfs.mkdir(parents=True, exist_ok=True)
        for layer in layers:
            if layer in names:
                _extract_layer(read(layer), rootfs)
    return meta


class ContainerCollector(Collector):
    name = "container"
    kinds = {"image"}

    def collect(self, target: Target, kb: KnowledgeBase) -> list[RawFinding]:
        from ecdat.collectors.binary import BinaryCollector
        from ecdat.collectors.certificate import CertificateCollector
        from ecdat.collectors.dependency import DependencyCollector
        from ecdat.collectors.source import SourceCollector

        src = Path(target.path)
        tmp = Path(tempfile.mkdtemp(prefix="ecdat-img-"))
        try:
            tar_path = src
            if not src.exists():                      # treat as a registry reference -> crane pull
                exe = tools.find("crane")
                if not exe:
                    return [RawFinding("container", "library", "image-unavailable", target.path, None, "crane not installed",
                                       "low", target.name, {"error": "image reference given but crane is not available"}, {"zone": target.zone})]
                tar_path = tmp / "image.tar"
                r = subprocess.run([str(exe), "pull", target.path, str(tar_path)], capture_output=True, text=True, timeout=900)
                if r.returncode != 0:
                    return [RawFinding("container", "library", "image-unavailable", target.path, None, r.stderr[:200], "low",
                                       target.name, {"error": "crane pull failed"}, {"zone": target.zone})]
            rootfs = tmp / "rootfs"
            if tar_path.is_dir():
                if (tar_path / "index.json").exists():
                    # OCI layout directory: tar it up in memory and reuse the same path
                    buf = io.BytesIO()
                    with tarfile.open(fileobj=buf, mode="w") as tf:
                        tf.add(str(tar_path), arcname=".")
                    tar_path = tmp / "layout.tar"
                    tar_path.write_bytes(buf.getvalue())
                    meta = extract_image(tar_path, rootfs)
                else:
                    shutil.copytree(tar_path, rootfs)
                    meta = {"format": "rootfs-dir", "layers": 0}
            else:
                meta = extract_image(tar_path, rootfs)
            prefix = f"image://{target.name}/"
            sub = Target(kind="dir", path=str(rootfs), name=target.name, zone=target.zone, data_class=target.data_class,
                         criticality=target.criticality, props={**target.props, "location_prefix": prefix})
            out: list[RawFinding] = []
            for coll in (SourceCollector(), DependencyCollector(), CertificateCollector(), BinaryCollector()):
                try:
                    fs = coll.collect(sub, kb)
                except Exception as exc:  # one broken collector must not sink the image scan
                    fs = [RawFinding("container", "library", f"{coll.name}-error", prefix, None, str(exc)[:200], "low",
                                     target.name, {"error": str(exc)[:200]}, {"zone": target.zone})]
                for f in fs:
                    f.context["container"] = True
                    f.context["image"] = meta.get("tags") or [target.name]
                out += fs
            out.append(RawFinding("container", "library", f"image:{target.name}", prefix, None,
                                  f"{meta.get('format')} image, {meta.get('layers')} layers, {meta.get('os')}/{meta.get('architecture')}",
                                  "high", target.name, {"api": "image-metadata", "image": meta, "ecosystem": "container", "provides": []},
                                  {"zone": target.zone, "container": True}))
            return out
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
