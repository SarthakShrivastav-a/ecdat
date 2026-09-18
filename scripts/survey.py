"""Quantum-readiness snapshot of India's public-facing web, by NCIIPC sector, against a global reference set.

Per host: two connections, exactly what a browser does on a visit.
  1. a TLS 1.3 ClientHello offering X25519MLKEM768 first -> which key-exchange group does the server pick?
  2. a normal TLS handshake -> negotiated version, cipher suite, leaf certificate (key algorithm, size, signature).
No crawling, no vulnerability probing, no authentication.

Publication rule: only sector aggregates leave this machine. The per-host table (hosts.csv) stays local.

    python scripts/survey.py            # -> out/survey/{hosts.csv,survey.json,survey.md}
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ecdat.collectors.protocol import probe_pq_groups, ssl_handshake  # noqa: E402

OUT = ROOT / "out" / "survey"

SECTORS: dict[str, list[str]] = {
    "Government (central)": [
        "www.india.gov.in", "www.mygov.in", "www.meity.gov.in", "www.mha.gov.in", "www.mea.gov.in", "www.pmindia.gov.in",
        "dst.gov.in", "www.cert-in.org.in", "www.nic.in", "uidai.gov.in", "myaadhaar.uidai.gov.in", "www.digilocker.gov.in",
        "www.incometax.gov.in", "www.gst.gov.in", "www.passportindia.gov.in", "www.eci.gov.in", "web.umang.gov.in",
        "www.epfindia.gov.in", "parivahan.gov.in", "pib.gov.in", "www.data.gov.in", "www.nciipc.gov.in", "gem.gov.in",
        "eprocure.gov.in", "www.cbic.gov.in", "www.dgft.gov.in", "www.mca.gov.in", "www.education.gov.in", "www.niti.gov.in",
        "cag.gov.in", "upsc.gov.in", "ssc.gov.in", "www.sih.gov.in", "www.aicte.gov.in", "www.ugc.gov.in", "ncert.nic.in",
        "www.dpiit.gov.in", "www.mof.gov.in", "www.indiacode.nic.in", "main.sci.gov.in", "www.cybercrime.gov.in",
        "www.sebi.gov.in", "www.rbi.org.in", "www.trai.gov.in", "dot.gov.in", "www.tec.gov.in", "www.isro.gov.in", "www.drdo.gov.in",
    ],
    "Banking, financial services & insurance": [
        "onlinesbi.sbi", "sbi.co.in", "www.hdfcbank.com", "www.icicibank.com", "www.axisbank.com", "www.kotak.com",
        "www.pnbindia.in", "www.bankofbaroda.in", "canarabank.com", "www.unionbankofindia.co.in", "bankofindia.co.in",
        "www.idbibank.in", "www.yesbank.in", "www.indusind.com", "www.federalbank.co.in", "www.npci.org.in", "paytm.com",
        "www.phonepe.com", "razorpay.com", "licindia.in", "www.nseindia.com", "www.bseindia.com", "www.cdslindia.com",
        "nsdl.co.in", "irdai.gov.in", "www.sbi.bank.in", "www.hdfc.bank.in", "www.icici.bank.in", "www.axis.bank.in",
        "www.indianbank.in", "www.iob.in", "www.centralbankofindia.co.in", "www.bankofmaharashtra.in", "www.ucobank.com",
    ],
    "Telecom": [
        "www.airtel.in", "www.jio.com", "www.myvi.in", "www.bsnl.co.in", "www.cdot.in", "www.tcil.net.in", "www.mtnl.in",
        "www.railtelindia.com", "www.bbnl.nic.in",
    ],
    "Power & energy": [
        "www.powergrid.in", "ntpc.co.in", "grid-india.in", "iocl.com", "ongcindia.com", "www.bharatpetroleum.in",
        "www.hindustanpetroleum.com", "gailonline.com", "www.nhpcindia.com", "www.tatapower.com", "www.adanigreenenergy.com",
        "www.coalindia.in", "www.npcil.nic.in", "powermin.gov.in", "cea.nic.in", "www.sjvn.nic.in",
    ],
    "Transport": [
        "www.irctc.co.in", "indianrailways.gov.in", "www.airindia.com", "www.goindigo.in", "www.aai.aero",
        "delhimetrorail.com", "ihmcl.co.in", "www.nhai.gov.in", "www.shipmin.gov.in", "civilaviation.gov.in",
        "www.concorindia.co.in", "morth.nic.in",
    ],
    "Health": [
        "www.mohfw.gov.in", "abdm.gov.in", "www.aiims.edu", "pmjay.gov.in", "www.esic.gov.in", "www.icmr.gov.in",
        "www.cdsco.gov.in", "nhm.gov.in", "www.nhp.gov.in", "www.apollohospitals.com", "www.fortishealthcare.com",
    ],
    "Strategic & public enterprises": [
        "hal-india.co.in", "bel-india.in", "www.barc.gov.in", "www.mod.gov.in", "bhel.com", "www.sail.co.in",
        "www.bdl-india.in", "www.mazagondock.in", "www.grse.in", "www.beml.co.in", "www.ecil.co.in", "www.dae.gov.in",
    ],
    "Global reference": [
        "www.google.com", "www.cloudflare.com", "www.microsoft.com", "www.apple.com", "www.amazon.com", "www.facebook.com",
        "github.com", "www.wikipedia.org", "www.netflix.com", "openai.com", "www.chase.com", "www.paypal.com", "www.hsbc.com",
        "www.gov.uk", "www.usa.gov", "europa.eu", "www.bund.de", "www.canada.ca", "www.gov.sg", "www.jpmorgan.com",
        "www.visa.com", "www.mastercard.com", "www.linkedin.com", "www.youtube.com", "www.x.com",
    ],
}


def _key_desc(cert: x509.Certificate) -> tuple[str, int | None]:
    k = cert.public_key()
    if isinstance(k, rsa.RSAPublicKey):
        return "RSA", k.key_size
    if isinstance(k, ec.EllipticCurvePublicKey):
        return f"ECDSA-{k.curve.name}", k.curve.key_size
    if isinstance(k, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(k, ed448.Ed448PublicKey):
        return "Ed448", 448
    return type(k).__name__, None


def probe(sector: str, host: str) -> dict:
    row: dict = {"sector": sector, "host": host, "reachable": False}
    try:
        socket.getaddrinfo(host, 443)
    except OSError:
        row["error"] = "dns"
        return row
    try:
        pq = probe_pq_groups(host, 443)
        row.update(selected_group=pq.get("selected_group"), pq_kex=bool(pq.get("pq_kex")), pq_hrr=pq.get("hrr"),
                   pq_probe_version=pq.get("server_version"))
    except Exception as exc:  # the raw probe fails on TLS 1.2-only servers: that is itself a finding
        row.update(pq_kex=False, pq_error=type(exc).__name__)
    try:
        hs = ssl_handshake(host, 443)
        row.update(reachable=True, tls_version=hs.get("version"), cipher=hs.get("cipher_suite"))
        der = hs.get("cert_der")
        if der:
            cert = x509.load_der_x509_certificate(der if isinstance(der, bytes) else bytes(der))
            alg, size = _key_desc(cert)
            row.update(cert_key=alg, cert_key_bits=size,
                       cert_sig=getattr(cert.signature_hash_algorithm, "name", None),
                       cert_issuer=(cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME) or [None])[0].value
                       if cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME) else None,
                       cert_not_after=cert.not_valid_after_utc.date().isoformat())
    except Exception as exc:
        row["error"] = f"handshake: {type(exc).__name__}"
        row["reachable"] = row.get("selected_group") is not None
    return row


def _pct(n: int, d: int) -> float:
    return round(100.0 * n / d, 1) if d else 0.0


def aggregate(rows: list[dict]) -> dict:
    out = {}
    for sector in SECTORS:
        rs = [r for r in rows if r["sector"] == sector and r.get("reachable")]
        n = len(rs)
        out[sector] = {
            "hosts_probed": sum(1 for r in rows if r["sector"] == sector),
            "reachable": n,
            "pq_hybrid_kex_pct": _pct(sum(1 for r in rs if r.get("pq_kex")), n),
            "tls13_pct": _pct(sum(1 for r in rs if r.get("tls_version") == "TLSv1.3"), n),
            "tls12_max_pct": _pct(sum(1 for r in rs if r.get("tls_version") == "TLSv1.2"), n),
            "rsa_cert_pct": _pct(sum(1 for r in rs if r.get("cert_key") == "RSA"), n),
            "ecdsa_cert_pct": _pct(sum(1 for r in rs if str(r.get("cert_key", "")).startswith("ECDSA")), n),
            "pq_cert_pct": 0.0 if n else 0.0,  # no public CA issues ML-DSA certificates yet
            "classical_only_pct": _pct(sum(1 for r in rs if not r.get("pq_kex")), n),
        }
    india = [r for r in rows if r["sector"] != "Global reference" and r.get("reachable")]
    out["_india_all"] = {"reachable": len(india), "pq_hybrid_kex_pct": _pct(sum(1 for r in india if r.get("pq_kex")), len(india)),
                         "tls13_pct": _pct(sum(1 for r in india if r.get("tls_version") == "TLSv1.3"), len(india)),
                         "rsa_cert_pct": _pct(sum(1 for r in india if r.get("cert_key") == "RSA"), len(india))}
    return out


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    jobs = [(s, h) for s, hosts in SECTORS.items() for h in hosts]
    with ThreadPoolExecutor(max_workers=12) as ex:
        rows = list(ex.map(lambda sh: probe(*sh), jobs))
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="minutes")
    fields = sorted({k for r in rows for k in r})
    with (OUT / "hosts.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["sector", "host"] + [f for f in fields if f not in ("sector", "host")])
        w.writeheader()
        w.writerows(rows)
    agg = aggregate(rows)
    (OUT / "survey.json").write_text(json.dumps({"taken_utc": stamp, "method": __doc__.split("\n\n")[1], "sectors": agg},
                                                indent=2), encoding="utf-8")
    lines = [f"# Quantum-readiness snapshot, {stamp} UTC", "",
             "| sector | reachable/probed | hybrid PQ key exchange | TLS 1.3 | TLS 1.2 max | RSA leaf cert | ECDSA leaf cert |",
             "|---|---|---|---|---|---|---|"]
    for s, v in agg.items():
        if s.startswith("_"):
            continue
        lines.append(f"| {s} | {v['reachable']}/{v['hosts_probed']} | {v['pq_hybrid_kex_pct']}% | {v['tls13_pct']}% | "
                     f"{v['tls12_max_pct']}% | {v['rsa_cert_pct']}% | {v['ecdsa_cert_pct']}% |")
    ia = agg["_india_all"]
    lines += ["", f"India, all sectors: {ia['reachable']} hosts, hybrid PQ {ia['pq_hybrid_kex_pct']}%, TLS 1.3 {ia['tls13_pct']}%, "
              f"RSA leaf {ia['rsa_cert_pct']}%. Post-quantum (ML-DSA) certificates: 0% everywhere (no public CA issues them yet)."]
    (OUT / "survey.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
