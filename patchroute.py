#!/usr/bin/env python3
"""
patchroute - single-file vulnerability scanner with risk-based enrichment.

Matches an inventory of installed software against public vulnerability
databases, enriches every finding with EPSS, CISA KEV and MITRE ATT&CK,
triages false positives, produces step-by-step remediation, and writes a
self-contained HTML report.

    python patchroute.py --demo -o report.html                 # offline sample
    python patchroute.py --input inventory.xlsx -o report.html
    python patchroute.py --input ./inventories/ -o report.html
    python patchroute.py --host -o report.html
    python patchroute.py --selftest

Inventory formats: txt, csv/tsv, xlsx/xlsm, docx, pdf, JSON (plain, CycloneDX,
SPDX, Syft), XML (CycloneDX, pom), YAML, and lockfiles/manifests.

Requires Python 3.9+ and NOTHING ELSE. Optional extras improve things but are
never required: openpyxl / python-docx (more robust Office parsing),
pdfplumber or pypdf (PDF input), PyYAML (YAML input).

This is a DEFENSIVE tool: it identifies and ranks known vulnerabilities so they
can be fixed. It does not exploit anything.

Data sources: OSV.dev - NVD - FIRST.org EPSS - CISA KEV - MITRE ATT&CK
License: MIT
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# ==========================================================================
# DATA MODEL
# ==========================================================================
@dataclass
class Package:
    """A piece of software found in the inventory."""
    name: str
    version: str
    ecosystem: str = "generic"      # PyPI, npm, Debian, RPM, generic
    cpe: Optional[str] = None       # optional CPE 2.3 string
    source: str = "input"           # how it was discovered

    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}:{self.version}".lower()


@dataclass
class Remediation:
    """Concrete, actionable steps to fix (or contain) a finding."""
    action: str = "review"          # upgrade | mitigate | monitor | verify | review
    headline: str = ""              # "Upgrade django 2.2.0 -> 2.2.4"
    target_version: str = ""        # candidate published fixed version
    commands: list[str] = field(default_factory=list)   # copy-paste fix commands
    steps: list[str] = field(default_factory=list)      # ordered human steps
    mitigations: list[str] = field(default_factory=list)  # compensating controls
    verification: str = ""          # how to confirm the fix landed
    due_date: str = ""              # remediation deadline (KEV or SLA derived)
    due_reason: str = ""            # why that deadline
    effort: str = ""                # patch | minor | major | unknown
    effort_note: str = ""           # breaking-change warning


@dataclass
class Finding:
    """A single vulnerability matched against a package, plus enrichment."""
    cve: str
    package: Package
    summary: str = ""
    cvss_score: Optional[float] = None
    cvss_severity: str = "UNKNOWN"          # CRITICAL/HIGH/MEDIUM/LOW/NONE
    cvss_vector: str = ""
    cwe: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    # enrichment
    epss_score: Optional[float] = None      # 0..1 probability of exploitation
    epss_percentile: Optional[float] = None
    kev: bool = False                       # in CISA KEV catalog
    kev_due_date: str = ""
    kev_ransomware: str = ""
    attack_techniques: list[dict] = field(default_factory=list)  # {id,name,tactic}

    # false-positive handling
    confidence: float = 1.0                 # 0..1 match confidence
    fp_flags: list[str] = field(default_factory=list)  # reasons it may be an FP
    suppressed: bool = False
    suppress_reason: str = ""

    # derived
    priority_score: float = 0.0
    priority_label: str = ""
    remediation: Optional[Remediation] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class ScanHealth:
    """Coverage problems must never be mistaken for a clean scan."""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    feeds: dict[str, str] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return not self.errors


def normalize_severity(score: Optional[float]) -> str:
    """CVSS v3 qualitative bands."""
    if score is None:
        return "UNKNOWN"
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"

# ==========================================================================
# INVENTORY PARSERS  (txt, csv, xlsx, docx, pdf, SBOM, lockfiles)
# ==========================================================================
# ---------------------------------------------------------------------------
# safety limits when opening untrusted archives
MAX_MEMBERS = 2000
MAX_MEMBER_BYTES = 80 * 1024 * 1024      # 80 MB uncompressed per member
MAX_TOTAL_BYTES = 400 * 1024 * 1024      # 400 MB uncompressed total

# ---------------------------------------------------------------------------
# ecosystem handling
ECO_ALIASES = {
    "pypi": "PyPI", "pip": "PyPI", "python": "PyPI",
    "npm": "npm", "node": "npm", "nodejs": "npm",
    "debian": "Debian", "deb": "Debian", "dpkg": "Debian", "apt": "Debian",
    "ubuntu": "Ubuntu",
    "rpm": "Red Hat", "redhat": "Red Hat", "rhel": "Red Hat",
    "yum": "Red Hat", "dnf": "Red Hat", "centos": "Red Hat",
    "alpine": "Alpine", "apk": "Alpine",
    "go": "Go", "golang": "Go",
    "cargo": "crates.io", "rust": "crates.io", "crates.io": "crates.io",
    "maven": "Maven", "java": "Maven",
    "gem": "RubyGems", "ruby": "RubyGems", "rubygems": "RubyGems",
    "nuget": "NuGet", "dotnet": "NuGet", ".net": "NuGet",
    "composer": "Packagist", "php": "Packagist", "packagist": "Packagist",
    "hex": "Hex", "pub": "Pub", "conan": "ConanCenter",
    "generic": "generic",
}

# purl type -> OSV ecosystem
PURL_ECO = {
    "pypi": "PyPI", "npm": "npm", "deb": "Debian", "rpm": "Red Hat",
    "apk": "Alpine", "golang": "Go", "maven": "Maven", "cargo": "crates.io",
    "gem": "RubyGems", "nuget": "NuGet", "composer": "Packagist",
    "hex": "Hex", "pub": "Pub", "conan": "ConanCenter",
}

# filename -> ecosystem hint
FILE_ECO_HINT = {
    "requirements.txt": "PyPI", "requirements-dev.txt": "PyPI",
    "constraints.txt": "PyPI", "pipfile.lock": "PyPI", "poetry.lock": "PyPI",
    "package-lock.json": "npm", "yarn.lock": "npm", "npm-shrinkwrap.json": "npm",
    "cargo.lock": "crates.io", "composer.lock": "Packagist",
    "gemfile.lock": "RubyGems", "go.mod": "Go", "go.sum": "Go",
    "pom.xml": "Maven", "packages.lock.json": "NuGet",
}


def normalize_ecosystem(eco: str | None, default: str = "generic") -> str:
    if not eco:
        return default
    key = str(eco).strip().lower()
    return ECO_ALIASES.get(key, eco if eco else default)


def eco_from_purl(purl: str) -> tuple[str | None, str | None, str | None]:
    """`pkg:pypi/django@2.2.0` -> ('PyPI', 'django', '2.2.0')."""
    if not purl or not purl.startswith("pkg:"):
        return None, None, None
    body = purl[4:]
    ptype, _, rest = body.partition("/")
    if not rest:
        return None, None, None
    rest = rest.split("?")[0].split("#")[0]
    name, _, version = rest.rpartition("@")
    if not name:                       # no @version present
        name, version = rest, ""
    # namespaced names: @scope/pkg (npm), group/artifact (maven)
    name = name.strip("/")
    if ptype.lower() == "maven":
        name = name.replace("/", ":")
    elif "/" in name and ptype.lower() == "npm":
        name = "@" + name if not name.startswith("@") else name
    return PURL_ECO.get(ptype.lower()), name or None, version or None


# ---------------------------------------------------------------------------
# validation helpers
_VERSION_RE = re.compile(r"^v?\d[\w.\-+~:]*$", re.I)
_NAME_RE = re.compile(r"^[@A-Za-z0-9][\w.\-+/@:]{0,120}$")
_HEADER_WORDS = {
    "name", "package", "packages", "component", "library", "product",
    "version", "versions", "ver", "ecosystem", "type", "cpe", "purl",
    "description", "license", "vendor", "notes", "n/a", "total", "software",
}


def looks_like_version(s: str) -> bool:
    s = (s or "").strip()
    return bool(s) and len(s) <= 60 and bool(_VERSION_RE.match(s))


def looks_like_name(s: str) -> bool:
    s = (s or "").strip()
    if not s or s.lower() in _HEADER_WORDS:
        return False
    return bool(_NAME_RE.match(s)) and not looks_like_version(s)


def mk(name: str, version: str, eco: str | None, default_eco: str,
       source: str, cpe: str | None = None) -> Package | None:
    name = (name or "").strip().strip('"\'')
    version = (version or "").strip().strip('"\'').lstrip("vV") \
        if version and re.match(r"^v\d", version or "", re.I) else (version or "").strip().strip('"\'')
    if not looks_like_name(name):
        return None
    if version and not looks_like_version(version):
        version = ""
    return Package(name=name, version=version,
                   ecosystem=normalize_ecosystem(eco, default_eco),
                   cpe=cpe, source=source)


# ---------------------------------------------------------------------------
# 1. free-text line heuristics  (txt, md, log, console dumps, fallback)
# ---------------------------------------------------------------------------
_SKIP_LINE = re.compile(
    r"^\s*(#|//|--|\*|;|desired=|\|\s*status|\+\+\+|===|---)", re.I)

_PATTERNS: list[tuple[re.Pattern, str]] = [
    # dpkg -l :  ii  name  1.2.3-4  amd64  description
    (re.compile(r"^[a-z]{2}\s+(?P<name>[\w.+\-]+)(?::\w+)?\s+(?P<version>\S+)\s+\S+"), "Debian"),
    # pip freeze / pinned requirements: ranges are not installed versions.
    (re.compile(r"^(?P<name>[A-Za-z0-9._\-\[\]]+)\s*==\s*(?P<version>[\w.\-+!]+)"), ""),
    # npm:  @scope/name@1.2.3  or  name@1.2.3
    (re.compile(r"^(?P<name>@?[\w.\-]+(?:/[\w.\-]+)?)@(?P<version>\d[\w.\-+]*)$"), "npm"),
    # rpm -qa:  name-1.2.3-4.el8.x86_64
    (re.compile(r"^(?P<name>[A-Za-z][\w.+\-]*?)-(?P<version>\d[\w.]*-[\w.]+)\.(?:x86_64|noarch|i686|aarch64|armv7hl)$"), "Red Hat"),
    # name (1.2.3)
    (re.compile(r"^(?P<name>[\w.@/\-+]+)\s*\((?P<version>[\w.\-+]+)\)"), ""),
    # name: 1.2.3   /   name : 1.2.3
    (re.compile(r"^(?P<name>[\w.@/\-+]+)\s*:\s*(?P<version>\d[\w.\-+]*)$"), ""),
    # name, 1.2.3  /  name | 1.2.3  /  name<TAB>1.2.3  /  name 1.2.3
    (re.compile(r"^(?P<name>[\w.@/\-+]+)\s*[,|\t]\s*(?P<version>\d[\w.\-+]*)"), ""),
    (re.compile(r"^(?P<name>[\w.@/\-+]+)\s+(?P<version>\d[\w.\-+]*)\s*$"), ""),
    # name-1.2.3  (tarball / directory style) - last resort
    (re.compile(r"^(?P<name>[A-Za-z][\w.+]*(?:-[A-Za-z][\w.+]*)*)-(?P<version>\d[\w.]*)$"), ""),
]


def parse_text_lines(text: str, default_eco: str, source: str) -> list[Package]:
    out: list[Package] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or len(line) > 400 or _SKIP_LINE.match(line):
            continue
        line = line.rstrip(",;")
        for pattern, eco_hint in _PATTERNS:
            m = pattern.match(line)
            if not m:
                continue
            p = mk(m.group("name"), m.group("version"),
                   eco_hint or None, default_eco, source)
            if p:
                out.append(p)
            break
    return out


# ---------------------------------------------------------------------------
# 2. tabular helpers (shared by csv / xlsx / docx tables)
# ---------------------------------------------------------------------------
def _find_header(rows: list[list[str]]) -> tuple[int, dict[str, int]] | None:
    """Locate a header row containing a name-ish and version-ish column."""
    name_keys = {"name", "package", "packages", "component", "library",
                 "product", "software", "artifact", "dependency"}
    ver_keys = {"version", "ver", "versions", "installed", "installed version",
                "current version"}
    eco_keys = {"ecosystem", "type", "platform", "language", "repo",
                "repository", "package type", "source"}
    for idx, row in enumerate(rows[:25]):
        cells = [str(c or "").strip().lower() for c in row]
        cmap: dict[str, int] = {}
        for i, c in enumerate(cells):
            if c in name_keys and "name" not in cmap:
                cmap["name"] = i
            elif c in ver_keys and "version" not in cmap:
                cmap["version"] = i
            elif c in eco_keys and "ecosystem" not in cmap:
                cmap["ecosystem"] = i
            elif c == "purl" and "purl" not in cmap:
                cmap["purl"] = i
            elif c == "cpe" and "cpe" not in cmap:
                cmap["cpe"] = i
        if "name" in cmap and ("version" in cmap or "purl" in cmap):
            return idx, cmap
    return None


def parse_rows(rows: list[list[str]], default_eco: str,
               source: str) -> list[Package]:
    """Turn a 2-D grid into packages: use headers if present, else heuristics."""
    rows = [r for r in rows if any(str(c or "").strip() for c in r)]
    if not rows:
        return []

    out: list[Package] = []
    found = _find_header(rows)

    if found:
        hdr_idx, cmap = found
        for row in rows[hdr_idx + 1:]:
            get = lambda k: (str(row[cmap[k]]).strip()
                             if k in cmap and cmap[k] < len(row) and row[cmap[k]] is not None
                             else "")
            if "purl" in cmap and get("purl"):
                eco, nm, ver = eco_from_purl(get("purl"))
                p = mk(nm or get("name"), ver or get("version"), eco,
                       default_eco, source, get("cpe") or None)
            else:
                p = mk(get("name"), get("version"),
                       get("ecosystem") or None, default_eco, source,
                       get("cpe") or None)
            if p:
                out.append(p)
        if out:
            return out

    # no usable header: scan each row for a name cell + version cell pair
    for row in rows:
        cells = [str(c).strip() for c in row if str(c or "").strip()]
        if not cells:
            continue
        name = next((c for c in cells if looks_like_name(c)), None)
        version = next((c for c in cells if looks_like_version(c)), None)
        if name and version:
            eco = next((c for c in cells
                        if c.lower() in ECO_ALIASES and c.lower() != "generic"), None)
            p = mk(name, version, eco, default_eco, source)
            if p:
                out.append(p)
        elif len(cells) == 1:
            out.extend(parse_text_lines(cells[0], default_eco, source))
    return out


# ---------------------------------------------------------------------------
# 3. CSV / TSV
# ---------------------------------------------------------------------------
def parse_csv(text: str, default_eco: str, source: str,
              delimiter: str | None = None) -> list[Package]:
    if delimiter is None:
        sample = "\n".join(text.splitlines()[:20])
        try:
            delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
        except csv.Error:
            delimiter = ","
    rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
    return parse_rows(rows, default_eco, source)


# ---------------------------------------------------------------------------
# 4. JSON  (plain / CycloneDX / SPDX / Syft / lockfiles)
# ---------------------------------------------------------------------------
def parse_json(text: str, default_eco: str, source: str) -> list[Package]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return parse_text_lines(text, default_eco, source)

    # Pipfile.lock has top-level default/develop sections, not packages.
    if isinstance(data, dict) and ("_meta" in data or
                                   ("default" in data and "develop" in data)):
        out = []
        for section in ("default", "develop"):
            for name, meta in (data.get(section) or {}).items():
                if not isinstance(meta, dict):
                    continue
                version = str(meta.get("version", ""))
                if version.startswith("=="):
                    version = version[2:]
                p = mk(name, version, "PyPI", default_eco, source)
                if p:
                    out.append(p)
        return out

    # CycloneDX
    if isinstance(data, dict) and (data.get("bomFormat") == "CycloneDX"
                                   or "components" in data):
        out = []
        def walk(comps):
            for c in comps or []:
                if not isinstance(c, dict):
                    continue
                eco, nm, ver = eco_from_purl(c.get("purl", ""))
                p = mk(nm or c.get("name", ""), ver or c.get("version", ""),
                       eco or c.get("type"), default_eco, source + " (CycloneDX)",
                       c.get("cpe"))
                if p:
                    out.append(p)
                walk(c.get("components"))
        walk(data.get("components"))
        if out:
            return out

    # SPDX
    if isinstance(data, dict) and ("spdxVersion" in data or "SPDXID" in data):
        out = []
        for pkg in data.get("packages", []):
            purl = ""
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator", "")
                    break
            eco, nm, ver = eco_from_purl(purl)
            p = mk(nm or pkg.get("name", ""),
                   ver or pkg.get("versionInfo", ""),
                   eco, default_eco, source + " (SPDX)")
            if p:
                out.append(p)
        if out:
            return out

    # Syft native
    if isinstance(data, dict) and "artifacts" in data:
        out = []
        for a in data.get("artifacts", []):
            eco, nm, ver = eco_from_purl(a.get("purl", ""))
            p = mk(nm or a.get("name", ""), ver or a.get("version", ""),
                   eco or a.get("type"), default_eco, source + " (Syft)")
            if p:
                out.append(p)
        if out:
            return out

    # npm package-lock v2/v3 ("packages") and v1 ("dependencies")
    if isinstance(data, dict) and ("lockfileVersion" in data
                                   or "packages" in data or "dependencies" in data):
        out = []
        pkgs = data.get("packages")
        if isinstance(pkgs, dict) and any("node_modules" in k for k in pkgs):
            for path, meta in pkgs.items():
                if not path or not isinstance(meta, dict):
                    continue
                name = path.split("node_modules/")[-1]
                p = mk(name, meta.get("version", ""), "npm", default_eco,
                       source + " (package-lock)")
                if p:
                    out.append(p)
        def walk_deps(d):
            for name, meta in (d or {}).items():
                if isinstance(meta, dict):
                    p = mk(name, meta.get("version", ""), "npm", default_eco,
                           source + " (package-lock)")
                    if p:
                        out.append(p)
                    walk_deps(meta.get("dependencies"))
        if not out:
            walk_deps(data.get("dependencies"))
        if out:
            return out

    # plain {"packages":[...]} or a bare list
    rows = data.get("packages", data) if isinstance(data, dict) else data
    if isinstance(rows, list):
        out = []
        for r in rows:
            if isinstance(r, dict):
                eco, nm, ver = eco_from_purl(r.get("purl", ""))
                p = mk(nm or r.get("name") or r.get("package", ""),
                       ver or str(r.get("version", "")),
                       eco or r.get("ecosystem") or r.get("type"),
                       default_eco, source, r.get("cpe"))
                if p:
                    out.append(p)
            elif isinstance(r, str):
                out.extend(parse_text_lines(r, default_eco, source))
        if out:
            return out
    return []


def parse_poetry_lock(text: str, source: str) -> list[Package]:
    """Read package records without requiring tomllib (Python 3.9 compatible)."""
    out = []
    for block in re.split(r"(?m)^\s*\[\[package\]\]\s*$", text)[1:]:
        name = re.search(r'(?m)^name\s*=\s*["\']([^"\']+)["\']', block)
        version = re.search(r'(?m)^version\s*=\s*["\']([^"\']+)["\']', block)
        if name and version:
            p = mk(name.group(1), version.group(1), "PyPI", "PyPI", source)
            if p:
                out.append(p)
    return out


# ---------------------------------------------------------------------------
# 5. XML  (CycloneDX XML, pom.xml, generic)
# ---------------------------------------------------------------------------
def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_xml(text: str, default_eco: str, source: str) -> list[Package]:
    try:
        root = ET.fromstring(text)              # no entity expansion by default
    except ET.ParseError:
        return parse_text_lines(text, default_eco, source)

    out: list[Package] = []

    # CycloneDX XML: <component><name/><version/><purl/></component>
    for el in root.iter():
        if _localname(el.tag) not in ("component", "dependency", "package"):
            continue
        vals = {}
        for child in el:
            ln = _localname(child.tag)
            if ln in ("name", "version", "purl", "artifactid", "groupid", "cpe"):
                vals[ln] = (child.text or "").strip()
        if vals.get("purl"):
            eco, nm, ver = eco_from_purl(vals["purl"])
            p = mk(nm or vals.get("name", ""), ver or vals.get("version", ""),
                   eco, default_eco, source, vals.get("cpe"))
        elif vals.get("artifactid"):            # Maven pom.xml
            name = vals["artifactid"]
            if vals.get("groupid"):
                name = f"{vals['groupid']}:{name}"
            p = mk(name, vals.get("version", ""), "Maven", default_eco, source)
        else:
            p = mk(vals.get("name", ""), vals.get("version", ""),
                   None, default_eco, source, vals.get("cpe"))
        if p:
            out.append(p)
    return out


# ---------------------------------------------------------------------------
# 6. XLSX / XLSM   (stdlib zip+xml, or openpyxl when installed)
# ---------------------------------------------------------------------------
_SS_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def _col_index(ref: str) -> int:
    """'BC12' -> 54 (0-based column)."""
    letters = "".join(ch for ch in ref if ch.isalpha()).upper()
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return max(n - 1, 0)


def _safe_zip(path: Path) -> zipfile.ZipFile:
    zf = zipfile.ZipFile(path)
    infos = zf.infolist()
    if len(infos) > MAX_MEMBERS:
        zf.close()
        raise ValueError(f"archive has too many members ({len(infos)})")
    total = sum(i.file_size for i in infos)
    if total > MAX_TOTAL_BYTES:
        zf.close()
        raise ValueError("archive uncompressed size exceeds limit")
    return zf


def _read_member(zf: zipfile.ZipFile, name: str) -> str:
    try:
        info = zf.getinfo(name)
    except KeyError:
        return ""
    if info.file_size > MAX_MEMBER_BYTES:
        raise ValueError(f"{name} exceeds size limit")
    return zf.read(name).decode("utf-8", errors="replace")


def _xlsx_stdlib(path: Path, default_eco: str, source: str) -> list[Package]:
    with _safe_zip(path) as zf:
        names = zf.namelist()

        shared: list[str] = []
        if "xl/sharedStrings.xml" in names:
            root = ET.fromstring(_read_member(zf, "xl/sharedStrings.xml"))
            for si in root:
                shared.append("".join(t.text or "" for t in si.iter(f"{_SS_NS}t")))

        sheets = sorted(n for n in names
                        if n.startswith("xl/worksheets/") and n.endswith(".xml"))
        all_rows: list[list[str]] = []
        for sheet in sheets:
            xml = _read_member(zf, sheet)
            if not xml:
                continue
            root = ET.fromstring(xml)
            for row_el in root.iter(f"{_SS_NS}row"):
                row: list[str] = []
                for c in row_el.iter(f"{_SS_NS}c"):
                    idx = _col_index(c.get("r", "")) if c.get("r") else len(row)
                    ctype = c.get("t", "")
                    val = ""
                    if ctype == "s":
                        v = c.find(f"{_SS_NS}v")
                        if v is not None and (v.text or "").isdigit():
                            i = int(v.text)
                            val = shared[i] if i < len(shared) else ""
                    elif ctype == "inlineStr":
                        val = "".join(t.text or "" for t in c.iter(f"{_SS_NS}t"))
                    else:
                        v = c.find(f"{_SS_NS}v")
                        val = (v.text or "") if v is not None else ""
                    while len(row) <= idx:
                        row.append("")
                    row[idx] = val.strip()
                if row:
                    all_rows.append(row)
    return parse_rows(all_rows, default_eco, source)


def parse_xlsx(path: Path, default_eco: str, source: str) -> list[Package]:
    try:
        import openpyxl                                   # optional
        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        rows: list[list[str]] = []
        for ws in wb.worksheets:
            for row in ws.iter_rows(values_only=True):
                rows.append(["" if c is None else str(c) for c in row])
        wb.close()
        pkgs = parse_rows(rows, default_eco, source)
        if pkgs:
            return pkgs
    except ImportError:
        pass
    except Exception:
        pass
    return _xlsx_stdlib(path, default_eco, source)


# ---------------------------------------------------------------------------
# 7. DOCX   (stdlib zip+xml, or python-docx when installed)
# ---------------------------------------------------------------------------
_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _docx_stdlib(path: Path, default_eco: str, source: str) -> list[Package]:
    with _safe_zip(path) as zf:
        parts = [n for n in zf.namelist()
                 if n in ("word/document.xml",)
                 or n.startswith("word/header") or n.startswith("word/footer")]
        rows: list[list[str]] = []
        paragraphs: list[str] = []
        for part in parts:
            xml = _read_member(zf, part)
            if not xml:
                continue
            root = ET.fromstring(xml)

            # tables first: each w:tbl -> rows of cell text
            for tbl in root.iter(f"{_W_NS}tbl"):
                for tr in tbl.iter(f"{_W_NS}tr"):
                    cells = []
                    for tc in tr.iter(f"{_W_NS}tc"):
                        text = "".join(t.text or "" for t in tc.iter(f"{_W_NS}t"))
                        cells.append(text.strip())
                    if cells:
                        rows.append(cells)

            # then loose paragraphs (skip ones already inside tables)
            table_para_ids = {id(p) for tbl in root.iter(f"{_W_NS}tbl")
                              for p in tbl.iter(f"{_W_NS}p")}
            for p in root.iter(f"{_W_NS}p"):
                if id(p) in table_para_ids:
                    continue
                text = "".join(t.text or "" for t in p.iter(f"{_W_NS}t")).strip()
                if text:
                    paragraphs.append(text)

    out = parse_rows(rows, default_eco, source) if rows else []
    out.extend(parse_text_lines("\n".join(paragraphs), default_eco, source))
    return out


def parse_docx(path: Path, default_eco: str, source: str) -> list[Package]:
    try:
        import docx                                        # optional
        d = docx.Document(str(path))
        rows = [[c.text.strip() for c in r.cells] for t in d.tables for r in t.rows]
        paras = "\n".join(p.text for p in d.paragraphs if p.text.strip())
        out = parse_rows(rows, default_eco, source) if rows else []
        out.extend(parse_text_lines(paras, default_eco, source))
        if out:
            return out
    except ImportError:
        pass
    except Exception:
        pass
    return _docx_stdlib(path, default_eco, source)


# ---------------------------------------------------------------------------
# 8. PDF  (optional dependency; degrades with a clear message)
# ---------------------------------------------------------------------------
def parse_pdf(path: Path, default_eco: str, source: str) -> list[Package]:
    text = ""
    try:
        import pdfplumber                                  # optional, best tables
        with pdfplumber.open(str(path)) as pdf:
            rows: list[list[str]] = []
            chunks = []
            for page in pdf.pages:
                for table in page.extract_tables() or []:
                    for row in table:
                        rows.append(["" if c is None else str(c).strip() for c in row])
                chunks.append(page.extract_text() or "")
            text = "\n".join(chunks)
            out = parse_rows(rows, default_eco, source) if rows else []
            out.extend(parse_text_lines(text, default_eco, source))
            return out
    except ImportError:
        pass
    except Exception:
        pass

    try:
        from pypdf import PdfReader                         # optional fallback
        reader = PdfReader(str(path))
        text = "\n".join(pg.extract_text() or "" for pg in reader.pages)
    except ImportError:
        raise RuntimeError(
            "PDF input needs an extra library. Install one of:\n"
            "    pip install pdfplumber      (best: reads tables)\n"
            "    pip install pypdf           (lighter: text only)\n"
            "Or export the inventory to .csv/.xlsx/.txt instead.")
    except Exception as e:
        raise RuntimeError(f"could not read PDF: {e}")
    return parse_text_lines(text, default_eco, source)


# ---------------------------------------------------------------------------
# 9. dispatcher
# ---------------------------------------------------------------------------
TEXT_SUFFIXES = {".txt", ".md", ".log", ".list", ".lock", ".cfg", ".ini",
                 ".conf", ".out", ".dat", ""}


def parse_file(path: str | Path, default_eco: str = "generic",
               verbose: bool = False) -> list[Package]:
    """Parse any supported inventory file into a package list."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    if p.is_dir():
        raise IsADirectoryError(str(p))

    suffix = p.suffix.lower()
    lname = p.name.lower()
    source = p.name

    # filename-based ecosystem hint wins over the generic default
    eco = FILE_ECO_HINT.get(lname, default_eco)

    # binary / container formats
    if suffix in (".xlsx", ".xlsm", ".xltx"):
        return parse_xlsx(p, eco, source)
    if suffix in (".docx", ".dotx", ".docm"):
        return parse_docx(p, eco, source)
    if suffix == ".pdf":
        return parse_pdf(p, eco, source)
    if suffix in (".xls", ".doc"):
        raise RuntimeError(
            f"{suffix} is the legacy binary Office format. Re-save it as "
            f"{'.xlsx' if suffix == '.xls' else '.docx'} (or export to .csv) "
            "and scan that.")

    # text-ish formats
    raw = p.read_bytes()
    if b"\x00" in raw[:4096]:
        raise RuntimeError(f"{p.name} looks like a binary file, not an inventory")
    text = raw.decode("utf-8", errors="replace")
    if lname.startswith("requirements") or lname == "constraints.txt":
        if re.search(r"(?m)^\s*[A-Za-z0-9._\-\[\]]+\s*(?:>=|<=|~=|!=|>|<)\s*\S+", text):
            raise RuntimeError("un-pinned requirement is not an installed version; supply pip freeze or an SBOM")

    if lname == "poetry.lock":
        return parse_poetry_lock(text, source)
    if lname in {"cargo.lock", "gemfile.lock", "yarn.lock", "go.mod", "go.sum",
                 "composer.lock", "packages.lock.json"}:
        raise RuntimeError(f"{p.name} is not supported by this parser; supply an SBOM or CSV instead")

    if suffix == ".json":
        return parse_json(text, eco, source)
    if suffix in (".xml", ".pom", ".nuspec", ".csproj"):
        return parse_xml(text, eco, source)
    if suffix in (".csv", ".tsv"):
        return parse_csv(text, eco, source,
                         delimiter="\t" if suffix == ".tsv" else None)
    if suffix in (".yaml", ".yml"):
        try:
            import yaml                                    # optional
            data = yaml.safe_load(text)
            return parse_json(json.dumps(data), eco, source)
        except ImportError:
            return parse_text_lines(text, eco, source)
        except Exception:
            return parse_text_lines(text, eco, source)

    # unknown / plain text: try JSON, then CSV if it looks delimited, then lines
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        pkgs = parse_json(text, eco, source)
        if pkgs:
            return pkgs
    head = "\n".join(text.splitlines()[:20])
    if head.count(",") >= 2 or head.count("\t") >= 2 or head.count("|") >= 2:
        pkgs = parse_csv(text, eco, source)
        if pkgs:
            return pkgs
    return parse_text_lines(text, eco, source)


SUPPORTED_HELP = (
    ".json (plain/CycloneDX/SPDX/Syft/npm/Pipfile), .csv, .tsv, .xlsx, .xlsm, "
    ".docx, .pdf, .xml (CycloneDX/pom), .yaml, .txt/.md/.log and manifests "
    "(requirements.txt, package-lock.json, Pipfile.lock, poetry.lock)"
)


def parse_path(path: str | Path, default_eco: str = "generic",
               recursive: bool = True, verbose: bool = False
               ) -> tuple[list[Package], list[str]]:
    """Parse a file, or every recognisable inventory file in a directory.

    Returns (packages, notes) where notes records per-file outcomes so the
    report and console can show what was actually read.
    """
    p = Path(path)
    notes: list[str] = []
    out: list[Package] = []

    if p.is_dir():
        candidates = []
        walker = p.rglob("*") if recursive else p.glob("*")
        for f in sorted(walker):
            if not f.is_file() or f.name.startswith("."):
                continue
            if any(part in {"node_modules", ".git", "__pycache__", "venv",
                            ".venv", "dist", "build"} for part in f.parts):
                continue
            if (f.suffix.lower() in {".json", ".csv", ".tsv", ".xlsx", ".xlsm",
                                     ".docx", ".pdf", ".xml", ".txt", ".yaml",
                                     ".yml", ".md", ".lock"}
                    or f.name.lower() in FILE_ECO_HINT):
                candidates.append(f)
        if not candidates:
            notes.append(f"{p}: no recognisable inventory files found")
        for f in candidates:
            try:
                pkgs = parse_file(f, default_eco, verbose)
                out.extend(pkgs)
                notes.append(f"{f.name}: {len(pkgs)} packages")
            except Exception as e:
                notes.append(f"{f.name}: skipped ({e})")
        return out, notes

    pkgs = parse_file(p, default_eco, verbose)
    notes.append(f"{p.name}: {len(pkgs)} packages")
    return pkgs, notes

# ==========================================================================
# INVENTORY COLLECTION  (files + live host)
# ==========================================================================
# ----- file input --------------------------------------------------------------
def from_file(path: str, default_ecosystem: str = "generic") -> list[Package]:
    """Parse a single inventory file of any supported format."""
    return parse_file(path, default_ecosystem)


def from_path(path: str, default_ecosystem: str = "generic",
              recursive: bool = True) -> tuple[list[Package], list[str]]:
    """Parse a file, or every recognisable inventory file in a directory."""
    return parse_path(path, default_ecosystem, recursive)


# ----- live host collectors ----------------------------------------------------
def _run(cmd: list[str]) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return res.stdout
    except (subprocess.SubprocessError, OSError):
        return ""


def _collect_dpkg() -> list[Package]:
    if not shutil.which("dpkg-query"):
        return []
    out = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    pkgs = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, ver = line.split("\t", 1)
        # strip Debian epoch/revision noise for cleaner matching
        pkgs.append(Package(name.strip(), ver.strip(), "Debian", source="dpkg"))
    return pkgs


def _collect_rpm() -> list[Package]:
    if not shutil.which("rpm"):
        return []
    out = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
    pkgs = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, ver = line.split("\t", 1)
        pkgs.append(Package(name.strip(), ver.strip(), "Red Hat", source="rpm"))
    return pkgs


def _collect_pip() -> list[Package]:
    if not shutil.which("pip") and not shutil.which("pip3"):
        return []
    exe = "pip3" if shutil.which("pip3") else "pip"
    out = _run([exe, "list", "--format=json"])
    if not out:
        return []
    try:
        rows = json.loads(out)
    except json.JSONDecodeError:
        return []
    return [Package(r["name"], r.get("version", ""), "PyPI", source="pip") for r in rows]


def _collect_npm() -> list[Package]:
    if not shutil.which("npm"):
        return []
    out = _run(["npm", "ls", "-g", "--json", "--depth=0"])
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    deps = data.get("dependencies", {})
    return [Package(n, (v.get("version") or ""), "npm", source="npm")
            for n, v in deps.items()]


def from_host() -> list[Package]:
    """Auto-detect and collect from every available package manager."""
    pkgs: list[Package] = []
    for collector in (_collect_dpkg, _collect_rpm, _collect_pip, _collect_npm):
        pkgs.extend(collector())
    return pkgs


def dedupe(packages: list[Package]) -> list[Package]:
    seen = {}
    for p in packages:
        if p.name and p.key() not in seen:
            seen[p.key()] = p
    return list(seen.values())

# ==========================================================================
# VULNERABILITY SOURCES  (OSV.dev, NVD)
# ==========================================================================
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

VERSION = "0.1.0"
USER_AGENT = f"patchroute/{VERSION} (+defensive-security-tool)"


def _post_json(url: str, payload: dict, timeout: int = 45) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _get_json(url: str, timeout: int = 45, api_key: str | None = None) -> dict:
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


# ----- OSV --------------------------------------------------------------------
def osv_query(packages: list[Package], verbose: bool = False,
              health: ScanHealth | None = None) -> dict[str, list[str]]:
    """Return {package.key(): [vuln_id, ...]} using the OSV batch endpoint."""
    queries = []
    index = []
    for p in packages:
        if not p.version:
            if health:
                health.errors.append(f"OSV skipped {p.key()}: missing version")
            continue
        if p.ecosystem == "generic":
            if health:
                health.errors.append(f"OSV skipped {p.key()}: unknown/unsupported ecosystem")
            continue
        queries.append({
            "version": p.version,
            "package": {"name": p.name, "ecosystem": p.ecosystem},
        })
        index.append(p.key())

    result: dict[str, list[str]] = {}
    if not queries:
        return result

    # OSV batch accepts many queries at once; chunk to be polite.
    for start in range(0, len(queries), 100):
        chunk = queries[start:start + 100]
        keys = index[start:start + 100]
        try:
            resp = _post_json(OSV_BATCH, {"queries": chunk})
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            if health:
                health.errors.append(f"OSV batch {start // 100 + 1} failed: {e}")
            if verbose:
                print(f"  [osv] batch failed: {e}")
            continue
        if len(resp.get("results", [])) != len(chunk):
            if health:
                health.errors.append(f"OSV batch {start // 100 + 1}: incomplete response")
        for key, item in zip(keys, resp.get("results", [])):
            vulns = [v["id"] for v in (item.get("vulns") or [])]
            if vulns:
                result[key] = vulns
    return result


def osv_detail(vuln_id: str, verbose: bool = False,
               health: ScanHealth | None = None) -> dict:
    try:
        return _get_json(OSV_VULN + urllib.parse.quote(vuln_id))
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        if health:
            health.errors.append(f"OSV detail {vuln_id} failed: {e}")
        if verbose:
            print(f"  [osv] detail {vuln_id} failed: {e}")
        return {}


def _cve_from_osv(detail: dict) -> str:
    """Prefer a CVE alias; fall back to the OSV id (e.g. GHSA-...)."""
    for alias in detail.get("aliases", []):
        if alias.upper().startswith("CVE-"):
            return alias.upper()
    vid = detail.get("id", "")
    return vid.upper() if vid.upper().startswith("CVE-") else vid


def _severity_from_osv(detail: dict) -> tuple[float | None, str, str]:
    for sev in detail.get("severity", []):
        if sev.get("type", "").startswith("CVSS"):
            vector = sev.get("score", "")
            score = _cvss_base_from_vector(vector)
            return score, normalize_severity(score), vector
    # DB-specific severity label
    db = detail.get("database_specific", {})
    label = str(db.get("severity", "")).upper()
    return None, label or "UNKNOWN", ""


def _cvss_base_from_vector(vector: str) -> float | None:
    """We don't recompute CVSS; OSV usually carries the base score inline.
    If only a vector is present we leave the score to NVD enrichment."""
    return None


def _fixed_versions_from_osv(detail: dict) -> list[str]:
    fixed = []
    for aff in detail.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return sorted(set(fixed))


def build_findings_osv(packages: list[Package], verbose: bool = False,
                       health: ScanHealth | None = None) -> list[Finding]:
    """Query OSV and expand every hit into an enriched Finding skeleton."""
    by_key = {p.key(): p for p in packages}
    hits = osv_query(packages, verbose=verbose, health=health)
    findings: list[Finding] = []
    detail_cache: dict[str, dict] = {}

    for key, vuln_ids in hits.items():
        pkg = by_key[key]
        for vid in vuln_ids:
            detail = detail_cache.get(vid) or osv_detail(vid, verbose=verbose,
                                                       health=health)
            detail_cache[vid] = detail
            score, sev, vector = _severity_from_osv(detail)
            cwes = [x for x in detail.get("database_specific", {}).get("cwe_ids", [])] \
                if isinstance(detail.get("database_specific", {}), dict) else []
            f = Finding(
                cve=_cve_from_osv(detail) or vid,
                package=pkg,
                summary=(detail.get("summary")
                         or (detail.get("details", "")[:280])),
                cvss_score=score,
                cvss_severity=sev,
                cvss_vector=vector,
                cwe=cwes,
                fixed_versions=_fixed_versions_from_osv(detail),
                references=[r.get("url", "") for r in detail.get("references", [])][:8],
            )
            findings.append(f)
            time.sleep(0.02)  # be gentle with the public API
    return findings


# ----- NVD (CVE detail: CVSS + CWE) -------------------------------------------
def nvd_enrich(findings: list[Finding], api_key: str | None = None,
               verbose: bool = False, health: ScanHealth | None = None) -> None:
    """Fill in CVSS score/severity/vector and CWE for CVE-identified findings.

    NVD without a key allows ~5 requests / 30s, so we cache and pace requests.
    """
    cache: dict[str, dict] = {}
    delay = 0.7 if api_key else 6.5
    unique_cves = sorted({f.cve for f in findings if f.cve.upper().startswith("CVE-")})

    for cve in unique_cves:
        try:
            data = _get_json(f"{NVD_CVE}?cveId={cve}", api_key=api_key)
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            if health:
                health.errors.append(f"NVD {cve} failed: {e}")
            if verbose:
                print(f"  [nvd] {cve} failed: {e}")
            time.sleep(delay)
            continue

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            if health:
                health.warnings.append(f"NVD has no record for {cve}")
            time.sleep(delay)
            continue
        cve_obj = vulns[0].get("cve", {})
        cache[cve] = _parse_nvd_cve(cve_obj)
        time.sleep(delay)

    for f in findings:
        info = cache.get(f.cve)
        if not info:
            continue
        if info.get("rejected"):
            f.fp_flags.append("nvd:rejected-cve")
        # only overwrite if OSV lacked a numeric score
        if f.cvss_score is None and info.get("score") is not None:
            f.cvss_score = info["score"]
            f.cvss_severity = normalize_severity(info["score"])
            f.cvss_vector = info.get("vector", "")
        if not f.cwe and info.get("cwe"):
            f.cwe = info["cwe"]


def _parse_nvd_cve(cve_obj: dict) -> dict:
    out: dict = {"rejected": cve_obj.get("vulnStatus", "").lower() == "rejected"}
    metrics = cve_obj.get("metrics", {})
    for mkey in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(mkey):
            m = metrics[mkey][0].get("cvssData", {})
            out["score"] = m.get("baseScore")
            out["vector"] = m.get("vectorString", "")
            break
    cwes = []
    for wk in cve_obj.get("weaknesses", []):
        for desc in wk.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    out["cwe"] = sorted(set(cwes))
    return out

# ==========================================================================
# THREAT-INTEL ENRICHMENT  (EPSS, CISA KEV)
# ==========================================================================
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"





# ----- EPSS -------------------------------------------------------------------
def epss_enrich(findings: list[Finding], verbose: bool = False,
                health: ScanHealth | None = None) -> None:
    cves = sorted({f.cve for f in findings if f.cve.upper().startswith("CVE-")})
    scores: dict[str, tuple[float, float]] = {}

    # EPSS API accepts a comma-separated list; chunk to keep URLs sane.
    for start in range(0, len(cves), 100):
        chunk = cves[start:start + 100]
        url = f"{EPSS_API}?cve={urllib.parse.quote(','.join(chunk))}"
        try:
            data = _get_json(url)
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            if health:
                health.errors.append(f"EPSS chunk {start // 100 + 1} failed: {e}")
            if verbose:
                print(f"  [epss] chunk failed: {e}")
            continue
        for row in data.get("data", []):
            try:
                scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, ValueError, TypeError):
                continue

    for f in findings:
        if f.cve in scores:
            f.epss_score, f.epss_percentile = scores[f.cve]


# ----- CISA KEV ---------------------------------------------------------------
def load_kev(verbose: bool = False, health: ScanHealth | None = None) -> dict[str, dict]:
    """Download the KEV catalogue -> {CVE: {dateAdded,dueDate,ransomware,...}}."""
    try:
        data = _get_json(KEV_FEED)
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        if health:
            health.errors.append(f"CISA KEV feed failed: {e}")
        if verbose:
            print(f"  [kev] feed failed: {e}")
        return {}
    out = {}
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID", "").upper()
        if cve:
            out[cve] = v
    return out


def kev_enrich(findings: list[Finding], kev: dict[str, dict]) -> None:
    for f in findings:
        v = kev.get(f.cve.upper())
        if v:
            f.kev = True
            f.kev_due_date = v.get("dueDate", "")
            f.kev_ransomware = v.get("knownRansomwareCampaignUse", "")

# ==========================================================================
# MITRE ATT&CK MAPPING
# ==========================================================================
# technique registry: id -> (name, tactic)
TECHNIQUES = {
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1189": ("Drive-by Compromise", "Initial Access"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1005": ("Data from Local System", "Collection"),
    "T1211": ("Exploitation for Defense Evasion", "Defense Evasion"),
    "T1212": ("Exploitation for Credential Access", "Credential Access"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1554": ("Compromise Host Software Binary", "Persistence"),
    "T1195": ("Supply Chain Compromise", "Initial Access"),
    "T1040": ("Network Sniffing", "Credential Access"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access"),
}

# CWE -> list of technique ids
CWE_TO_ATTACK: dict[str, list[str]] = {
    # injection
    "CWE-89": ["T1190"],                     # SQL injection
    "CWE-78": ["T1059", "T1190"],            # OS command injection
    "CWE-77": ["T1059"],                     # command injection
    "CWE-94": ["T1059", "T1203"],            # code injection
    "CWE-917": ["T1059"],                    # EL injection
    "CWE-79": ["T1189", "T1059"],            # XSS
    "CWE-611": ["T1190"],                    # XXE
    "CWE-918": ["T1190"],                    # SSRF
    # memory safety -> code execution
    "CWE-787": ["T1203", "T1068"],           # OOB write
    "CWE-125": ["T1203"],                    # OOB read
    "CWE-120": ["T1203"],                    # buffer overflow
    "CWE-119": ["T1203"],                    # memory bounds
    "CWE-416": ["T1203"],                    # use-after-free
    "CWE-476": ["T1499"],                    # null deref -> DoS
    "CWE-190": ["T1203"],                    # integer overflow
    # deserialization / upload
    "CWE-502": ["T1190", "T1203"],           # unsafe deserialization
    "CWE-434": ["T1190"],                    # unrestricted upload
    # path / access
    "CWE-22": ["T1190", "T1083"],            # path traversal
    "CWE-23": ["T1083"],
    "CWE-98": ["T1190"],                     # PHP file inclusion
    # authn / authz
    "CWE-287": ["T1078"],                    # improper authentication
    "CWE-306": ["T1190", "T1078"],           # missing authentication
    "CWE-862": ["T1078"],                    # missing authorization
    "CWE-863": ["T1078"],                    # incorrect authorization
    "CWE-269": ["T1068"],                    # improper privilege mgmt
    "CWE-250": ["T1068"],                    # execution w/ unnecessary privs
    "CWE-732": ["T1068"],                    # incorrect permission assignment
    # crypto / secrets / mitm
    "CWE-798": ["T1552"],                    # hard-coded credentials
    "CWE-522": ["T1552"],                    # insufficiently protected creds
    "CWE-311": ["T1040", "T1557"],           # missing encryption
    "CWE-295": ["T1557"],                    # improper cert validation
    "CWE-327": ["T1557"],                    # broken crypto
    # info disclosure
    "CWE-200": ["T1005"],                    # information exposure
    "CWE-209": ["T1005"],                    # error message exposure
    # csrf / ssrf-ish
    "CWE-352": ["T1189"],                    # CSRF
    # dos
    "CWE-400": ["T1499"],                    # uncontrolled resource consumption
    "CWE-770": ["T1499"],                    # allocation w/o limits
    # supply chain
    "CWE-1104": ["T1195"],                   # unmaintained third-party
}


def _network_exploitable(vector: str) -> bool:
    return "AV:N" in (vector or "")


def map_findings(findings: list[Finding]) -> None:
    for f in findings:
        tech_ids: list[str] = []
        for cwe in f.cwe:
            tech_ids.extend(CWE_TO_ATTACK.get(cwe.upper(), []))

        # fallback: network-exploitable with no CWE mapping -> Initial Access
        if not tech_ids and _network_exploitable(f.cvss_vector):
            tech_ids.append("T1190")

        seen = []
        for tid in tech_ids:
            if tid in seen or tid not in TECHNIQUES:
                continue
            seen.append(tid)
            name, tactic = TECHNIQUES[tid]
            f.attack_techniques.append({"id": tid, "name": name, "tactic": tactic})


def tactic_summary(findings: list[Finding]) -> dict[str, int]:
    """Count findings per ATT&CK tactic for the report's coverage strip."""
    counts: dict[str, int] = {}
    for f in findings:
        tactics = {t["tactic"] for t in f.attack_techniques}
        for t in tactics:
            counts[t] = counts.get(t, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

# ==========================================================================
# FALSE-POSITIVE TRIAGE + PRIORITISATION
# ==========================================================================
_TOKEN = re.compile(r"(\d+)|([a-zA-Z]+)")


def _ver_tokens(v: str) -> list[tuple[int, object]]:
    """Parse a version into ordered comparable tokens.

    Each token is (kind, value) where kind 0 = numeric (sorts below any
    alphabetic token so `1.0.1` < `1.0.1g`) and kind 1 = alphabetic. This is
    intentionally simple but letter-aware, which matters for schemes like
    OpenSSL's `1.0.1g`.
    """
    tokens: list[tuple[int, object]] = []
    for part in re.split(r"[.\-_+~]", v.strip()):
        for num, alpha in _TOKEN.findall(part):
            if num:
                tokens.append((0, int(num)))
            elif alpha:
                tokens.append((1, alpha.lower()))
    return tokens


def _compare(a: str, b: str) -> int | None:
    """Return -1/0/1 for a<b/a==b/a>b, or None if the two versions are not
    confidently comparable (mixed numeric/alpha at the same position). A None
    result must be treated conservatively by callers -- we never hide a
    finding on an uncertain comparison."""
    # Pre-release and distribution version rules differ by ecosystem. A
    # lexical guess could wrongly classify a vulnerable version as patched.
    if re.search(r"(?i)(?:rc|alpha|beta|dev|pre|snapshot|ubuntu|el\d)", a + " " + b):
        return 0 if a == b else None
    ta, tb = _ver_tokens(a), _ver_tokens(b)
    for x, y in zip(ta, tb):
        if x[0] != y[0]:
            return None            # numeric vs alpha at same slot -> unsure
        if x[1] != y[1]:
            return -1 if x[1] < y[1] else 1
    if len(ta) == len(tb):
        return 0
    # the longer one has an extra trailing token; a trailing token makes it
    # greater (1.0.1g > 1.0.1, 1.2.0.1 > 1.2.0)
    return 1 if len(ta) > len(tb) else -1


def _confidently_ge(installed: str, fixed: str) -> bool:
    """True only when we are *sure* installed >= fixed. Uncertain -> False,
    so a real vulnerability is reported rather than silently suppressed."""
    c = _compare(installed, fixed)
    return c is not None and c >= 0


# ----- suppression file -------------------------------------------------------
def load_suppressions(path: str | None) -> dict[str, str]:
    """`.vulnignore`: lines of `CVE-... [# reason]` or `CVE-...:pkgname`."""
    supp: dict[str, str] = {}
    if not path:
        return supp
    p = Path(path)
    if not p.exists():
        return supp
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        reason = ""
        if "#" in line:
            line, reason = line.split("#", 1)
            reason = reason.strip()
        supp[line.strip().upper()] = reason or "listed in .vulnignore"
    return supp


def apply_suppressions(findings: list[Finding], supp: dict[str, str]) -> None:
    for f in findings:
        key_cve = f.cve.upper()
        key_scoped = f"{f.cve.upper()}:{f.package.name.upper()}"
        if key_cve in supp or key_scoped in supp:
            f.suppressed = True
            f.suppress_reason = supp.get(key_scoped) or supp.get(key_cve, "")


# ----- false-positive heuristics ---------------------------------------------
def check_false_positives(findings: list[Finding]) -> None:
    for f in findings:
        flags = f.fp_flags  # may already contain nvd:rejected-cve

        if not f.package.version:
            flags.append("no-version: match is name-only")
            f.confidence = min(f.confidence, 0.4)

        # OSV returned this installed version as affected. A fixed-version
        # comparison alone cannot refute that result: advisories may reopen
        # ranges or offer fixes on multiple release branches.

        if "nvd:rejected-cve" in flags:
            f.confidence = min(f.confidence, 0.1)

        # de-dupe flags, keep order
        seen = []
        for x in flags:
            if x not in seen:
                seen.append(x)
        f.fp_flags = seen


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Same CVE on the same package from multiple sources -> keep the richest."""
    best: dict[tuple, Finding] = {}
    for f in findings:
        k = (f.cve.upper(), f.package.key())
        cur = best.get(k)
        if cur is None:
            best[k] = f
            continue
        # prefer the one with a numeric CVSS, then more references
        score_new = (f.cvss_score is not None, len(f.references))
        score_cur = (cur.cvss_score is not None, len(cur.references))
        if score_new > score_cur:
            best[k] = f
    return list(best.values())


# ----- prioritisation ---------------------------------------------------------
def score_findings(findings: list[Finding]) -> None:
    """Blend severity, exploit likelihood and known exploitation into 0..100."""
    for f in findings:
        cvss = f.cvss_score if f.cvss_score is not None else 5.0
        epss = f.epss_score if f.epss_score is not None else 0.0

        base = (cvss / 10.0) * 55          # severity contributes up to 55
        likely = epss * 30                 # exploit likelihood up to 30
        known = 15 if f.kev else 0         # proven exploitation is decisive

        raw = base + likely + known
        raw *= f.confidence                # discount likely false positives

        f.priority_score = round(raw, 1)
        f.priority_label = _label(f)


def _label(f: Finding) -> str:
    if f.suppressed:
        return "Suppressed"
    if f.confidence < 0.3:
        return "Review (likely FP)"
    if f.kev:
        return "Act now (KEV)"
    if (f.epss_score or 0) >= 0.5 and (f.cvss_score or 0) >= 7:
        return "Urgent"
    if f.priority_score >= 45:
        return "High"
    if f.priority_score >= 25:
        return "Medium"
    return "Low"

# ==========================================================================
# REMEDIATION ENGINE
# ==========================================================================
# ---------------------------------------------------------------------------
# SLA policy: days to remediate, by priority label. Tunable per organisation.
SLA_DAYS = {
    "Act now (KEV)": 7,
    "Urgent": 7,
    "High": 30,
    "Medium": 90,
    "Low": 180,
    "Review (likely FP)": 90,
    "Suppressed": 0,
}


# ---------------------------------------------------------------------------
# ecosystem-specific upgrade commands
def _upgrade_commands(eco: str, name: str, target: str) -> list[str]:
    e = (eco or "").lower()
    if e == "pypi":
        return [f'pip install --upgrade "{name}=={target}"',
                f'# then pin it: update requirements.txt to {name}=={target}']
    if e == "npm":
        return [f"npm install {name}@{target}",
                "npm ls " + name + "   # confirm no transitive copy remains"]
    if e in ("debian", "ubuntu"):
        return ["sudo apt-get update",
                f"sudo apt-get install --only-upgrade {name}",
                f"# if the fix is not yet in your release, check the security pocket:",
                f"apt-cache policy {name}"]
    if e == "red hat":
        return [f"sudo dnf upgrade --refresh {name}",
                f"# RHEL 7 / older: sudo yum update {name}"]
    if e == "alpine":
        return ["sudo apk update", f"sudo apk upgrade {name}"]
    if e == "maven":
        return [f"# in pom.xml set the dependency version to {target}",
                f"mvn versions:use-dep-version -Dincludes={name} -DdepVersion={target}",
                "mvn dependency:tree   # confirm no other path pulls the old version"]
    if e == "go":
        return [f"go get {name}@v{target.lstrip('v')}", "go mod tidy"]
    if e == "crates.io":
        return [f"cargo update -p {name} --precise {target}"]
    if e == "rubygems":
        return [f"bundle update {name} --conservative",
                f"# or pin in Gemfile: gem '{name}', '{target}'"]
    if e == "nuget":
        return [f"dotnet add package {name} --version {target}"]
    if e == "packagist":
        return [f"composer require {name}:{target} --update-with-dependencies"]
    return [f"# upgrade {name} to {target} using your platform's package manager"]


def _verification(eco: str, name: str, target: str) -> str:
    e = (eco or "").lower()
    if e == "pypi":
        return f"pip show {name}   # Version: should read {target} or higher"
    if e == "npm":
        return f"npm ls {name}   # every listed copy should be >= {target}"
    if e in ("debian", "ubuntu"):
        return f"dpkg -s {name} | grep ^Version   # should be >= {target}"
    if e == "red hat":
        return f"rpm -q {name}   # should be >= {target}"
    if e == "alpine":
        return f"apk info -v {name}"
    if e == "maven":
        return f"mvn dependency:tree -Dincludes={name}"
    if e == "go":
        return f"go list -m {name}"
    if e == "crates.io":
        return f"cargo tree -i {name}"
    return f"re-run this scan and confirm {name} no longer appears"


# ---------------------------------------------------------------------------
def _pick_target(installed: str, fixed_versions: list[str]) -> str:
    """Suggest a comparable published fix; never guess across version schemes."""
    if not fixed_versions:
        return ""
    if not installed:
        return ""
    above = [fv for fv in fixed_versions if _compare(installed, fv) == -1]
    return sorted(above, key=_pad)[0] if above else ""


def _pad(v: str):
    parts = []
    for tok in v.replace("-", ".").replace("_", ".").split("."):
        num = "".join(ch for ch in tok if ch.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts)


def _effort(installed: str, target: str) -> tuple[str, str]:
    """Guess upgrade disruption from the version delta."""
    if not installed or not target:
        return "unknown", "Version delta unknown — review the changelog before upgrading."
    a, b = _pad(installed), _pad(target)
    a = a + (0,) * (len(b) - len(a))
    b = b + (0,) * (len(a) - len(b))
    if a[0] != b[0]:
        return "major", ("Major version jump — expect breaking API changes. "
                         "Read the upgrade notes and test in staging first.")
    if len(a) > 1 and a[1] != b[1]:
        return "minor", "Minor version bump — usually backward compatible; run your test suite."
    return "patch", "Patch-level bump — low risk, safe to fast-track."


# ---------------------------------------------------------------------------
# compensating controls when there is no patch
CWE_MITIGATIONS: dict[str, list[str]] = {
    "CWE-89": ["Use parameterised queries / prepared statements on the affected path.",
               "Add a WAF rule for SQL metacharacters on the exposed endpoint.",
               "Restrict the DB account to least privilege so injection can't escalate."],
    "CWE-78": ["Never pass user input to a shell; use argument arrays, not string concatenation.",
               "Run the service as an unprivileged user with a restricted shell."],
    "CWE-77": ["Validate input against a strict allowlist before it reaches any interpreter."],
    "CWE-79": ["Deploy a strict Content-Security-Policy to blunt script injection.",
               "Ensure output encoding is applied on the affected template path."],
    "CWE-502": ["Disable deserialization of untrusted input; allowlist permitted classes.",
                "Block the affected endpoint at the proxy until patched."],
    "CWE-611": ["Disable external entity resolution in the XML parser configuration."],
    "CWE-918": ["Restrict outbound egress from the service; deny link-local metadata IPs (169.254.169.254)."],
    "CWE-22":  ["Canonicalise and validate paths; confine the process with chroot/containers."],
    "CWE-434": ["Restrict upload types and store uploads outside the web root, non-executable."],
    "CWE-287": ["Enforce MFA on the affected authentication path.",
                "Restrict the endpoint to trusted networks / VPN."],
    "CWE-306": ["Put an authenticating reverse proxy in front of the unauthenticated endpoint."],
    "CWE-862": ["Add server-side authorization checks; do not rely on UI-level restrictions."],
    "CWE-863": ["Review and tighten role checks on the affected resource."],
    "CWE-269": ["Drop unnecessary privileges/capabilities; apply seccomp or AppArmor confinement."],
    "CWE-798": ["Rotate the affected credentials now and move them to a secrets manager.",
                "Assume compromise: audit logs for use of the hard-coded credential."],
    "CWE-522": ["Rotate exposed credentials and enforce encryption at rest."],
    "CWE-311": ["Force TLS on the affected channel and disable plaintext fallback."],
    "CWE-295": ["Enable strict certificate validation and pin trusted CAs."],
    "CWE-327": ["Disable the weak cipher/algorithm in configuration; require modern suites."],
    "CWE-400": ["Apply rate limits and request size caps at the proxy.",
                "Set memory/CPU limits so a DoS can't take the host down."],
    "CWE-770": ["Enforce resource quotas and connection limits."],
    "CWE-200": ["Suppress verbose errors and stack traces in production responses."],
    "CWE-352": ["Enforce anti-CSRF tokens and SameSite=Strict cookies."],
    "CWE-1321": ["Freeze/validate object prototypes; reject `__proto__` keys in input."],
    "CWE-125": ["Restrict access to the affected parser/service to trusted inputs only."],
    "CWE-787": ["Enable ASLR/DEP and stack protections; isolate the service."],
    "CWE-416": ["Isolate the process; restart the service on a schedule to limit exposure."],
}

GENERIC_MITIGATIONS = [
    "Reduce exposure: restrict the affected service to trusted networks until patched.",
    "Increase monitoring on the affected host and alert on anomalous behaviour.",
]


def _mitigations(f: Finding) -> list[str]:
    out: list[str] = []
    for cwe in f.cwe:
        out.extend(CWE_MITIGATIONS.get(cwe.upper(), []))
    if "AV:N" in (f.cvss_vector or ""):
        out.append("Network-reachable (AV:N): block or firewall the exposed port "
                   "from untrusted networks as an immediate stopgap.")
    if f.kev:
        out.append("Listed in CISA KEV — assume active exploitation; hunt for "
                   "indicators of compromise on affected hosts, don't just patch.")
    if str(f.kev_ransomware).lower() == "known":
        out.append("Known ransomware use — verify backups are offline and restorable.")
    if not out:
        out.extend(GENERIC_MITIGATIONS)
    seen, uniq = set(), []
    for m in out:
        if m not in seen:
            seen.add(m)
            uniq.append(m)
    return uniq[:6]


def _due(f: Finding) -> tuple[str, str]:
    if f.kev and f.kev_due_date:
        return f.kev_due_date, "CISA KEV remediation deadline (binding for US federal agencies; a strong benchmark for everyone else)"
    days = SLA_DAYS.get(f.priority_label, 90)
    if days == 0:
        return "", "suppressed — no deadline"
    return (date.today() + timedelta(days=days)).isoformat(), \
        f"internal SLA: {days} days for '{f.priority_label}' findings"


# ---------------------------------------------------------------------------
def build(findings: list[Finding]) -> None:
    """Attach a Remediation to every finding (call after scoring)."""
    for f in findings:
        pkg = f.package
        target = _pick_target(pkg.version, f.fixed_versions)
        due, due_reason = _due(f)
        r = Remediation(due_date=due, due_reason=due_reason)

        if f.suppressed:
            r.action = "monitor"
            r.headline = f"Suppressed — {f.suppress_reason or 'accepted risk'}"
            r.steps = ["No action required while the suppression stands.",
                       "Re-review the exception at your next risk review."]
            r.mitigations = _mitigations(f)
            f.remediation = r
            continue

        if f.confidence < 0.3:
            r.action = "verify"
            r.headline = "Verify before acting — this match looks like a false positive"
            r.steps = ["Confirm the flagged version is what's actually deployed."]
            r.steps += [f"Check the FP signal: {flag}" for flag in f.fp_flags]
            r.steps.append("If confirmed a false positive, add it to .vulnignore "
                           "with a reason so it stays documented.")
            r.verification = _verification(pkg.ecosystem, pkg.name, target or pkg.version)
            r.mitigations = []
            f.remediation = r
            continue

        if target:
            r.action = "upgrade"
            r.target_version = target
            r.headline = (f"Review upgrade of {pkg.name} {pkg.version or '?'} → {target}")
            r.commands = _upgrade_commands(pkg.ecosystem, pkg.name, target)
            r.effort, r.effort_note = _effort(pkg.version, target)
            r.verification = _verification(pkg.ecosystem, pkg.name, target)
            r.steps = [
                f"Check that {target} resolves this advisory on your release branch; "
                "then upgrade in every environment where it is deployed.",
                "Rebuild and redeploy any image or artifact that bundles this package.",
                "Check for transitive copies — a direct upgrade doesn't always "
                "replace a nested dependency.",
            ]
            if f.kev:
                r.steps.insert(0, "Prioritise: this is actively exploited in the "
                                  "wild (CISA KEV). Patch ahead of the queue.")
            r.mitigations = _mitigations(f) if f.kev or (f.epss_score or 0) >= 0.1 else []
            if r.mitigations:
                r.mitigations.insert(0, "If you cannot patch immediately, apply these "
                                        "interim controls:")
        else:
            r.action = "mitigate"
            r.headline = f"No comparable upgrade identified for {pkg.name} — review advisory"
            r.effort, r.effort_note = "unknown", "A fix may exist on another version branch."
            r.mitigations = _mitigations(f)
            r.steps = [
                "Check the vendor advisory for a fix on your release branch; re-scan regularly.",
                "If the component is unmaintained, plan a migration to a "
                "supported alternative.",
                "Consider removing the component if it is not essential.",
            ]
            r.verification = "re-run this scan after the vendor publishes a fix"
        f.remediation = r


# ---------------------------------------------------------------------------
def plan(findings: list[Finding]) -> list[dict]:
    """Consolidated, de-duplicated fix plan grouped by package.

    One `pip install --upgrade x` can close several CVEs, so the actionable
    unit of work is the package, not the CVE.
    """
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.suppressed or f.confidence < 0.3 or not f.remediation:
            continue
        groups[(f.package.ecosystem, f.package.name, f.package.version)].append(f)

    out = []
    for (eco, name, version), items in groups.items():
        items.sort(key=lambda f: -f.priority_score)
        # Only propose a single target if every finding names that same
        # candidate. The candidate still needs a rescan to establish safety.
        targets = [f.remediation.target_version for f in items
                   if f.remediation and f.remediation.target_version]
        best = targets[0] if len(targets) == len(items) and len(set(targets)) == 1 else ""
        top = items[0]
        due_dates = [f.remediation.due_date for f in items
                     if f.remediation and f.remediation.due_date]
        out.append({
            "ecosystem": eco,
            "name": name,
            "version": version,
            "target": best,
            "action": "review upgrade" if best else "review advisories",
            "commands": _upgrade_commands(eco, name, best) if best else [],
            "verification": _verification(eco, name, best) if best else "",
            "effort": _effort(version, best)[0] if best else "unknown",
            "effort_note": _effort(version, best)[1] if best else
                           "No published fix — apply compensating controls.",
            "cves": [f.cve for f in items],
            "kev": any(f.kev for f in items),
            "max_score": max(f.priority_score for f in items),
            "label": top.priority_label,
            "due": min(due_dates) if due_dates else "",
            "mitigations": top.remediation.mitigations if not best and top.remediation else [],
        })
    out.sort(key=lambda g: (-g["max_score"], g["name"]))
    return out

# ==========================================================================
# HTML REPORT
# ==========================================================================
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _pct(x) -> str:
    return f"{x * 100:.1f}%" if isinstance(x, (int, float)) else "—"


def _sev_class(sev: str) -> str:
    return "sev-" + (sev or "unknown").lower()


def _split(findings: list[Finding]):
    active, suppressed, likely_fp = [], [], []
    for f in findings:
        if f.suppressed:
            suppressed.append(f)
        elif f.confidence < 0.3:
            likely_fp.append(f)
        else:
            active.append(f)
    active.sort(key=lambda f: (-f.priority_score, SEV_ORDER.get(f.cvss_severity, 5)))
    likely_fp.sort(key=lambda f: -f.priority_score)
    return active, likely_fp, suppressed


def _stat_row(active: list[Finding]) -> str:
    kev = sum(1 for f in active if f.kev)
    crit = sum(1 for f in active if f.cvss_severity == "CRITICAL")
    high_epss = sum(1 for f in active if (f.epss_score or 0) >= 0.5)
    urgent = sum(1 for f in active if f.priority_label in ("Act now (KEV)", "Urgent"))
    cells = [
        ("Active findings", len(active), "neutral"),
        ("In CISA KEV", kev, "kev"),
        ("Critical (CVSS)", crit, "crit"),
        ("High EPSS (≥50%)", high_epss, "epss"),
        ("Act now / urgent", urgent, "urgent"),
    ]
    out = ['<div class="stats">']
    for label, val, cls in cells:
        out.append(
            f'<div class="stat stat-{cls}">'
            f'<span class="stat-val">{val}</span>'
            f'<span class="stat-label">{_esc(label)}</span></div>'
        )
    out.append("</div>")
    return "".join(out)


def _attack_strip(findings: list[Finding]) -> str:
    counts = tactic_summary([f for f in findings if not f.suppressed])
    if not counts:
        return ""
    mx = max(counts.values())
    chips = []
    for tactic, n in counts.items():
        w = 30 + int(70 * n / mx)
        chips.append(
            f'<div class="tactic" style="--w:{w}%">'
            f'<span class="tactic-name">{_esc(tactic)}</span>'
            f'<span class="tactic-count">{n}</span></div>'
        )
    return (
        '<section class="panel"><h2 class="panel-h">ATT&CK tactic coverage '
        '<span class="hint">heuristic CWE→technique mapping</span></h2>'
        f'<div class="tactics">{"".join(chips)}</div></section>'
    )


def _priority_bar(f: Finding) -> str:
    cvss = (f.cvss_score or 0) / 10 * 55
    epss = (f.epss_score or 0) * 30
    kev = 15 if f.kev else 0
    total = max(cvss + epss + kev, 0.001)
    seg = lambda v, c: (
        f'<span class="seg seg-{c}" style="width:{v / total * 100:.1f}%" '
        f'title="{c}: {v:.1f}"></span>' if v > 0 else ""
    )
    return (
        '<div class="pbar" role="img" '
        f'aria-label="priority {f.priority_score}">'
        f'{seg(cvss, "cvss")}{seg(epss, "epss")}{seg(kev, "kev")}</div>'
    )


def _attack_chips(f: Finding) -> str:
    if not f.attack_techniques:
        return '<span class="muted">—</span>'
    chips = []
    for t in f.attack_techniques:
        chips.append(
            f'<span class="chip" title="{_esc(t["tactic"])}">'
            f'{_esc(t["id"])} · {_esc(t["name"])}</span>'
        )
    return "".join(chips)


def _refs(f: Finding) -> str:
    links = []
    for r in f.references[:5]:
        if r:
            parsed = urllib.parse.urlsplit(r.strip())
            if parsed.scheme.lower() in {"https", "http"} and parsed.netloc:
                links.append(f'<a href="{_esc(r)}" rel="noopener noreferrer">{_esc(r)}</a>')
    return "<br>".join(links) if links else '<span class="muted">none</span>'


def _fp_flags(f: Finding) -> str:
    if not f.fp_flags:
        return ""
    items = "".join(f'<li>{_esc(x)}</li>' for x in f.fp_flags)
    return f'<div class="fp"><span class="fp-h">FP checks</span><ul>{items}</ul></div>'


def _codeblock(lines: list[str], label: str = "") -> str:
    if not lines:
        return ""
    body = "\n".join(lines)
    return (f'<div class="code"><button class="copy" type="button" '
            f'data-copy="{_esc(body)}">copy</button>'
            f'<pre>{_esc(body)}</pre></div>')


def _remediation_block(f: Finding) -> str:
    r = f.remediation
    if r is None:
        return ""
    parts = [f'<div class="remed remed-{_esc(r.action)}">',
             '<div class="remed-h">Remediation'
             f'<span class="act act-{_esc(r.action)}">{_esc(r.action)}</span></div>',
             f'<p class="remed-headline">{_esc(r.headline)}</p>']

    if r.due_date:
        parts.append(f'<div class="due"><span class="k">Due</span> '
                     f'<b>{_esc(r.due_date)}</b> '
                     f'<span class="muted">— {_esc(r.due_reason)}</span></div>')
    if r.effort:
        parts.append(f'<div class="effort effort-{_esc(r.effort)}">'
                     f'<span class="k">Upgrade risk</span> <b>{_esc(r.effort)}</b> '
                     f'<span class="muted">— {_esc(r.effort_note)}</span></div>')
    if r.steps:
        items = "".join(f"<li>{_esc(s)}</li>" for s in r.steps)
        parts.append(f'<ol class="steps">{items}</ol>')
    if r.commands:
        parts.append('<div class="k">Fix</div>' + _codeblock(r.commands))
    if r.verification:
        parts.append('<div class="k">Verify</div>' + _codeblock([r.verification]))
    if r.mitigations:
        items = "".join(f"<li>{_esc(m)}</li>" for m in r.mitigations)
        parts.append(f'<div class="k">Interim controls</div><ul class="mit">{items}</ul>')
    parts.append("</div>")
    return "".join(parts)


def _plan_panel(plan_rows: list[dict]) -> str:
    """The consolidated fix plan: one upgrade often closes several CVEs."""
    if not plan_rows:
        return ""
    total_cves = sum(len(g["cves"]) for g in plan_rows)
    rows = []
    for i, g in enumerate(plan_rows, 1):
        cves = " ".join(f'<span class="mini-cve">{_esc(c)}</span>' for c in g["cves"])
        kev = '<span class="badge badge-kev">KEV</span>' if g["kev"] else ""
        target = (f'<span class="arrow">→</span> <b>{_esc(g["target"])}</b>'
                  if g["target"] else '<span class="muted">review vendor fixes</span>')
        due = (f'<span class="due-chip">due {_esc(g["due"])}</span>'
               if g["due"] else "")
        cmds = _codeblock(g["commands"]) if g["commands"] else ""
        mit = ""
        if not g["commands"] and g["mitigations"]:
            items = "".join(f"<li>{_esc(m)}</li>" for m in g["mitigations"])
            mit = f'<ul class="mit">{items}</ul>'
        rows.append(f"""
        <details class="fix">
          <summary class="fix-head">
            <span class="step-n">{i}</span>
            <span class="fix-pkg">{_esc(g["name"])}
              <span class="ver">{_esc(g["version"] or "?")}</span> {target}</span>
            <span class="eco">{_esc(g["ecosystem"])}</span>
            {kev}
            <span class="badge badge-effort effort-{_esc(g["effort"])}">{_esc(g["effort"])}</span>
            <span class="closes">{len(g["cves"])} findings to verify</span>
            {due}
          </summary>
          <div class="fix-body">
            <div class="mini-cves">{cves}</div>
            <div class="effort-note muted">{_esc(g["effort_note"])}</div>
            {cmds}{mit}
            {'<div class="k">Verify</div>' + _codeblock([g["verification"]]) if g["verification"] else ""}
          </div>
        </details>""")

    return (f'<section class="panel panel-plan"><h2 class="panel-h">Remediation plan '
            f'<span class="count">{len(plan_rows)} actions</span> '
            f'<span class="hint">grouped by package — review {total_cves} findings, '
            f'highest risk first</span></h2>'
            f'<div class="fixes">{"".join(rows)}</div></section>')


def _finding_row(f: Finding) -> str:
    kev_badge = ('<span class="badge badge-kev">KEV'
                 + (' · ransomware' if str(f.kev_ransomware).lower() == "known" else "")
                 + "</span>") if f.kev else ""
    epss_disp = _pct(f.epss_score)
    epss_p = f" (p{f.epss_percentile*100:.0f})" if f.epss_percentile is not None else ""
    fixed = ", ".join(f.fixed_versions) if f.fixed_versions else "—"
    conf = f"{f.confidence*100:.0f}%"

    return f"""
    <details class="finding {_sev_class(f.cvss_severity)}">
      <summary class="finding-head">
        <span class="prio">{f.priority_score:g}</span>
        <span class="cve">{_esc(f.cve)}</span>
        <span class="pkg">{_esc(f.package.name)} <span class="ver">{_esc(f.package.version or '?')}</span></span>
        <span class="badge {_sev_class(f.cvss_severity)}">{_esc(f.cvss_severity)}
          {f'· {f.cvss_score:g}' if f.cvss_score is not None else ''}</span>
        {kev_badge}
        <span class="badge badge-label">{_esc(f.priority_label)}</span>
        {_priority_bar(f)}
      </summary>
      <div class="finding-body">
        <p class="summary">{_esc(f.summary) or '<span class="muted">No summary available.</span>'}</p>
        <div class="grid">
          <div><span class="k">EPSS</span><span class="v">{epss_disp}{epss_p}</span></div>
          <div><span class="k">CVSS vector</span><span class="v mono">{_esc(f.cvss_vector) or '—'}</span></div>
          <div><span class="k">CWE</span><span class="v">{_esc(', '.join(f.cwe)) or '—'}</span></div>
          <div><span class="k">Ecosystem</span><span class="v">{_esc(f.package.ecosystem)}</span></div>
          <div><span class="k">Fixed in</span><span class="v">{_esc(fixed)}</span></div>
          <div><span class="k">Match confidence</span><span class="v">{conf}</span></div>
        </div>
        <div class="attack-line"><span class="k">ATT&CK</span> <span class="chips">{_attack_chips(f)}</span></div>
        {_fp_flags(f)}
        {_remediation_block(f)}
        <div class="refs"><span class="k">References</span><div class="ref-list">{_refs(f)}</div></div>
      </div>
    </details>"""


def _section(title: str, findings: list[Finding], note: str = "") -> str:
    if not findings:
        return ""
    rows = "".join(_finding_row(f) for f in findings)
    note_html = f'<span class="hint">{_esc(note)}</span>' if note else ""
    return (f'<section class="panel"><h2 class="panel-h">{_esc(title)} '
            f'<span class="count">{len(findings)}</span> {note_html}</h2>'
            f'<div class="findings">{rows}</div></section>')


def _sources_panel(notes: list[str]) -> str:
    """Show which input files were read and what came out of each."""
    if not notes:
        return ""
    items = "".join(f'<li>{_esc(n)}</li>' for n in notes)
    return ('<section class="panel"><h2 class="panel-h">Inventory sources '
            f'<span class="count">{len(notes)}</span></h2>'
            f'<ul class="srclist">{items}</ul></section>')


def render(findings: list[Finding], meta: dict, plan_rows: list[dict] | None = None) -> str:
    active, likely_fp, suppressed = _split(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    scanned = meta.get("packages_scanned", 0)
    inv_src = _esc(meta.get("inventory_source", "—"))
    online = meta.get("online", True)
    notes = meta.get("source_notes", [])

    errors = meta.get("scan_errors", [])
    warnings = meta.get("scan_warnings", [])
    offline_banner = ""
    if errors:
        details = "".join(f"<li>{_esc(e)}</li>" for e in errors)
        offline_banner = (f'<div class="banner">INCOMPLETE SCAN — results may omit '
                          f'vulnerabilities. Exit code 3.<ul>{details}</ul></div>')
    elif not online:
        offline_banner = '<div class="banner">Offline demo data — no live feeds queried.</div>'
    if warnings:
        offline_banner += ('<div class="banner">Feed notes:<ul>' +
                           "".join(f"<li>{_esc(w)}</li>" for w in warnings) +
                           '</ul></div>')

    body = "".join([
        _stat_row(active),
        offline_banner,
        _plan_panel(plan_rows or []),
        _attack_strip(findings),
        _section("Priority findings", active,
                 "ranked by blended CVSS + EPSS + KEV risk"),
        _section("Likely false positives", likely_fp,
                 "low match confidence — verify before dismissing"),
        _section("Suppressed", suppressed, "listed in .vulnignore"),
        _sources_panel(notes),
    ])

    return _TEMPLATE.format(
        css=_CSS,
        js=_JS,
        now=now,
        scanned=scanned,
        inv_src=inv_src,
        total=len(findings),
        active=len(active),
        body=body,
    )


_CSS = """
:root{
  --bg:#0b0f17; --panel:#131a26; --panel-2:#0f1520; --line:#243044;
  --ink:#cdd8ea; --muted:#697a95; --accent:#6ea8fe;
  --crit:#ff5470; --high:#ff9448; --med:#f2c94c; --low:#56b6ff; --none:#5b6b82;
  --kev:#ff5470; --epss:#c084fc; --cvss:#6ea8fe; --ok:#4ade80;
  --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none;word-break:break-all}
a:hover{text-decoration:underline}
.wrap{max-width:1120px;margin:0 auto;padding:28px 20px 80px}
.masthead{border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:22px;
  display:flex;flex-wrap:wrap;align-items:baseline;gap:14px 22px}
.logo{font-family:var(--mono);font-weight:700;font-size:19px;letter-spacing:.5px}
.logo b{color:var(--accent)}
.meta{font-family:var(--mono);font-size:12px;color:var(--muted);
  display:flex;gap:18px;flex-wrap:wrap;margin-left:auto}
.meta span b{color:var(--ink);font-weight:600}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:22px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:14px 16px;display:flex;flex-direction:column;gap:2px}
.stat-val{font-family:var(--mono);font-size:28px;font-weight:700;line-height:1}
.stat-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}
.stat-kev .stat-val{color:var(--kev)} .stat-crit .stat-val{color:var(--crit)}
.stat-epss .stat-val{color:var(--epss)} .stat-urgent .stat-val{color:var(--high)}
.banner{background:rgba(242,201,76,.08);border:1px solid rgba(242,201,76,.35);
  color:var(--med);border-radius:10px;padding:12px 16px;margin-bottom:22px;font-size:13px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:18px 18px 8px;margin-bottom:20px}
.panel-h{font-size:13px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);
  margin:0 0 14px;display:flex;align-items:center;gap:10px;font-weight:600}
.panel-h .count{background:var(--panel-2);border:1px solid var(--line);border-radius:20px;
  padding:1px 9px;font-size:12px;color:var(--ink);font-family:var(--mono)}
.hint{font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted);font-size:12px}
.tactics{display:flex;flex-direction:column;gap:6px;padding-bottom:8px}
.tactic{display:grid;grid-template-columns:220px 1fr;align-items:center;gap:12px;
  font-family:var(--mono);font-size:12px}
.tactic-name{color:var(--ink)}
.tactic-count{position:relative;height:20px;border-radius:5px;
  background:linear-gradient(90deg,var(--accent),#3b6fd4);width:var(--w);
  color:#06101f;font-weight:700;display:flex;align-items:center;padding:0 8px;min-width:26px}
.findings{display:flex;flex-direction:column;gap:8px;padding-bottom:10px}
.finding{background:var(--panel-2);border:1px solid var(--line);border-radius:9px;
  border-left:3px solid var(--none);overflow:hidden}
.finding.sev-critical{border-left-color:var(--crit)}
.finding.sev-high{border-left-color:var(--high)}
.finding.sev-medium{border-left-color:var(--med)}
.finding.sev-low{border-left-color:var(--low)}
.finding-head{list-style:none;cursor:pointer;display:flex;align-items:center;
  gap:10px;padding:11px 14px;flex-wrap:wrap}
.finding-head::-webkit-details-marker{display:none}
.finding-head:hover{background:rgba(110,168,254,.05)}
.prio{font-family:var(--mono);font-weight:700;font-size:15px;min-width:38px;color:var(--ink)}
.cve{font-family:var(--mono);font-weight:600;color:var(--accent);min-width:132px}
.pkg{color:var(--ink)} .pkg .ver{color:var(--muted);font-family:var(--mono);font-size:12px}
.badge{font-size:11px;font-family:var(--mono);padding:2px 8px;border-radius:5px;
  border:1px solid var(--line);white-space:nowrap;text-transform:uppercase;letter-spacing:.4px}
.badge.sev-critical{background:rgba(255,84,112,.14);color:var(--crit);border-color:rgba(255,84,112,.4)}
.badge.sev-high{background:rgba(255,148,72,.14);color:var(--high);border-color:rgba(255,148,72,.4)}
.badge.sev-medium{background:rgba(242,201,76,.14);color:var(--med);border-color:rgba(242,201,76,.4)}
.badge.sev-low{background:rgba(86,182,255,.14);color:var(--low);border-color:rgba(86,182,255,.4)}
.badge.sev-unknown,.badge.sev-none{background:var(--panel);color:var(--muted)}
.badge-kev{background:var(--kev);color:#170307;border-color:var(--kev);font-weight:700}
.badge-label{background:var(--panel);color:var(--ink)}
.pbar{display:flex;height:7px;border-radius:4px;overflow:hidden;background:#0a0e15;
  flex:1 1 120px;min-width:110px;margin-left:auto}
.seg-cvss{background:var(--cvss)} .seg-epss{background:var(--epss)} .seg-kev{background:var(--kev)}
.finding-body{padding:4px 16px 16px;border-top:1px solid var(--line)}
.summary{color:var(--ink);margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px 20px;margin:10px 0}
.grid>div{display:flex;flex-direction:column;gap:2px}
.k{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)}
.v{color:var(--ink)} .v.mono,.mono{font-family:var(--mono);font-size:12px}
.attack-line{margin:12px 0;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{font-family:var(--mono);font-size:11px;background:var(--panel);border:1px solid var(--line);
  border-radius:5px;padding:2px 8px;color:var(--ink)}
/* ---- remediation plan (signature element) ---- */
.panel-plan{border-color:#2c4a3e;background:linear-gradient(180deg,#132018,#131a26 120px)}
.fixes{display:flex;flex-direction:column;gap:8px;padding-bottom:10px}
.fix{background:var(--panel-2);border:1px solid var(--line);border-radius:9px;
  border-left:3px solid var(--ok);overflow:hidden}
.fix-head{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;
  padding:11px 14px;flex-wrap:wrap}
.fix-head::-webkit-details-marker{display:none}
.fix-head:hover{background:rgba(74,222,128,.05)}
.step-n{font-family:var(--mono);font-size:12px;font-weight:700;color:#06101f;
  background:var(--ok);border-radius:50%;width:22px;height:22px;display:flex;
  align-items:center;justify-content:center;flex:none}
.fix-pkg{font-weight:600}
.fix-pkg .ver{font-family:var(--mono);font-size:12px;color:var(--muted);font-weight:400}
.arrow{color:var(--ok);margin:0 2px}
.fix-pkg b{font-family:var(--mono);color:var(--ok)}
.eco{font-family:var(--mono);font-size:11px;color:var(--muted);
  border:1px solid var(--line);border-radius:4px;padding:1px 7px}
.closes{font-size:11px;font-family:var(--mono);color:var(--muted);margin-left:auto}
.due-chip{font-family:var(--mono);font-size:11px;color:var(--med);
  border:1px solid rgba(242,201,76,.35);border-radius:4px;padding:1px 7px}
.badge-effort.effort-patch{background:rgba(74,222,128,.14);color:var(--ok);border-color:rgba(74,222,128,.4)}
.badge-effort.effort-minor{background:rgba(242,201,76,.14);color:var(--med);border-color:rgba(242,201,76,.4)}
.badge-effort.effort-major{background:rgba(255,148,72,.14);color:var(--high);border-color:rgba(255,148,72,.4)}
.badge-effort.effort-unknown{background:var(--panel);color:var(--muted)}
.fix-body{padding:12px 16px 16px;border-top:1px solid var(--line)}
.mini-cves{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:8px}
.mini-cve{font-family:var(--mono);font-size:11px;background:var(--panel);
  border:1px solid var(--line);border-radius:4px;padding:1px 7px;color:var(--accent)}
.effort-note{font-size:12px;margin-bottom:10px}
/* ---- code blocks + copy ---- */
.code{position:relative;background:#080c13;border:1px solid var(--line);
  border-radius:7px;margin:6px 0 12px}
.code pre{margin:0;padding:11px 13px;overflow-x:auto;font-family:var(--mono);
  font-size:12.5px;line-height:1.6;color:#b6e3c8;white-space:pre-wrap;word-break:break-word}
.copy{position:absolute;top:7px;right:7px;background:var(--panel);color:var(--muted);
  border:1px solid var(--line);border-radius:5px;font-family:var(--mono);font-size:11px;
  padding:3px 9px;cursor:pointer}
.copy:hover{color:var(--ink);border-color:var(--accent)}
.copy.done{color:var(--ok);border-color:var(--ok)}
/* ---- per-finding remediation ---- */
.remed{background:rgba(74,222,128,.05);border:1px solid rgba(74,222,128,.22);
  border-radius:9px;padding:12px 14px;margin:14px 0 4px}
.remed-mitigate{background:rgba(255,148,72,.05);border-color:rgba(255,148,72,.25)}
.remed-verify,.remed-monitor{background:rgba(105,122,149,.07);border-color:var(--line)}
.remed-h{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);
  display:flex;align-items:center;gap:9px;margin-bottom:7px;font-weight:600}
.act{font-size:10px;border-radius:4px;padding:1px 7px;font-family:var(--mono);
  background:var(--ok);color:#06101f;letter-spacing:.4px}
.act-mitigate{background:var(--high)} .act-verify,.act-monitor{background:var(--muted)}
.remed-headline{margin:0 0 9px;font-weight:600;color:var(--ink)}
.due,.effort{font-size:12.5px;margin:4px 0}
.due .k,.effort .k{display:inline;margin-right:5px}
.steps{margin:9px 0;padding-left:20px}
.steps li{margin:4px 0}
.mit{margin:6px 0 0;padding-left:20px}
.mit li{margin:4px 0;color:var(--ink)}
.srclist{margin:0 0 12px;padding-left:20px;font-family:var(--mono);font-size:12px;color:var(--ink)}
.srclist li{margin:3px 0}
.fp{background:rgba(242,201,76,.06);border:1px solid rgba(242,201,76,.25);border-radius:8px;
  padding:8px 12px;margin:12px 0}
.fp-h{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--med)}
.fp ul{margin:6px 0 0;padding-left:18px}
.fp li{font-family:var(--mono);font-size:12px;color:var(--ink)}
.refs{margin-top:12px} .ref-list{margin-top:4px;font-size:12px;font-family:var(--mono)}
.muted{color:var(--muted)}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:30px;
  font-family:var(--mono);line-height:1.7}
@media (max-width:820px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .grid{grid-template-columns:1fr 1fr}
  .tactic{grid-template-columns:140px 1fr}
  .meta{margin-left:0}
}
@media (max-width:520px){.stats{grid-template-columns:1fr}.grid{grid-template-columns:1fr}}
@media (prefers-reduced-motion:no-preference){
  .finding[open]{animation:reveal .18s ease}
  @keyframes reveal{from{opacity:.5}to{opacity:1}}
}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
"""


_JS = """
document.addEventListener('click', function (e) {
  var btn = e.target.closest('.copy');
  if (!btn) return;
  var text = btn.getAttribute('data-copy') || '';
  function done() {
    var old = btn.textContent;
    btn.textContent = 'copied'; btn.classList.add('done');
    setTimeout(function () { btn.textContent = old; btn.classList.remove('done'); }, 1400);
  }
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(fallback);
  } else { fallback(); }
  function fallback() {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (err) { btn.textContent = 'select & copy'; }
    document.body.removeChild(ta);
  }
});
"""

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PatchRoute Report — {now}</title>
<style>{css}</style></head>
<body><div class="wrap">
<header class="masthead">
  <div class="logo"><b>Patch</b>Route</div>
  <div class="meta">
    <span>scan <b>{now}</b></span>
    <span>inventory <b>{inv_src}</b></span>
    <span>packages <b>{scanned}</b></span>
    <span>findings <b>{total}</b> ({active} active)</span>
  </div>
</header>
{body}
<footer>
  Priority = severity (CVSS) + exploit likelihood (EPSS) + known exploitation (CISA KEV),
  discounted by match confidence.<br>
  ATT&CK mapping is a heuristic CWE→technique association, not an authoritative link.
  Verify findings before acting.
</footer>
</div><script>{js}</script></body></html>"""

# ==========================================================================
# COMMAND-LINE INTERFACE
# ==========================================================================
#!/usr/bin/env python3




def log(msg: str, quiet: bool = False):
    if not quiet:
        print(msg, file=sys.stderr)


def collect_inventory(args, health: ScanHealth | None = None) -> tuple[list[Package], str, list[str]]:
    """Returns (packages, source_label, per-file notes)."""
    if args.demo:
        return _demo_inventory(), "demo sample", ["bundled demo data"]
    if args.host:
        pkgs = from_host()
        return dedupe(pkgs), "live host", ["live host package managers"]
    if args.input:
        all_pkgs: list[Package] = []
        notes: list[str] = []
        for item in args.input:
            try:
                pkgs, n = from_path(item, args.ecosystem, not args.no_recurse)
                all_pkgs.extend(pkgs)
                notes.extend(n)
                if health:
                    health.errors.extend(note for note in n if ": skipped (" in note)
            except Exception as e:
                notes.append(f"{item}: ERROR {e}")
                if health:
                    health.errors.append(f"Inventory {item} failed: {e}")
                log(f"[!] {item}: {e}", args.quiet)
        label = (Path(args.input[0]).name if len(args.input) == 1
                 else f"{len(args.input)} inputs")
        return dedupe(all_pkgs), label, notes
    raise SystemExit("error: provide --input FILE|DIR, --host, or --demo")


def _demo_inventory() -> list[Package]:
    return [
        Package("log4j-core", "2.14.1", "Maven"),
        Package("openssl", "1.0.1", "Debian"),
        Package("lodash", "4.17.11", "npm"),
        Package("django", "2.2.0", "PyPI"),
        Package("requests", "2.31.0", "PyPI"),   # likely clean
        Package("jinja2", "2.10", "PyPI"),
    ]


def _demo_findings(pkgs: list[Package]) -> list[Finding]:
    """Deterministic offline findings so the report renders without network."""
    by = {p.name: p for p in pkgs}
    F = []

    def mk(cve, pkgname, summary, score, cwe, fixed, epss, kev, refs, rans=""):
        f = Finding(
            cve=cve, package=by[pkgname], summary=summary,
            cvss_score=score, cvss_severity=normalize_severity(score),
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe=cwe, fixed_versions=fixed, references=refs,
            epss_score=epss, epss_percentile=(epss and 0.98) or 0.1,
            kev=kev, kev_ransomware=rans,
        )
        return f

    F.append(mk("CVE-2021-44228", "log4j-core",
                "Log4Shell: JNDI lookup in log messages enables remote code execution.",
                10.0, ["CWE-502", "CWE-917"], ["2.15.0"], 0.975, True,
                ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"], "Known"))
    F.append(mk("CVE-2014-0160", "openssl",
                "Heartbleed: OOB read in TLS heartbeat leaks memory contents.",
                7.5, ["CWE-125"], ["1.0.1g"], 0.944, True,
                ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"]))
    F.append(mk("CVE-2019-10744", "lodash",
                "Prototype pollution in defaultsDeep allows property injection.",
                9.1, ["CWE-1321"], ["4.17.12"], 0.31, False,
                ["https://nvd.nist.gov/vuln/detail/CVE-2019-10744"]))
    F.append(mk("CVE-2019-14232", "django",
                "Denial of service via large input to django.utils.text truncator.",
                7.5, ["CWE-400"], ["2.2.4"], 0.12, False,
                ["https://nvd.nist.gov/vuln/detail/CVE-2019-14232"]))
    F.append(mk("CVE-2019-10906", "jinja2",
                "Sandbox escape via str.format_map allowing code execution.",
                8.6, ["CWE-134"], ["2.10.1"], 0.22, False,
                ["https://nvd.nist.gov/vuln/detail/CVE-2019-10906"]))
    # a deliberately disputed / already-fixed style entry to exercise FP logic
    fp = mk("CVE-2023-99999", "requests",
            "Disputed advisory; no fix published and vendor rejects impact.",
            5.0, [], [], 0.01, False, [])
    fp.fp_flags.append("nvd:rejected-cve")
    F.append(fp)
    return F


def run(args) -> int:
    quiet = args.quiet
    health = ScanHealth()
    args.ecosystem = normalize_ecosystem(args.ecosystem, "generic")
    pkgs, inv_src, src_notes = collect_inventory(args, health)
    log(f"[*] inventory: {len(pkgs)} packages from {inv_src}", quiet)
    if not pkgs:
        log("[!] no packages found", quiet)
        if not args.demo:
            health.errors.append("No packages were parsed from the inventory")

    online = True
    if args.demo:
        findings = _demo_findings(pkgs)
        online = False
        log("[*] demo mode: using bundled offline findings", quiet)
    elif not pkgs:
        findings = []
        online = False
    else:
        log("[*] querying OSV.dev …", quiet)
        findings = build_findings_osv(pkgs, verbose=not quiet, health=health)
        log(f"    {len(findings)} raw findings", quiet)

        log("[*] enriching with NVD (CVSS/CWE) …", quiet)
        nvd_enrich(findings, api_key=args.nvd_key, verbose=not quiet, health=health)

        log("[*] enriching with EPSS …", quiet)
        epss_enrich(findings, verbose=not quiet, health=health)

        log("[*] loading CISA KEV catalogue …", quiet)
        kev = load_kev(verbose=not quiet, health=health)
        kev_enrich(findings, kev)

    # ATT&CK mapping
    log("[*] mapping to ATT&CK …", quiet)
    map_findings(findings)

    # false-positive triage + prioritisation
    log("[*] running false-positive checks …", quiet)
    findings = dedupe_findings(findings)
    check_false_positives(findings)
    supp = load_suppressions(args.ignore)
    apply_suppressions(findings, supp)
    score_findings(findings)

    # remediation guidance (needs final scores/labels for SLA dates)
    log("[*] building remediation guidance …", quiet)
    build(findings)
    plan_rows = plan(findings)

    active = sum(1 for f in findings if not f.suppressed and f.confidence >= 0.3)
    log(f"[*] {len(findings)} findings ({active} active after FP triage)", quiet)
    log(f"[*] remediation plan: {len(plan_rows)} package actions", quiet)

    meta = {
        "packages_scanned": len(pkgs),
        "inventory_source": inv_src,
        "online": online,
        "source_notes": src_notes,
        "scan_errors": health.errors,
        "scan_warnings": health.warnings,
    }

    if args.json:
        Path(args.json).write_text(
            json.dumps([f.to_dict() for f in findings], indent=2, default=str))
        log(f"[+] wrote JSON: {args.json}", quiet)

    html_out = render(findings, meta, plan_rows)
    Path(args.output).write_text(html_out, encoding="utf-8")
    log(f"[+] wrote report: {args.output}", quiet)

    if args.md:
        Path(args.md).write_text(_markdown_plan(plan_rows, findings), encoding="utf-8")
        log(f"[+] wrote remediation plan: {args.md}", quiet)

    if not health.complete:
        log(f"[!] incomplete scan: {len(health.errors)} coverage error(s)", quiet)
        return 3
    return _exit_code(findings, args.fail_on, quiet)


def _exit_code(findings, level, quiet=False) -> int:
    """Non-zero exit for CI when findings at/above a threshold remain."""
    if not level:
        return 0
    live = [f for f in findings if not f.suppressed and f.confidence >= 0.3]
    sev = {"critical": {"CRITICAL"}, "high": {"CRITICAL", "HIGH"},
           "medium": {"CRITICAL", "HIGH", "MEDIUM"}}
    if level == "kev":
        hits = [f for f in live if f.kev]
    elif level == "any":
        hits = live
    else:
        hits = [f for f in live if f.cvss_severity in sev[level]]
    if hits:
        log(f"[!] gate '{level}' failed: {len(hits)} finding(s) at or above threshold",
            quiet)
        return 2
    return 0


def _markdown_plan(plan_rows, findings) -> str:
    """Plain-text remediation plan for tickets, PR comments, or email."""
    lines = ["# Remediation plan", ""]
    total = sum(len(g["cves"]) for g in plan_rows)
    lines.append(f"{len(plan_rows)} package actions covering {total} findings, "
                 f"highest risk first.")
    lines.append("")
    for i, g in enumerate(plan_rows, 1):
        head = (f"{g['name']} {g['version'] or '?'} -> {g['target']}"
                if g["target"] else f"{g['name']} {g['version'] or '?'} (review vendor fixes)")
        lines.append(f"## {i}. {head}")
        flags = [g["ecosystem"], f"risk: {g['effort']}", f"verify {len(g['cves'])} findings"]
        if g["kev"]:
            flags.append("**CISA KEV — actively exploited**")
        if g["due"]:
            flags.append(f"due {g['due']}")
        lines += ["", " | ".join(flags), "",
                  f"CVEs: {', '.join(g['cves'])}", "", g["effort_note"], ""]
        if g["commands"]:
            lines += ["```bash"] + g["commands"] + ["```", ""]
        if g["mitigations"]:
            lines.append("Interim controls:")
            lines += [f"- {m}" for m in g["mitigations"]] + [""]
        if g["verification"]:
            lines += ["Verify:", "```bash", g["verification"], "```", ""]
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(
        description="PatchRoute: vulnerability scanner with EPSS/KEV/ATT&CK enrichment "
                    "and false-positive triage → HTML report.")
    p.add_argument("--version", action="version", version=f"PatchRoute {VERSION}")
    src = p.add_argument_group("inventory source (choose one)")
    src.add_argument("--input", metavar="PATH", nargs="+",
                     help="inventory file(s) or directory. Supported: "
                          + SUPPORTED_HELP)
    src.add_argument("--host", action="store_true",
                     help="scan this machine's installed packages")
    src.add_argument("--demo", action="store_true",
                     help="use bundled offline sample data (no network)")

    p.add_argument("-o", "--output", default="patchroute-report.html",
                   help="HTML report path (default: patchroute-report.html)")
    p.add_argument("--json", metavar="FILE", help="also write findings as JSON")
    p.add_argument("--md", metavar="FILE",
                   help="also write the remediation plan as Markdown (for tickets/PRs)")
    p.add_argument("--ignore", metavar="FILE",
                   help="suppression file (.vulnignore)")
    p.add_argument("--nvd-key", metavar="KEY",
                   help="NVD API key (raises rate limit; optional)")
    p.add_argument("--ecosystem", default="generic", metavar="ECO",
                   help="ecosystem hint for files that don't state one "
                        "(PyPI, npm, Debian, Red Hat, Alpine, Maven, Go, …)")
    p.add_argument("--no-recurse", action="store_true",
                   help="when --input is a directory, don't descend into subdirectories")
    p.add_argument("--fail-on", metavar="LEVEL", default=None,
                   choices=["kev", "critical", "high", "medium", "any"],
                   help="exit non-zero if findings at/above LEVEL remain (for CI)")
    p.add_argument("--selftest", action="store_true",
                   help="run built-in self-tests and exit")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress logs")

    args = p.parse_args()
    if args.selftest:
        sys.exit(_selftest())
    try:
        sys.exit(run(args))
    except KeyboardInterrupt:
        sys.exit(130)



# ==========================================================================
# SELF-TEST  (python patchroute.py --selftest)
# ==========================================================================
def _selftest() -> int:
    """Verify the scanner works on this machine. Focused on the places where a
    silent bug is dangerous: the version comparator (a wrong answer hides a
    real vulnerability) and the remediation branches."""
    ok = fail = 0

    def check(name, fn):
        nonlocal ok, fail
        try:
            fn()
            print(f"  PASS  {name}")
            ok += 1
        except Exception as e:
            print(f"  FAIL  {name}: {type(e).__name__}: {e}")
            fail += 1

    def t_text():
        txt = ("django==2.2.0\nlodash@4.17.11\njinja2 2.10\nopenssl (1.0.1)\n"
               "# a comment\nhttpd-2.4.6-97.el7.x86_64\n")
        pkgs = parse_text_lines(txt, "generic", "t")
        names = {p.name for p in pkgs}
        assert {"django", "lodash", "jinja2", "openssl", "httpd"} <= names, names
        assert next(p for p in pkgs if p.name == "lodash").ecosystem == "npm"

    def t_csv():
        pkgs = parse_csv("name,version,ecosystem\ndjango,2.2.0,PyPI\n", "generic", "t")
        assert len(pkgs) == 1 and pkgs[0].ecosystem == "PyPI"

    def t_sbom():
        bom = json.dumps({"bomFormat": "CycloneDX", "components": [
            {"name": "django", "version": "2.2.0", "purl": "pkg:pypi/django@2.2.0"}]})
        pkgs = parse_json(bom, "generic", "t")
        assert len(pkgs) == 1 and pkgs[0].ecosystem == "PyPI"

    def t_xlsx_docx_stdlib():
        """The stdlib ZIP+XML readers must work without openpyxl/python-docx."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            x = Path(d) / "i.xlsx"
            _make_min_xlsx(x)
            pkgs = _xlsx_stdlib(x, "generic", "i.xlsx")
            assert any(p.name == "django" and p.version == "2.2.0" for p in pkgs), pkgs

    def t_versions():
        assert _confidently_ge("1.0.1g", "1.0.1g")
        assert _confidently_ge("1.0.1h", "1.0.1g")
        assert _confidently_ge("2.32.0", "2.31.0")
        assert not _confidently_ge("1.0.1", "1.0.1g"), \
            "1.0.1 must NOT be treated as patched against 1.0.1g"
        assert not _confidently_ge("2.14.1", "2.15.0")
        assert not _confidently_ge("2.10", "2.10.1")
        assert not _confidently_ge("1.0rc1", "1.0")
        assert not _confidently_ge("1.0.0-1ubuntu2", "1.0.0-1ubuntu1")

    def t_fp():
        f = Finding(cve="CVE-1", package=Package("x", "", "PyPI"))
        check_false_positives([f])
        assert f.confidence <= 0.4 and any("no-version" in x for x in f.fp_flags)
        affected = Finding(cve="CVE-2", package=Package("x", "2.0", "PyPI"),
                           fixed_versions=["1.5"])
        check_false_positives([affected])
        assert affected.confidence == 1.0, "OSV affected match must not be dismissed"

    def t_lockfiles():
        pipfile = '{"_meta":{},"default":{"requests":{"version":"==2.0"}},"develop":{}}'
        assert parse_json(pipfile, "PyPI", "Pipfile.lock")[0].version == "2.0"
        poetry = '[[package]]\nname = "requests"\nversion = "2.0"\n'
        assert parse_poetry_lock(poetry, "poetry.lock")[0].version == "2.0"

    def t_coverage_and_links():
        from unittest.mock import patch
        health = ScanHealth()
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
            osv_query([Package("requests", "2.0", "PyPI")], health=health)
        assert not health.complete and "OSV batch" in health.errors[0]
        f = Finding("CVE-2", Package("x", "1.0", "PyPI"),
                    references=["javascript:alert(1)", "https://example.org/advisory"])
        assert "javascript:" not in _refs(f) and "https://example.org" in _refs(f)

    def t_plan_candidates():
        fs = [Finding("CVE-1", Package("x", "1.0", "PyPI"), fixed_versions=["1.2"]),
              Finding("CVE-2", Package("x", "1.0", "PyPI"), fixed_versions=["2.0"])]
        score_findings(fs)
        build(fs)
        assert plan(fs)[0]["target"] == "", "conflicting release branches need review"

    def t_remediation():
        def mkf(fixed, supp=False, conf=1.0):
            f = Finding(cve="CVE-1", package=Package("acme", "1.0", "PyPI"),
                        cvss_score=8.0, cvss_severity="HIGH", cwe=["CWE-89"],
                        fixed_versions=fixed)
            f.suppressed, f.confidence = supp, conf
            score_findings([f])
            return f
        up, mit = mkf(["1.2", "1.5"]), mkf([])
        sup, ver = mkf(["1.2"], supp=True), mkf(["1.2"], conf=0.1)
        build([up, mit, sup, ver])
        assert up.remediation.action == "upgrade"
        assert up.remediation.target_version == "1.2", "should pick comparable candidate"
        assert "pip install" in " ".join(up.remediation.commands)
        assert mit.remediation.action == "mitigate" and mit.remediation.mitigations
        assert sup.remediation.action == "monitor"
        assert ver.remediation.action == "verify"

    def t_plan():
        fs = []
        for cve in ("CVE-1", "CVE-2"):
            f = Finding(cve=cve, package=Package("acme", "1.0", "PyPI"),
                        cvss_score=7.0, cvss_severity="HIGH", fixed_versions=["1.2"])
            score_findings([f])
            fs.append(f)
        build(fs)
        rows = plan(fs)
        assert len(rows) == 1 and len(rows[0]["cves"]) == 2, \
            "one upgrade should close both CVEs"

    def t_report():
        pkgs = _demo_inventory()
        fs = _demo_findings(pkgs)
        map_findings(fs)
        check_false_positives(fs)
        score_findings(fs)
        build(fs)
        html_out = render(fs, {"packages_scanned": len(pkgs),
                               "inventory_source": "selftest", "online": False},
                          plan(fs))
        assert "<!doctype html>" in html_out.lower()
        assert "Remediation plan" in html_out
        assert "{css}" not in html_out and "{body}" not in html_out, \
            "unrendered template placeholder"

    print("patchroute self-test\n")
    for name, fn in [("text line heuristics", t_text),
                     ("csv parsing", t_csv),
                     ("CycloneDX SBOM", t_sbom),
                     ("stdlib xlsx reader", t_xlsx_docx_stdlib),
                     ("version comparator fails safe", t_versions),
                     ("false-positive flags", t_fp),
                     ("Pipfile and Poetry locks", t_lockfiles),
                     ("failed feed and safe links", t_coverage_and_links),
                     ("conflicting fix candidates", t_plan_candidates),
                     ("remediation branches", t_remediation),
                     ("consolidated plan grouping", t_plan),
                     ("HTML report renders", t_report)]:
        check(name, fn)
    print(f"\n{ok} passed, {fail} failed")
    return 1 if fail else 0


def _make_min_xlsx(path) -> None:
    """Write a minimal 2-row xlsx, used only by the self-test."""
    import zipfile as _z
    ss = ('<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/'
          'spreadsheetml/2006/main" count="4" uniqueCount="4">'
          "<si><t>name</t></si><si><t>version</t></si>"
          "<si><t>django</t></si><si><t>2.2.0</t></si></sst>")
    sheet = ('<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/'
             'spreadsheetml/2006/main"><sheetData>'
             '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>'
             '<row r="2"><c r="A2" t="s"><v>2</v></c><c r="B2" t="s"><v>3</v></c></row>'
             "</sheetData></worksheet>")
    ct = ('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
          'package/2006/content-types"><Default Extension="xml" '
          'ContentType="application/xml"/></Types>')
    with _z.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("xl/sharedStrings.xml", ss)
        z.writestr("xl/worksheets/sheet1.xml", sheet)


if __name__ == "__main__":
    main()
