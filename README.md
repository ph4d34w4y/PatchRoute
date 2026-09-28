# PatchRoute

**Turn a software inventory into a prioritized vulnerability review and patch plan.**

A dependency-light vulnerability scanner that matches your installed software
against public vulnerability databases, enriches every finding with **EPSS**,
**CISA KEV**, and **MITRE ATT&CK**, runs **false-positive triage**, produces
**step-by-step remediation**, and writes a single self-contained **HTML report**.

Reads inventories from **txt, csv, xlsx, docx, pdf, JSON/SBOM, XML and
selected lockfiles** — or straight off a live host.

**It's one file.** `patchroute.py` is the entire program: copy it to a server,
drop it in a CI job, run it. No installation is needed for core formats.

It is a *defensive* / vulnerability-management tool: it identifies and ranks
known vulnerabilities so you can patch them. It never exploits anything.

```bash
python patchroute.py --selftest                             # verify it works here
python patchroute.py --demo -o report.html                  # offline sample, no network
python patchroute.py --input inventory.xlsx -o report.html  # spreadsheet
python patchroute.py --input inventory.docx -o report.html  # Word doc
python patchroute.py --input ./inventories/ -o report.html  # a whole folder
python patchroute.py --host -o report.html                  # scan this machine
```

Start with the offline demo, then open `report.html` in a browser:

```bash
python patchroute.py --selftest
python patchroute.py --demo -o report.html
```

For a live scan, use a pinned inventory or SBOM and specify the ecosystem when
the input does not include one:

```bash
python patchroute.py --input requirements.txt --ecosystem PyPI -o report.html
```

Live scans need HTTPS access to OSV, NVD, FIRST EPSS, and CISA KEV. Package
names and versions are sent to OSV; the generated report stays local.

Optional installation: `pip install .` provides the `patchroute` command.
Direct `python patchroute.py` use needs no installation.

## Requirements

Python 3.9+ and nothing else. Every import is standard library, so it drops
onto a bare host and runs. Verify on arrival with `python patchroute.py --selftest`.

Optional extras improve things but are never required:

| Package | Adds |
|---|---|
| `pdfplumber` *or* `pypdf` | PDF input (the only format that needs a library) |
| `openpyxl` / `python-docx` | More robust Office parsing — the built-in ZIP+XML readers already handle standard files |
| `PyYAML` | YAML input |

An NVD API key (`--nvd-key`) raises the NVD rate limit; useful for large
inventories, optional otherwise.

## What it does

| Stage | Source | Purpose |
|-------|--------|---------|
| Inventory | `--input` file, or live `dpkg`/`rpm`/`pip`/`npm` | what software is present |
| Match | [OSV.dev](https://osv.dev) | package + version → known vulnerabilities |
| Severity | [NVD 2.0](https://nvd.nist.gov) | CVSS score/vector + CWE |
| Exploit likelihood | [EPSS](https://www.first.org/epss/) | probability of exploitation (next 30 days) |
| Known exploitation | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | is it exploited *in the wild* right now |
| Technique mapping | MITRE ATT&CK | how an attacker would use it (via CWE→technique) |
| Triage | built-in | flag false positives, score, and rank |

## Input formats

Point `--input` at one file, several files, or a directory (which is walked
recursively). Format is detected from the extension and contents, not assumed.

| Format | Extensions | Notes |
|---|---|---|
| Spreadsheet | `.xlsx` `.xlsm` | All sheets read. Finds a `name`/`version` header row, else falls back to scanning cells |
| Word | `.docx` | Reads **tables and body paragraphs**, so a prose inventory works too |
| Text | `.txt` `.md` `.log` and anything unrecognised | Line heuristics — see below |
| CSV/TSV | `.csv` `.tsv` | Delimiter auto-sniffed |
| SBOM | `.json` `.xml` | **CycloneDX**, **SPDX**, **Syft** — `purl` gives an exact ecosystem |
| PDF | `.pdf` | Tables + text. Needs `pdfplumber` or `pypdf` (see below) |
| Lockfiles | by name | `requirements.txt` (pinned `==` only), `package-lock.json`, `Pipfile.lock`, `poetry.lock`; other lockfile formats require conversion to SBOM or CSV |
| Console dumps | `.txt` | `pip freeze`, `dpkg -l`, `rpm -qa` output pasted straight into a file |

### Text line heuristics

These all parse, mixed freely in one file — comments and headers are skipped:

```
django==2.2.0                       pip / requirements
lodash@4.17.11                      npm (incl. @scope/name@1.2.3)
jinja2 2.10                         whitespace separated
openssl (1.0.1)                     parenthesised
struts2-core: 2.3.30                colon separated
ii  libssl1.1  1.1.1f-1ubuntu2  ... dpkg -l output
httpd-2.4.6-97.el7.x86_64           rpm -qa output
```

### Ecosystem detection

Accurate results need the right ecosystem (OSV is ecosystem-specific). It is
resolved in this order:

1. An explicit `ecosystem`/`type` column, or a `purl` in an SBOM
2. The filename (`requirements.txt` → PyPI, `package-lock.json` → npm, …)
3. The line format (`name@1.2.3` → npm, `rpm -qa` style → Red Hat)
4. `--ecosystem` — **set this for plain text files**, e.g. `--ecosystem PyPI`

Aliases are accepted: `pip`/`python` → PyPI, `deb`/`apt` → Debian, `rhel`/`dnf`
→ Red Hat, `apk` → Alpine, `rust` → crates.io, and so on.

### Notes on file handling

* `.xlsx` and `.docx` are ZIP+XML and are parsed with the **standard library**,
  so no install is needed. If `openpyxl` / `python-docx` are present they're
  used instead for robustness.
* PDF is the one format needing an extra package: `pip install pdfplumber`
  (best — reads tables) or `pip install pypdf` (lighter). Without either you
  get a clear message, not a stack trace.
* Legacy `.xls` / `.doc` aren't supported — re-save as `.xlsx` / `.docx`.
* Archives are opened with member-count and size limits, and XML is parsed
  without entity expansion, because inventory files often come from elsewhere.

## Remediation

Every finding gets a proposed action, not just a severity label:

* **A candidate fix** — a comparable published fixed version with a suggested command for that ecosystem:
  `pip install --upgrade`, `npm install`, `apt-get install --only-upgrade`,
  `dnf upgrade`, `apk upgrade`, `mvn versions:use-dep-version`, `go get`,
  `cargo update`, `bundle update`, `dotnet add package`, `composer require`.
* **Upgrade risk** — patch / minor / major, derived from the version delta, so
  a breaking major bump is flagged before someone ships it on a Friday.
* **Verification** — the command that confirms the fix actually landed
  (`pip show`, `dpkg -s`, `rpm -q`, `mvn dependency:tree`, …).
* **Interim controls when there is no patch** — compensating controls derived
  from the weakness type: CWE-89 suggests parameterised queries, a WAF rule and
  DB least-privilege; CWE-798 says rotate the credential *and assume
  compromise*; network-reachable issues (`AV:N`) suggest firewalling the port.
* **A deadline** — the CISA KEV due date where one exists (binding for US
  federal agencies, a good benchmark for everyone else), otherwise an SLA date
  from the risk score. Tune `SLA_DAYS` in `patchroute.py`.

The report opens with a **consolidated remediation plan grouped by package**.
A single target is suggested only when all findings on that package have the
same comparable candidate. Re-scan the upgraded package before treating any
finding as closed. Use `--md plan.md` to export it for a ticket or PR.

## Prioritisation

Raw CVSS tells you how *bad* a bug is, not how *likely* it is to hurt you.
PatchRoute blends three signals into one 0–100 priority score:

```
priority = severity(CVSS)·55%  +  likelihood(EPSS)·30%  +  known-exploited(KEV)·15%
           then multiplied by match confidence (false-positive discount)
```

A medium-CVSS bug in KEV with high EPSS can outrank a critical-CVSS bug
with a lower measured EPSS. Missing EPSS is shown as unknown in the report;
the score uses zero for the missing likelihood contribution. The priority bar
shows this decomposition for each finding.

## False-positive handling

Findings are triaged, not blindly listed:

- **Rejected / withdrawn CVEs** (per NVD) are demoted.
- **Version comparisons** do not override OSV affected-version matches.
  Published fixed versions may describe different release branches.
- **No fixed version published** means the vendor advisory needs review; it does
  not by itself lower match confidence.
- **Name-only matches** (no version) are marked low-confidence.
- **De-duplication** across sources.
- **Suppression file** (`--ignore .vulnignore`) for audited, explicit exceptions.

Low-confidence findings are separated into a "Likely false positives" section
rather than deleted, and suppressed findings appear in their own section with
your recorded reason — nothing is silently hidden.

## Usage

```
python patchroute.py [source] [options]

Source (choose one):
  --input PATH [PATH ...]   inventory file(s) or a directory
  --host                    scan installed packages on this machine
  --demo                    bundled offline sample data (no network needed)

Options:
  -o, --output FILE   HTML report path (default: patchroute-report.html)
  --json FILE         also write raw findings as JSON
  --md FILE           also write the remediation plan as Markdown
  --ignore FILE       suppression file (see .vulnignore.example)
  --ecosystem ECO     ecosystem hint for files that don't state one
  --no-recurse        don't descend into subdirectories
  --nvd-key KEY       NVD API key to raise the rate limit
  --fail-on LEVEL     exit 2 if findings remain at/above LEVEL, for CI:
                      kev | critical | high | medium | any
  --selftest          run built-in self-tests and exit
  --version           print the version
  -q, --quiet         suppress progress logs
```

### CI usage

```bash
python patchroute.py --input requirements.txt -o report.html --md plan.md --fail-on kev
```

Exit codes: `0` completed (and gate passed, if set), `2` gate failed,
`3` incomplete scan or enrichment, `130` interrupted. An incomplete scan cannot
pass CI as clean. The report lists coverage errors.

### Inventory file format

JSON:
```json
{ "packages": [ { "name": "django", "version": "2.2.0", "ecosystem": "PyPI" } ] }
```

CSV (header row required): `name,version,ecosystem[,cpe]`

Supported `ecosystem` values map to OSV: `PyPI`, `npm`, `Debian`, `Red Hat`,
`Alpine`, `Go`, `Maven`, `crates.io` (aliases like `pip`, `deb`, `apk` are
accepted).

## Rate limits / network

- Runs offline in `--demo` mode.
- Live scans call OSV, NVD, EPSS, and CISA over HTTPS. If a feed is unreachable,
  the report records the failure and the process exits `3` after writing outputs.
- NVD without an API key is limited to ~5 requests / 30s, so the scanner paces
  itself; pass `--nvd-key` for a large inventory.

## Limitations (read these)

- **Version comparison** is a lightweight built-in parser. It does not certify
  that an upgrade is safe, especially for pre-releases, distribution revisions,
  and separate maintenance branches. Review vendor advisories and re-scan.
- **ATT&CK mapping is heuristic** — a CWE→technique association, not an
  authoritative CVE→ATT&CK link. Use it to reason about attacker behaviour, not
  as ground truth. The report labels it as such.
- OSV coverage is strongest for open-source packages; for OS distro packages,
  results depend on the distro's OSV feed quality.
- **Text and PDF parsing is heuristic.** It handles the common layouts well,
  but always check the "Inventory sources" panel at the bottom of the report to
  confirm the package count matches what you expected. Structured input
  (SBOM > csv/xlsx > text) always gives better results.
- Remediation commands are **suggestions to review, not scripts to pipe into a
  shell**. Version pinning, transitive dependencies and your own change process
  still apply.

## Repository layout

```
patchroute.py              scanner and command-line interface
tests/                     offline regression tests
examples/inventory.json    example inventory for a live scan
.github/workflows/ci.yml   automated checks on pushes and pull requests
pyproject.toml             optional command installation
LICENSE                    MIT license
.vulnignore.example        suppression file template
```

`patchroute.py` is organised into clearly banner-separated sections in dependency
order: data model → parsers → inventory → sources (OSV/NVD) → enrichment
(EPSS/KEV) → ATT&CK → false-positive triage → remediation → HTML report → CLI
→ self-test.

### Editing it

Edit `patchroute.py` directly; it is the editable source in this distribution.
Run `python patchroute.py --selftest` and
`python -m unittest discover -s tests -v` before opening a pull request.

## Contributing

Changes to matching, parser coverage, or CI exit behavior should include a
regression test. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).

### Common tweaks

| Want to change | Where |
|---|---|
| Remediation deadlines | `SLA_DAYS` |
| Risk formula weights | `score_findings()` |
| CWE → ATT&CK mapping | `CWE_TO_ATTACK` |
| Compensating controls | `CWE_MITIGATIONS` |
| Upgrade commands per ecosystem | `_upgrade_commands()` |
| Report colours / layout | `_CSS` |
