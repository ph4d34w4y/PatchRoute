# Contributing to PatchRoute

Please keep reports and test fixtures free of credentials, internal hostnames,
and private inventories.

1. Open an issue with the behavior, expected result, and a small sanitized
   inventory or mocked API response.
2. Make a focused change to `patchroute.py` and add a regression check under
   `tests/` for coverage or matching changes.
3. Run `python patchroute.py --selftest` and
   `python -m unittest discover -s tests -v`.
4. Open a pull request describing the change and its limits.

For a security issue in PatchRoute itself, use GitHub's private vulnerability
reporting feature if enabled for the repository. Avoid posting exploit details
or private scan data in a public issue.
