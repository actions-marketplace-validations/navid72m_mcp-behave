mcp-behave community standards pack

Contents:
- CODE_OF_CONDUCT.md
- README-COMMUNITY-SNIPPET.md (optional section to add to README.md)
- CONTRIBUTING.md (updated with community and security links)
- SECURITY.md (response wording made best-effort rather than a fixed SLA)
- SUPPORT.md
- .github/ISSUE_TEMPLATE/bug_report.yml
- .github/ISSUE_TEMPLATE/feature_request.yml
- .github/ISSUE_TEMPLATE/question.yml
- .github/ISSUE_TEMPLATE/config.yml
- .github/PULL_REQUEST_TEMPLATE.md

Copy the files and preserve the .github directory structure into the root of the mcp-behave repository. The package includes replacements for CONTRIBUTING.md and SECURITY.md; review the diffs before overwriting your current copies.

Suggested README section (add near the contribution/development documentation):

Community & contributing
------------------------
Please read CODE_OF_CONDUCT.md before participating. See CONTRIBUTING.md for development setup and pull-request guidance. Use SUPPORT.md for usage questions and SECURITY.md for private vulnerability reports.

Review note:
The CoC report contact is navid72m@gmail.com; the security disclosure contact remains security@navidmirnouri.com as in the current repository's SECURITY.md.
The current SECURITY.md supported-version boundary (>= 0.4.0) has been preserved; verify this policy whenever the project's release-support policy changes.
