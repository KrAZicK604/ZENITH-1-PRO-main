# Security Policy

## Supported versions

Until the first tagged release is published, the protected `main` branch is
the supported security baseline. After releases begin, only the latest release
and `main` will receive security fixes.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| `main` | Yes |
| Older releases | No |

## Reporting a vulnerability

Do not disclose vulnerability details in a public issue, discussion, pull
request, or commit.

1. Open this repository's **Security** tab.
2. Open **Advisories** and choose **Report a vulnerability** when that option is
   available.
3. If private reporting is unavailable, open a minimal public issue titled
   `Private security contact requested` without including technical details,
   secrets, exploit code, or affected data.

Include the affected version or commit, potential impact, reproduction steps,
and any suggested mitigation. Remove credentials, personal information, and
unrelated data before submitting a report.

## Scope

Security reports may cover the application source, dependency configuration,
GitHub Actions workflows, development-container configuration, and documented
local execution path.

The project is a deterministic research and visualization lab. It does not
provide production authority, financial execution, safety-critical control, or
permission to test systems or data that you do not own or administer.

## Handling reports

Reports are validated privately before disclosure. Confirmed issues should be
fixed on a review branch, pass the repository's required checks, and be
documented in a security advisory or release note when disclosure is safe.
Response and remediation timing depends on severity and maintainer capacity;
this project does not currently promise a fixed service-level agreement.
