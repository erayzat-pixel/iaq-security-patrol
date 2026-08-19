# Security Policy

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a vulnerability that could be used to attack sites running IAQ Security Patrol.

Use GitHub's **Private Vulnerability Reporting / Security Advisory** feature for the repository when available. Include:

- affected version;
- WordPress and PHP versions;
- a concise description of the issue;
- reproduction steps or proof of concept;
- expected security impact;
- any suggested mitigation, if known.

Please avoid including real visitor IP addresses, credentials, access tokens, private server paths, or production logs unless they are strictly necessary and have been appropriately redacted.

## Supported versions

Until the project has multiple maintained release branches, security fixes target the latest published release.

## Scope

Security reports are especially useful for issues involving:

- authentication or authorization bypass;
- unsafe trust of forwarded IP headers;
- bypass of temporary bans;
- SQL injection;
- stored or reflected XSS in the admin interface;
- CSRF in administrative actions;
- crawler-verification bypasses;
- denial-of-service behavior created by the plugin itself;
- unsafe handling of remote crawler IP feeds.
