# IAQ Security Patrol

A lightweight WordPress security patrol that detects common exploit probes, suspicious 404 scanning, high-speed page bursts, direct URL enumeration, and temporary abusive behavior without requiring an external security service.

The project is intentionally small: it records security events locally, applies temporary IP bans, and exposes a simple WordPress admin view for active bans and recent patrol activity.

## What it does

- Blocks high-confidence exploit and credential-file probes immediately.
- Tracks suspicious PHP, exploit, sensitive-file, and configurable 404 activity.
- Detects rapid page bursts, sustained scraping, and direct URL enumeration.
- Applies temporary IP bans (24 hours by default).
- Supports IPv4 and IPv6 CIDR matching.
- Uses Cloudflare's real visitor IP only when the direct peer is verified as a Cloudflare network address.
- Protects selected legitimate crawler families from false bans using forward-confirmed reverse DNS or published crawler IP feeds where supported.
- Provides an admin dashboard with active bans, suspicious IPs, and recent events.
- Allows administrators to unban an IP or clear the event log.

## Philosophy

IAQ Security Patrol is a defensive traffic filter, not a full web application firewall. Its purpose is to make common probing and abusive automated behavior more expensive while keeping the implementation understandable and auditable.

It does **not** promise to identify every malicious request, replace server-level security controls, or prove that a visitor is human.

## Requirements

- WordPress 6.0 or later
- PHP 7.4 or later
- MySQL/MariaDB supported by the installed WordPress version

## Installation

1. Download or clone this repository.
2. Place the `iaq-security-patrol` directory in `wp-content/plugins/`.
3. Activate **IAQ Security Patrol** in WordPress Admin → Plugins.
4. Open **IAQ Patrol** in the WordPress admin menu.

The plugin creates its event and temporary-ban tables on activation.

## Default behavior

By default the plugin uses:

- 10 suspicious 404 events within 10 minutes before an automatic ban.
- A 24-hour temporary ban.
- Immediate blocking for high-confidence exploit probes.
- Behavioral thresholds for rapid bursts, sustained scraping, and direct URL enumeration.

The current release intentionally keeps these defaults in code rather than exposing a large configuration surface.

## Trusted crawler verification

A crawler name in a User-Agent string is not enough to receive an exemption.

For selected crawler families, IAQ Security Patrol verifies identity using either:

- forward-confirmed reverse DNS; or
- a crawler operator's published IP range feed.

If verification cannot be completed, the request is treated like ordinary traffic rather than being trusted based on its claimed User-Agent.

## Cloudflare

When WordPress is behind Cloudflare, the plugin accepts `CF-Connecting-IP` only when the direct TCP peer belongs to a configured Cloudflare IP range. Forwarded IP headers from arbitrary visitors are not trusted.

The Cloudflare ranges are currently bundled in the plugin source. Review them periodically if you operate behind Cloudflare.

## Data stored

Security events may store:

- visitor IP address;
- User-Agent;
- HTTP method;
- requested URI;
- event reason and risk value;
- response/status context;
- timestamp.

Temporary-ban records store the IP, reason, risk value, creation time, and expiration time.

Administrators should consider their own privacy, retention, and disclosure obligations before deploying traffic logging in production.

## External requests

The plugin may make server-side HTTP requests when verifying certain claimed crawler identities against published IP range feeds. These checks are cached with WordPress transients to reduce repeated remote requests.

No API key is required by this release.

## Security model and limitations

This plugin is one layer of defense. Keep WordPress, themes, plugins, PHP, and the web server patched and use appropriate server/CDN security controls.

Behavioral thresholds can produce false positives on unusual high-volume traffic. Test the defaults against your own traffic patterns before relying on automatic bans in a high-traffic or business-critical environment.

## Development

The project currently uses a deliberately compact single-file plugin architecture so the defensive logic can be audited easily.

Before submitting a pull request:

```bash
php -l iaq-security-patrol.php
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Security reports

Please do not publish exploitable vulnerabilities in a public issue. See [SECURITY.md](SECURITY.md).

## License

IAQ Security Patrol is licensed under the GNU General Public License v2.0 or later. See [LICENSE](LICENSE).
