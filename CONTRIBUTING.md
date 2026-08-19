# Contributing

Thanks for helping improve IAQ Security Patrol.

## Before opening a pull request

1. Keep changes narrowly scoped.
2. Preserve WordPress coding and security conventions.
3. Sanitize untrusted input and escape output at render time.
4. Use WordPress nonces and capability checks for state-changing admin actions.
5. Do not trust forwarding headers unless the direct proxy peer is verified.
6. Do not exempt bots based only on a User-Agent claim.
7. Avoid adding remote services, telemetry, or dependencies without a clear security reason and documentation.
8. Run a PHP syntax check:

```bash
php -l iaq-security-patrol.php
```

## Pull request notes

Explain:

- the behavior being changed;
- why the change is needed;
- possible false-positive/false-negative effects;
- how the change was tested;
- whether database schema or stored data changes.

## Privacy

Do not commit production logs, real visitor IP addresses, credentials, API keys, tokens, `.env` files, database exports, or private infrastructure details.
