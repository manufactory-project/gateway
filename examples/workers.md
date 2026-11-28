# workers.yaml

[workers.yaml](workers.yaml) gives three coding agent CLIs (`claude`, `codex`, `agy`) one link and principal each. Its paths are not yet confirmed for production use, so check the audit log for denials when you try it.

It needs three interfaces, `sbx0`, `sbx1` and `sbx2`. The [README setup](../README.md#set-up-with-incus) creates two, so [add a third](../docs/configuration.md#links) first, or setup fails.

What to know about this setup:

- **Login tokens live in the guest.** The CLIs run unmodified with subscription OAuth tokens, which `gateway` does not hide.
- **Path rules are the control.** Vendor API hosts also serve other things, such as telemetry (`/api/event_logging/v2/batch` on `api.anthropic.com`) and organization skills and plugins. The rules allow only the listed paths.
- **Token refresh is always allowed**, as exact-host, exact-path `POST` rules.
- **Interactive login is not.** Allow the login hostname for a few minutes with `gateway grant --ttl 5m`.
- **Use exact hostnames.** These vendor domains serve several products.
- **CA trust.** The CLIs were tested with `NODE_EXTRA_CA_CERTS` and `SSL_CERT_FILE` set to `/etc/ssl/certs/ca-certificates.crt`. Whether they trust the system store without those variables is untested.
