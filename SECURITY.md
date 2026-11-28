# Security policy

`gateway` sits between untrusted guests and the network, so containment bugs matter more than most.

## Reporting a vulnerability

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue, pull request or discussion for it.

Include what you need to reproduce it: the `gateway` version or commit, the config (with secrets removed), what the guest did, and what got through.

Reports that show a guest reaching something the [threat model](docs/threat-model.md) says it cannot are in scope. Behaviour the threat model lists as not protected or as an accepted risk is not a vulnerability, but a report that it is worse than described is welcome.

## Supported versions

Only the latest release gets security fixes.
