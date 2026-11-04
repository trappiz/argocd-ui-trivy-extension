# Security policy

## Supported versions

Only the latest release receives fixes. Upgrade by pointing `EXTENSION_URL` and
`EXTENSION_CHECKSUM_URL` at the newest tag on the
[releases page](https://github.com/trappiz/argocd-ui-trivy-extension/releases).

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/trappiz/argocd-ui-trivy-extension/security/advisories/new)
rather than in a public issue. Include the affected version, steps to
reproduce, and the impact you expect.

You can expect an acknowledgement within a few days. Fixes are released as a
new patch version and noted under **Security** in the [changelog](CHANGELOG.md).

## Threat model

The extension runs inside the Argo CD UI with the signed-in user's session and
adds no backend or permissions of its own. It does treat Trivy reports as
untrusted input: they are ordinary custom resources, so anyone who can write
them in a namespace controls their content. Report data is validated before
rendering, links are limited to `http` and `https`, and CSV exports neutralise
spreadsheet formulas.

## Verifying releases

Every release archive has a SHA-256 checksum, which the Argo CD extension
installer checks, and a signed build provenance attestation:

```bash
gh attestation verify extension-trivy.tar --repo trappiz/argocd-ui-trivy-extension
```
