# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- README screenshots now show the extension running in Argo CD 3.5 with real
  trivy-operator data.

## [0.1.0] - 2026-11-03

First release.

### Added

- **Security** tab on Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs,
  CronJobs, Pods, Argo Rollouts, Services, Ingresses and NetworkPolicies.
- Vulnerabilities view with a per-container selector, severity totals that
  double as filters, free-text search, a "fix available" filter, sortable
  columns and CSV export.
- Misconfigurations view for `ConfigAuditReport` checks, with remediation hints
  and an option to show passed checks.
- Exposed secrets view for `ExposedSecretReport` findings.
- Application status panel with critical and high totals, and a flyout that
  breaks them down per workload and container.
- Reports are found by following owner references in the application's resource
  tree, so the extension works with trivy-operator's hashed report names and
  ignores reports for superseded ReplicaSets.
- Light and dark theme support.
- Release workflow that publishes `extension-trivy.tar`, a SHA-256 checksum file
  and a build provenance attestation for every tag.
- CI with ESLint (strict, type-aware), Prettier, actionlint, zizmor and
  ShellCheck. Actions are pinned to full commit SHAs and run with job-scoped,
  least-privilege permissions.

[Unreleased]: https://github.com/trappiz/argocd-ui-trivy-extension/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/trappiz/argocd-ui-trivy-extension/releases/tag/v0.1.0
