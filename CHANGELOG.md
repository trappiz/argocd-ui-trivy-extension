# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-11-03

### Fixed

- Status panel text was oversized: the severity words picked up Argo CD's
  value font while the counts stayed small. The panel now matches Argo CD's
  built-in items, with the count at value size and the severity as secondary
  text.

### Changed

- README screenshots are re-captured at 2x resolution and show the 0.1.1/0.1.2
  layout.

## [0.1.1] - 2026-11-03

### Fixed

- The vulnerabilities table no longer pushes the installed version, fixed
  version and score off-screen in Argo CD's resource panel. Installed and fixed
  versions now share the package column, and long titles wrap to two lines.
- Misconfigurations that fail for more than one container (for example
  `AVD-KSV-0125` once per container) no longer produce duplicate React keys.
- The status panel now shows a "Vulnerabilities" heading and lines up with
  Argo CD's built-in panels. Argo CD does not draw a title for extension
  panels, so the extension renders its own.

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

[Unreleased]: https://github.com/trappiz/argocd-ui-trivy-extension/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/trappiz/argocd-ui-trivy-extension/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/trappiz/argocd-ui-trivy-extension/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/trappiz/argocd-ui-trivy-extension/releases/tag/v0.1.0
