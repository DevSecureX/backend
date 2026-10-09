# Third-Party Notices

DevSecureX orchestrates a number of third-party security scanners. **These tools are
not bundled or redistributed in this source repository** — they are installed from their
official upstream sources at container-build time (see `Dockerfile` and
`scripts/install-tools.sh`) and are executed as **separate processes**. DevSecureX does
not link against, modify, or vendor their source code.

Each tool remains under its own license, listed below. If you build and distribute a
container image (or any bundle) that includes these tools, you are responsible for
complying with each tool's redistribution terms (notices, and for copyleft licenses, the
corresponding source offer).

## Security scanners

| Tool | License | Project |
| --- | --- | --- |
| Semgrep (OSS engine) | LGPL-2.1 | https://github.com/semgrep/semgrep |
| Bandit | Apache-2.0 | https://github.com/PyCQA/bandit |
| Checkov | Apache-2.0 | https://github.com/bridgecrewio/checkov |
| Trivy | Apache-2.0 | https://github.com/aquasecurity/trivy |
| Gosec | Apache-2.0 | https://github.com/securego/gosec |
| GitLeaks | MIT | https://github.com/gitleaks/gitleaks |
| TruffleHog | AGPL-3.0 | https://github.com/trufflesecurity/trufflehog |
| ESLint + eslint-plugin-security | MIT / Apache-2.0 | https://github.com/eslint/eslint |
| SpotBugs | LGPL-2.1 | https://github.com/spotbugs/spotbugs |
| FindSecBugs | LGPL-3.0 | https://github.com/find-sec-bugs/find-sec-bugs |
| Brakeman (OSS) | MIT | https://github.com/presidentbeef/brakeman |
| Psalm | MIT | https://github.com/vimeo/psalm |
| Roslynator | Apache-2.0 | https://github.com/dotnet/roslynator |
| CppCheck | GPL-3.0 | https://github.com/danmar/cppcheck |
| Safety | MIT (CLI) | https://github.com/pyupio/safety |

> Versions are defined in `Dockerfile` / `scripts/install-tools.sh`. Refer to each
> upstream project for the exact license text at the version you install.

**Note on copyleft tools:** TruffleHog (AGPL-3.0), CppCheck (GPL-3.0), Semgrep,
SpotBugs and FindSecBugs (LGPL) are invoked as standalone programs. Running a separate
program is aggregation, not a derivative work, so these licenses do not extend to
DevSecureX's own source. Obligations (license text + source offer) would only attach if
you *redistribute* those tools' binaries (e.g. in a published image).

**Note on Safety:** the Safety CLI is MIT-licensed. Its vulnerability database may carry
separate terms. DevSecureX is a non-commercial, educational project and does not
redistribute the database. If you intend commercial use, review Safety's current terms
or substitute an alternative (e.g. Trivy / OSV) for dependency scanning.

## Detection rules

The Semgrep-format rules in `app/rules/*.yaml` are original rulesets authored for
DevSecureX (AI-assisted), informed by public vulnerability research and known exploit
patterns. They are not copied from the Semgrep Registry and are covered by this
project's MIT license.

## Application dependencies

Python and Node dependencies are listed in `app/requirements*.txt` and are
predominantly MIT / BSD / Apache-2.0 / ISC licensed. Generate a full SBOM
(e.g. with Syft) for a complete, version-pinned inventory.
