# ReversingLabs GitHub Action: rl-protect

ReversingLabs provides the officially supported GitHub Action for faster and easier use of the `rl-protect` tool in CI/CD workflows.
The action runs before any build job to scan open source dependencies and prevent those with vulnerabilities and security risks from being used during subsequent build jobs.

## What is rl-protect?

`rl-protect` is a CLI tool that scans manifest files for popular software package formats (npm, PyPI, RubyGems) to identify threats in open source dependencies before they are installed.
It can also be used for quick security checks by providing a specific software package URL.
In both cases, `rl-protect` connects to the [Spectra Assure Community](https://docs.secure.software/community) API to retrieve the latest information on analyzed open source software packages.

Spectra Assure is a software supply chain security platform created by ReversingLabs to help organizations develop and release software with confidence.
To provide a shift-left solution for software producers who work with third-party open source packages, ReversingLabs developed `rl-protect`.

## Requirements

**A valid token for your Spectra Assure Community or Portal user account**.

 Community tokens have the prefix `rlcmm`, and Portal tokens have the prefix `rls3c`. The token is required for authenticating to the Spectra Assure APIs. To obtain the token, follow the instructions in the [Spectra Assure Community](https://docs.secure.software/community/api/#get-started-with-the-community-api) or the [Spectra Assure Portal](https://docs.secure.software/api/generate-api-token) documentation depending on the account you want to use.

## Environment variables

This action requires the rl-token license data to be passed via the environment using a environment variable.

| Environment variable | Mandatory | 	Description |
| --                   | --        | --            |
| RL_TOKEN	| **yes**  | The token for authenticating to the Spectra Assure Community or the Spectra Assure Portal account. <br>Community tokens have the prefix `rlcmm`, and Portal tokens have the prefix `rls3c`.  |

ReversingLabs **strongly** recommends following best security practices and defining these secrets on the level of your GitHub organization or repository.

## Input parameters

| Name           | Required | Type     | Description |
| --             | --       | --       | --          |
| scan-path      | **yes**      | `string` | Path to a package manifest or lock file that should be checked. The current supported types can be found at: [package-manifest-coverage](https://docs.secure.software/concepts/package-manifest-coverage). |
| scan-profile   | no       | `string` | Name of a pre-configured profile or the path to a file that contains a custom rl-profile configuration. <br>Pre-configured profile names are: `minimum`, `baseline`, `hardened`. <br>If this parameter is not specified, `hardened` profile is used by default for Community accounts. <br>For Enterprise (Portal) accounts, an existing profile is imported from the Portal. |
| rl-server      | *depends*  | `string` | Applies only for Portal accounts. Name of the Spectra Assure Portal instance to connect to (example: my.secure.software/organization). |
| rl-org         | *depends*  | `string` | Applies only for Portal accounts. Name of the Spectra Assure Portal organization. The organization must exist on the Portal instance specified with `rl-server`. <br>The user account authenticated with the token must be a member of the specified organization and have the appropriate permissions. Organization names are case-sensitive. |
| rl-group       | no       | `string` | Applies only for Portal accounts. Name of the Spectra Assure Portal group. <br>The group must exist in the Portal organization specified with `rl-org`. Group names are case-sensitive. |
| check-deps     | no       | `string` | Default: `release`. Check for dependencies of the specified type. Multiple types can be specified as comma-separated values. <br>If using this parameter, at least one of the following values is required: `release`, `develop`. <br>Values `transitive` and `optional` are not required, but if you want to specify them, one of the required values must be present in the command. |
| transitive-depth | no     | `int`    | Specifies how many levels deep to scan transitive dependencies, as an integer value. This parameter applies only if `check-deps=transitive` is set. It defaults to `1` if not specified. |
| report         | no       | `string` | Path and filename for exporting the scan results as an `rl-protect.json` report. |
| verbose        | no       | `bool`   | Default: `false`. Increase script verbosity when running the action. |
| concise        | no       | `bool`   | Default: `false`. Do not show scan details just summarize the final result. |
| log-file       | no       | `string` | Path to a log file (will be created if it doesn't exist). Logs are kept in the CEF format. |
| log-level      | no       | `string` | Specifies the logging level as one of the following values: `pass`, `warning`, `fail`. The default value is `fail` (only failed events are logged). |
| log-label      | no       | `string` | A custom label to identify the logging source in SIEM (maximum 511 characters). |
| proxy-server   | no       | `string` | Optional configuration for a proxy server (DNS name or IP address). If specified, the `proxy-port` parameter becomes mandatory. |
| proxy-port     | no       | `int`    | The network port for proxy configuration. |
| proxy-user     | no       | `string` | If the proxy requires authentication, use this parameter to provide the user name. Must be used together with `proxy-password`. |
| proxy-password | no       | `string` | If the proxy requires authentication, use this parameter to provide the password. Must be used together with `proxy-user`. |

**For more details on all supported parameters, consult the [official rl-protect documentation](https://docs.secure.software/community/tools/rl-protect).**

## Artifact selection parameters

These parameters pin the scan to the artifact that would actually be installed on a specific target platform, instead of assessing the package as a whole.
Artifact selection currently applies to PyPI packages only.

Selection is off unless `target-python` is set. All other parameters in this table require it.

| Name                  | Required | Type     | Description |
| --                    | --       | --       | --          |
| target-python         | *depends* | `string` | Target Python version, for example `3.12` or `312`. Required to enable artifact selection: without it, none of the parameters below are passed to `rl-protect`. |
| target-platform       | no       | `string` | Comma-separated list of platform tags (for example `manylinux_2_28_x86_64`) or presets (for example `linux-x86_64`). Each value is passed to `rl-protect` as a separate `--target-platform` flag. See [Naming a platform](#naming-a-platform). |
| target-os             | no       | `string` | Target OS: `linux`, `macos`, or `windows`. Accepts an optional `:version` suffix that acts as a macOS deployment-target floor, for example `macos:12.0`. Must be used together with `target-arch`. |
| target-arch           | no       | `string` | Target CPU architecture: `x86_64`, `x86`, or `arm64`. Must be used together with `target-os`. |
| target-libc           | no       | `string` | Target Linux libc: `glibc`, `musl`, or `none` (default on Linux: `glibc`). Accepts an optional `:version` suffix that acts as a floor, for example `glibc:2.34`. Requires `target-os` and `target-arch`. |
| target-implementation | no       | `string` | Target Python interpreter: `cp` (default), `pp`, `jy`, `ip`, or `py`. |
| target-abi            | no       | `string` | Comma-separated list of ABI tags, for example `cp312,abi3,none`. Each value is passed to `rl-protect` as a separate `--target-abi` flag. By default the compatible ABIs are derived from `target-python`. |

If `rl-protect` cannot find a wheel compatible with the target, it falls back to the version's source distribution when one exists. Otherwise no artifact is pinned.

### Naming a platform

There are two ways to name the target platform. Use whichever is more convenient, but not both at once.

The first is `target-platform`, which accepts either a preset or an explicit platform tag. Presets bake in sensible baselines (glibc 2.28, musl 1.2, macOS 11.0); pass an explicit tag when you need a different baseline.

| Preset | Aliases | Platform tag |
| --     | --      | --           |
| `linux-x86_64`       | `linux-x64`, `linux-amd64` | `manylinux_2_28_x86_64` |
| `linux-aarch64`      | `linux-arm64`              | `manylinux_2_28_aarch64` |
| `linux-musl-x86_64`  | `linux-musl-x64`           | `musllinux_1_2_x86_64` |
| `linux-musl-aarch64` | `linux-musl-arm64`         | `musllinux_1_2_aarch64` |
| `macos-arm64`        | `macos-aarch64`            | `macosx_11_0_arm64` |
| `macos-x86_64`       | `macos-x64`, `macos-intel` | `macosx_11_0_x86_64` |
| `windows-x64`        | `windows-amd64`, `win64`   | `win_amd64` |
| `windows-x86`        |                            | `win32` |
| `windows-arm64`      |                            | `win_arm64` |

The second is to compose the platform from its parts with `target-os` and `target-arch`, which must be given together, optionally adding `target-libc` on Linux.

```yaml
        with:
          scan-path: 'requirements.txt'
          check-deps: 'release'
          target-python: '3.12'
          target-os: 'linux'
          target-arch: 'x86_64'
          target-libc: 'glibc:2.34'
```

Prefer one form or the other. If you supply both, `rl-protect` selects artifacts matching either form (their union) rather than letting one override the other, which usually widens selection more than intended. The action prints a warning in this case.

### Usage example: scanning for a release target

This pins the scan to the wheels that would be installed on the container image the build produces.

```yaml
      - name: gh-action-rl-protect-scan
        uses: reversinglabs/gh-action-rl-protect-scan@v1
        id: rl-protect
        env:
          RL_TOKEN: ${{ secrets.RL_TOKEN }}
        with:
          scan-path: 'uv.lock'
          check-deps: 'release,transitive'
          target-python: '3.12'
          target-platform: 'linux-x86_64'
          target-abi: 'cp312,abi3'
```

## PR comment parameters

These parameters control the optional PR comment posted by the action.
All are ignored unless `post-pr-comment` is `true`.

| Name                    | Required | Type     | Description |
| --                      | --       | --       | --          |
| post-pr-comment         | no       | `bool`   | Default: `false`. Post scan results as a comment on the pull request. Requires `github-token`. Only runs when the workflow is triggered by a pull request event. |
| github-token            | no       | `string` | GitHub token used to post the PR comment. Pass `secrets.GITHUB_TOKEN`. Required when `post-pr-comment` is `true`. The calling workflow must have `pull-requests: write` permission. |
| comment-template        | no       | `string` | Preset combination of display options: `concise`, `expanded`, or `verbose`. See [PR comment templates](#pr-comment-templates) for details. Individual `comment-*` inputs override the template when set. |
| comment-level           | no       | `string` | Default: `fail`. Controls which packages appear in the PR comment: `fail` shows only rejected packages, `warn` adds packages with warnings. Scan errors are always shown. The count of passed packages is always included in the summary line. Overrides `comment-template` when set. |
| comment-assessment      | no       | `string` | Assessment display style: `simplified` groups non-passing checks into a callout block, `table` shows all checks in a table, `off` hides the assessment section. Overrides `comment-template` when set. |
| comment-vulnerabilities | no       | `bool`   | Default: `true`. Show the CVE vulnerability table in the PR comment. |
| comment-license         | no       | `bool`   | Default: `false`. Show the package license in the PR comment. |
| comment-policy          | no       | `bool`   | Default: `false`. Show the policy violations table in the PR comment. |
| comment-overrides       | no       | `bool`   | Default: `false`. Show override details on assessments and policy violations in the PR comment. |



## Output

| Name        | Type     | Description |
| --          | --       | --          |
| status      | `string` | The single-word result of the action: success, failure or error. |
| description | `string` | The result of the action: a string terminating in FAIL or PASS. |

- The `stdout` of the rl-protect command will be available in file `1`.
- The `stderr` of the rl-protect command will be available in file `2`.

## Usage example

To protect your build from any harmful dependencies, the `rl-protect` job runs before the build.
This way, if any dependencies show malicious activities, they will not be used during a subsequent build job.

```yaml

name: RL_PROTECT_JOB

# Controls when the workflow will run
on:
  # Triggers the workflow on push or pull request events but only for the "main" branch
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

  # Allows you to run this workflow manually from the Actions tab
  workflow_dispatch:

# A workflow run is made up of one or more jobs that can run sequentially or in parallel
jobs:
  # This workflow contains a single job called "check_deps" to run before any build job
  check_deps:
    # The type of runner that the job will run on
    runs-on: ubuntu-latest

    # Steps represent a sequence of tasks that will be executed as part of the job
    steps:
      # Checks-out your repository under $GITHUB_WORKSPACE, so your job can access it
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd #v6.0.2

      # ---------------------------------------
      - name: gh-action-rl-protect-scan
        uses: reversinglabs/gh-action-rl-protect-scan@v1
        id: rl-protect
        env: # pass env var secrets
          RL_TOKEN: ${{ secrets.RL_TOKEN }}
        with: # pass ordinary params
          rl-server: 'my.secure.software/myServer'
          rl-org: 'myOrg'
          rl-group: 'myGroup'
          scan-path: 'requirements.txt'
          scan-profile: 'baseline'
          report: 'my-report.json'
          check-deps: 'develop,release'
          verbose: true

      # ---------------------------------------
      - name: Run a multi-line script to show the result of the rl-protect action
        run: |
            echo "Status of rl-protect: ${{steps.rl-protect.outputs.status}}"
            echo "Description of rl-protect: ${{steps.rl-protect.outputs.description}}"
            ls -la
            exit 0
    # build job
```

## PR comment templates

The `comment-template` input selects a preset combination of display options for the PR comment. Individual `comment-*` inputs always take precedence over the template when explicitly set.

| Template | Packages shown | Assessment style | Vulnerabilities | Policy |
|----------|---------------|-----------------|-----------------|--------|
| `concise` | Status summary + package summary table | off | no | no |
| `expanded` | Rejected packages | simplified | yes, with license | no |
| `verbose` | Rejected + warnings | table | yes | yes |

When no template is set the defaults match `expanded`: rejected packages only, simplified assessment, vulnerabilities shown, policy hidden.

### concise — status summary with package table

Posts a status line, package count, and a one-row-per-package summary table showing status and top finding. No per-package detail sections. Useful in high-traffic repositories where comment noise is a concern.

```yaml
      - name: gh-action-rl-protect-scan
        uses: reversinglabs/gh-action-rl-protect-scan@v1
        env:
          RL_TOKEN: ${{ secrets.RL_TOKEN }}
        with:
          scan-path: 'package.json'
          report: 'rl-protect.report.json'
          post-pr-comment: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
          comment-template: 'concise'
```

### expanded — rejected packages

Shows full per-package detail for rejected packages.
This is the recommended default for most teams.

```yaml
      - name: gh-action-rl-protect-scan
        uses: reversinglabs/gh-action-rl-protect-scan@v1
        env:
          RL_TOKEN: ${{ secrets.RL_TOKEN }}
        with:
          scan-path: 'package.json'
          report: 'rl-protect.report.json'
          post-pr-comment: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
          comment-template: 'expanded'
```

### verbose — full audit detail

Shows rejected and warning packages, uses the full assessment table, and includes policy violations and override audit trails.

```yaml
      - name: gh-action-rl-protect-scan
        uses: reversinglabs/gh-action-rl-protect-scan@v1
        env:
          RL_TOKEN: ${{ secrets.RL_TOKEN }}
        with:
          scan-path: 'package.json'
          report: 'rl-protect.report.json'
          post-pr-comment: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
          comment-template: 'verbose'
```

### Overriding template settings

Individual `comment-*` inputs override the template. For example, to use `expanded` but suppress the vulnerability table:

```yaml
          comment-template: 'expanded'
          comment-vulnerabilities: false
```

## Posting scan results as a PR comment

To post scan results as a comment on the pull request, enable `post-pr-comment` and pass the GitHub token.
The calling workflow must have `pull-requests: write` permission.
If a previous comment from the same scan already exists on the PR, it will be updated rather than duplicated.

```yaml
name: RL_PROTECT_JOB

# Triggers on pull requests targeting the main branch
on:
  pull_request:
    branches: [ "main" ]

jobs:
  # Scan dependencies before the build job
  check_deps:
    runs-on: ubuntu-latest

    # Required to post and update PR comments
    permissions:
      pull-requests: write

    steps:
      # Checks-out your repository under $GITHUB_WORKSPACE, so your job can access it
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd #v6.0.2

      # ---------------------------------------
      - name: gh-action-rl-protect-scan
        uses: reversinglabs/gh-action-rl-protect-scan@v1
        id: rl-protect
        env: # pass env var secrets
          RL_TOKEN: ${{ secrets.RL_TOKEN }}
        with: # pass ordinary params
          scan-path: 'requirements.txt'
          report: 'rl-protect.report.json'
          post-pr-comment: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
          comment-assessment: 'simplified'
          comment-level: 'fail'
```
