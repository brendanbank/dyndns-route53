# Releasing a New Version

## Prerequisites

- Push access to `main` and permission to create tags
- All changes merged to `main`

## Release Process

1. Ensure your changes are committed and pushed to `main`:
   ```bash
   git checkout main
   git pull
   ```

2. Create and push a version tag:
   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```

   The tag **must** start with `v` (e.g. `v1.0.0`, `v1.2.3`).

## What Happens Automatically

When you push a `v*` tag, the GitHub Actions workflow:

1. Builds a multi-platform Docker image (`linux/amd64` + `linux/arm64`)
2. Pushes it to `ghcr.io/brendanbank/dyndns-route53` with semver tags
3. Creates a GitHub Release with auto-generated release notes

### Image Tag Strategy

| Git Tag | Docker Tags |
|---------|-------------|
| `v1.2.3` | `1.2.3`, `1.2`, `1`, `latest` |
| `v2.0.0` | `2.0.0`, `2.0`, `2`, `latest` |
| PR #42 | `pr-42` |

## Post-Release

1. Verify the release on the [GitHub Releases page](https://github.com/brendanbank/dyndns-route53/releases)
2. Test the published image:
   ```bash
   docker pull ghcr.io/brendanbank/dyndns-route53:latest
   ```

## GHCR Package Visibility

New GHCR packages default to **private**. For the first release, you must manually set the package to public:

1. Go to the [package settings page](https://github.com/users/brendanbank/packages/container/dyndns-route53/settings)
2. Scroll to **Danger Zone** > **Change visibility**
3. Set to **Public**

This cannot be done via the API for user-owned container packages.
