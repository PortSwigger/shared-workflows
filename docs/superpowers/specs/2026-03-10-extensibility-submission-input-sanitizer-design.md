# Extensibility Submission Input Sanitizer — Design

## Problem

Three PortSwigger repositories accept user-controlled input from GitHub events (issue titles, PR titles, usernames, URLs) and pass them into shell execution contexts, creating command injection vulnerabilities:

- **extension-portal**: Fixed inline with `sanitizeText()`, regex URL validation, and `validate_repo.py`
- **bambdas**: Vulnerable — `issue-webhook.yml` and `pr-webhook.yml` echo/curl user inputs directly in `run:` steps
- **BChecks**: Partially mitigated — has hardened runner but same shell injection pattern in `issue_webhook.yml` and `pr_webhook.yml`. Also missing the `if: github.event.repository.fork == false` guard that bambdas has.

## Solution

A shared GitHub Action (`PortSwigger/extensibility-submission-input-sanitizer`) that sanitizes user-controlled inputs and outputs clean values. Consuming workflows use the sanitized outputs with `http-request-action` or `actions/github-script` — eliminating shell execution of user data entirely.

## Action Interface

### Type-Based Validation

The action accepts a `type` input that determines which fields are required and which URL pattern to enforce:

| Type                   | Required Fields                                        | URL Pattern Name   | URL Pattern                                  |
|------------------------|--------------------------------------------------------|--------------------|----------------------------------------------|
| `extension-submission` | title, author, url, version_number, product_compatibility | `github_repo`      | `https://github.com/owner/repo`              |
| `extension-update`     | title, url, version_number                             | `github_pr`        | `https://github.com/PortSwigger/repo/pull/N` |
| `bcheck`               | title, author, url                                     | `github_event_url` | `https://github.com/owner/repo/(issues\|pull)/N` |
| `bambda`               | title, author, url                                     | `github_event_url` | `https://github.com/owner/repo/(issues\|pull)/N` |

Fields not listed as required for a given type are optional. If an optional field is provided, it is still sanitized and output. Fields not applicable to the type (e.g., `version_number` for `bambda`) are ignored — the output is empty regardless of what was passed in.

### Inputs

| Input                  | Required | Description                                          |
|------------------------|----------|------------------------------------------------------|
| `type`                 | yes      | One of: `extension-submission`, `extension-update`, `bcheck`, `bambda` |
| `title`                | yes      | Submission title (issue or PR title)                 |
| `author`               | no       | Author identifier (GitHub login or display name)     |
| `url`                  | no       | URL to validate                                      |
| `version_number`       | no       | Version string (extension types only)                |
| `product_compatibility`| no       | JSON array of product labels (extension-submission only) |

`type` and `title` are unconditionally required at the action input level. All other inputs are optional at the YAML level — required/optional enforcement for them is determined by the `type` (see table above). For example, `author` is required for `bcheck`/`bambda`/`extension-submission` but optional for `extension-update`.

### Outputs

| Output                 | Description                                           |
|------------------------|-------------------------------------------------------|
| `title`                | Sanitized title                                       |
| `author`               | Sanitized author                                      |
| `url`                  | Sanitized and validated URL                           |
| `version_number`       | Validated version string (empty if not provided)      |
| `product_compatibility`| Validated JSON array (`[]` if not provided or not applicable) |
| `error_message`        | Non-empty if validation failed; empty on success      |

## Sanitization Rules

### Text (title, author)

- Strip characters: `< > " ' \``
- Replace newlines/tabs with spaces
- Strip non-printable characters (keep `\x20-\x7E`)
- Length limit: title 200 chars, author 100 chars
- Trim whitespace

### URL

- Max length: 500 chars
- Regex matched against the pattern for the given `type`
- Patterns:
  - `github_repo`: `^https://github\.com/[a-zA-Z0-9][a-zA-Z0-9-]{0,37}[a-zA-Z0-9]/[a-zA-Z0-9_.-]{1,100}/?$`
  - `github_pr`: `^https://github\.com/[Pp]ort[Ss]wigger/[a-zA-Z0-9_.-]{1,100}/pull/\d+/?$`
  - `github_event_url`: `^https://github\.com/[a-zA-Z0-9][a-zA-Z0-9-]{0,37}[a-zA-Z0-9]/[a-zA-Z0-9_.-]{1,100}/(issues|pull)/\d+/?$`

### Version Number (extension types)

- Must match `^[0-9a-zA-Z.-]+$`
- Max 50 chars

### Product Compatibility (extension-submission)

- Must parse as JSON array
- Each entry must be one of: `Community`, `DAST`, `Burp AI`

## Error Handling

The shared action always exits successfully. Validation failures are signalled via the `error_message` output. This allows consuming workflows to handle errors gracefully (post comments, close issues, send notifications) rather than having the job fail silently.

When validation fails, `error_message` contains a human-readable description. The sanitized output fields are empty.

Note: the existing extension-portal extraction step currently `throw`s on validation errors. Since validation responsibility moves to the shared action, the extraction step should be changed to only extract raw values — it should no longer validate or throw. All validation errors come from the sanitizer's `error_message` output.

## Implementation

### Technology

Composite GitHub Action using `actions/github-script`. All user-controlled inputs are passed to the JavaScript via `env:` — never interpolated into shell commands.

### Repository Structure

```
extensibility-submission-input-sanitizer/
├── action.yml
├── README.md
└── .github/
    └── workflows/
        └── test.yml
```

The sanitization logic (~80-100 lines of JS) lives inline in `action.yml` within the `actions/github-script` block.

### Testing

CI workflow (`test.yml`) runs on PR/push and exercises the action with:
- Valid inputs for each type
- Malicious inputs (injection attempts, backticks, newlines)
- Invalid URLs for each pattern
- Missing required fields per type
- Edge cases (empty strings, max-length strings, trailing slashes)

## Consuming Workflow Changes

### bambdas and BChecks

Replace the current vulnerable pattern. Example shown for an **issue webhook** (bambdas):

```yaml
# BEFORE (vulnerable)
- name: Push to Webhook
  run: |
    echo $AUTHOR $TITLE $LINK
    curl "$WEBHOOK" -X POST -H "Content-Type: application/json" -H "Authorization: $AUTH_TOKEN" -d "$AUTHOR"$'\n'"$TITLE"$'\n'"$LINK"
  env:
    AUTHOR: ${{ github.event.issue.user.login }}
    TITLE: ${{ github.event.issue.title }}
    LINK: ${{ github.event.issue.html_url }}
```

With:

```yaml
# AFTER (safe) — issue webhook example
jobs:
  webhook:
    runs-on: ubuntu-latest
    if: github.event.repository.fork == false
    steps:
      - name: Harden runner
        uses: portswigger-tim/safer-runner-action@b2208f653b6bf422e08501155f4df82bad008184 # v1.2.2
        with:
          mode: enforce
          disable-sudo: 'true'
          disable-docker: 'true'
          block-risky-github-subdomains: 'true'

      - name: Sanitize inputs
        id: sanitize
        uses: PortSwigger/extensibility-submission-input-sanitizer@<sha> # v1.0.0
        with:
          type: bambda
          title: ${{ github.event.issue.title }}
          author: ${{ github.event.issue.user.login }}
          url: ${{ github.event.issue.html_url }}

      - name: Post to webhook
        if: steps.sanitize.outputs.error_message == ''
        uses: fjogeleit/http-request-action@<sha>
        with:
          url: ${{ secrets.WEBHOOK_URL }}
          method: POST
          contentType: text/plain
          customHeaders: '{"Authorization": "${{ secrets.AUTH_TOKEN }}"}'
          data: |
            ${{ steps.sanitize.outputs.author }}
            ${{ steps.sanitize.outputs.title }}
            ${{ steps.sanitize.outputs.url }}
```

**PR webhook variant:** identical except event fields change to `github.event.pull_request.user.login`, `github.event.pull_request.title`, and `github.event.pull_request.html_url`. The same `type` (`bambda` or `bcheck`) is used for both issue and PR webhooks — the `github_event_url` pattern accepts both `/issues/N` and `/pull/N` paths.

**Error handling:** when `error_message` is non-empty, the workflow completes successfully with the webhook step skipped. No comment or close action is needed — the malformed input is silently dropped. These webhooks are internal notifications, not user-facing submissions.

**Trigger types:** preserve the existing trigger event types (`opened, reopened` for issues; `opened, reopened` for `pull_request_target`).

**Notes:**
- The `if: github.event.repository.fork == false` guard must be present on all workflows. Bambdas already has it (preserve). BChecks does not — it must be added.
- Add `portswigger-tim/safer-runner-action` to bambdas workflows (BChecks already has it).
- `http-request-action` uses Node.js HTTP client internally (no shell execution), which is why it is safe to pass sanitized outputs directly as the `data` input.
- Use `contentType: text/plain` to match the existing non-JSON payload format. The bambdas issue and PR webhooks currently send `Content-Type: application/json` despite not sending JSON; BChecks webhooks omit the Content-Type header entirely. Both should normalise to `text/plain` which is accurate.
- Pin `http-request-action` to a full SHA at implementation time, matching the existing convention.

### extension-portal

Split the existing `extract-issue-details` job:
1. **Extract step** — existing `actions/github-script` parses the issue template body, extracting raw field values (remove inline sanitization and `throw` calls — raw extraction only)
2. **Sanitize step** — calls the shared action with extracted values and the appropriate type

The extraction step determines the type based on the issue template marker: `template:01-submit-extension` maps to `extension-submission`, `template:02-submit-update` maps to `extension-update`. The extraction step should output this as `steps.extract.outputs.type`, which the sanitize step consumes via `with: type: ${{ steps.extract.outputs.type }}`.

Downstream jobs (`validate-extension`, `submit-extension`, etc.) read from the sanitize step's outputs instead. `validate_repo.py` remains in extension-portal as domain-specific logic.

## Versioning

Git tags (e.g., `v1.0.0`). Consuming workflows pin to a full SHA with a version comment, matching the existing convention across PortSwigger repositories.

## Rollout Order

1. Build and test the action in this repo
2. Update **bambdas** (add hardened runner + shared action + `http-request-action`, preserve existing fork guard)
3. Update **BChecks** (add fork guard + shared action + `http-request-action`)
4. Update **extension-portal** (replace inline sanitization with shared action call)
