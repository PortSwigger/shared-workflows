# Extensibility Submission Input Sanitizer Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a shared GitHub Action that sanitizes user-controlled inputs (title, author, URL, etc.) to prevent command injection across extension-portal, bambdas, and BChecks repositories.

**Architecture:** Composite GitHub Action using `actions/github-script` for inline JS sanitization. User inputs are passed via `env:` (never shell-interpolated). Consuming workflows replace vulnerable `run:` steps with the shared action + `fjogeleit/http-request-action` to eliminate shell execution of user data entirely.

**Tech Stack:** GitHub Actions (composite), `actions/github-script@v7`, `fjogeleit/http-request-action@v2`, `portswigger-tim/safer-runner-action@v1.2.2`

**Spec:** `docs/superpowers/specs/2026-03-10-extensibility-submission-input-sanitizer-design.md`

---

## File Structure

### Shared action repo (`extension-portal-details-action/`)

| File | Purpose |
|------|---------|
| `action.yml` | Composite action: inputs, outputs, `actions/github-script` sanitization step |
| `.github/workflows/test.yml` | CI workflow exercising the action with valid, malicious, and invalid inputs |

### Consuming repos (modifications only)

| File | Change |
|------|--------|
| `bambdas/.github/workflows/issue-webhook.yml` | Add hardened runner, replace `run:` with sanitize + http-request-action |
| `bambdas/.github/workflows/pr-webhook.yml` | Add hardened runner, replace `run:` with sanitize + http-request-action |
| `BChecks/.github/workflows/issue_webhook.yml` | Add fork guard, replace `run:` with sanitize + http-request-action |
| `BChecks/.github/workflows/pr_webhook.yml` | Add fork guard, replace `run:` with sanitize + http-request-action |
| `extension-portal/.github/workflows/process-created-issue.yml` | Split extraction from sanitization, remove inline sanitize/throw logic |

### Pinned action SHAs

| Action | SHA | Version |
|--------|-----|---------|
| `actions/github-script` | `f28e40c7f34bde8b3046d885e986cb6290c5673b` | v7 |
| `fjogeleit/http-request-action` | `551353b829c3646756b2ec2b3694f819d7957495` | v2.0.0 |
| `portswigger-tim/safer-runner-action` | `b2208f653b6bf422e08501155f4df82bad008184` | v1.2.2 |

---

## Chunk 1: Build the Shared Action

### Task 1: Create action.yml

**Files:**
- Create: `action.yml`

- [ ] **Step 1: Create `action.yml` with full sanitization logic**

```yaml
name: 'Extensibility Submission Input Sanitizer'
description: 'Sanitizes user-controlled inputs (title, author, URL) to prevent command injection in PortSwigger extensibility workflows'

inputs:
  type:
    description: 'Submission type: extension-submission, extension-update, bcheck, or bambda'
    required: true
  title:
    description: 'Submission title (issue or PR title)'
    required: true
  author:
    description: 'Author identifier (GitHub login or display name)'
    required: false
    default: ''
  url:
    description: 'URL to validate'
    required: false
    default: ''
  version_number:
    description: 'Version string (extension types only)'
    required: false
    default: ''
  product_compatibility:
    description: 'JSON array of product labels (extension-submission only)'
    required: false
    default: ''

outputs:
  title:
    description: 'Sanitized title'
    value: ${{ steps.sanitize.outputs.title }}
  author:
    description: 'Sanitized author'
    value: ${{ steps.sanitize.outputs.author }}
  url:
    description: 'Sanitized and validated URL'
    value: ${{ steps.sanitize.outputs.url }}
  version_number:
    description: 'Validated version string'
    value: ${{ steps.sanitize.outputs.version_number }}
  product_compatibility:
    description: 'Validated JSON array of product labels'
    value: ${{ steps.sanitize.outputs.product_compatibility }}
  error_message:
    description: 'Non-empty if validation failed'
    value: ${{ steps.sanitize.outputs.error_message }}

runs:
  using: 'composite'
  steps:
    - name: Sanitize and validate inputs
      id: sanitize
      uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7
      env:
        INPUT_TYPE: ${{ inputs.type }}
        INPUT_TITLE: ${{ inputs.title }}
        INPUT_AUTHOR: ${{ inputs.author }}
        INPUT_URL: ${{ inputs.url }}
        INPUT_VERSION_NUMBER: ${{ inputs.version_number }}
        INPUT_PRODUCT_COMPATIBILITY: ${{ inputs.product_compatibility }}
      with:
        script: |
          const type = process.env.INPUT_TYPE;
          const rawTitle = process.env.INPUT_TITLE;
          const rawAuthor = process.env.INPUT_AUTHOR;
          const rawUrl = process.env.INPUT_URL;
          const rawVersion = process.env.INPUT_VERSION_NUMBER;
          const rawCompatibility = process.env.INPUT_PRODUCT_COMPATIBILITY;

          // --- Sanitization functions ---

          const sanitizeText = (text, maxLength) => {
            if (!text) return '';
            return text
              .replace(/[<>"'`]/g, '')
              .replace(/[\r\n\t]/g, ' ')
              .replace(/[^\x20-\x7E]/g, '')
              .substring(0, maxLength)
              .trim();
          };

          // --- URL patterns per type ---

          const URL_PATTERNS = {
            'extension-submission': /^https:\/\/github\.com\/[a-zA-Z0-9][a-zA-Z0-9-]{0,37}[a-zA-Z0-9]\/[a-zA-Z0-9_.-]{1,100}\/?$/,
            'extension-update': /^https:\/\/github\.com\/[Pp]ort[Ss]wigger\/[a-zA-Z0-9_.-]{1,100}\/pull\/\d+\/?$/,
            'bcheck': /^https:\/\/github\.com\/[a-zA-Z0-9][a-zA-Z0-9-]{0,37}[a-zA-Z0-9]\/[a-zA-Z0-9_.-]{1,100}\/(issues|pull)\/\d+\/?$/,
            'bambda': /^https:\/\/github\.com\/[a-zA-Z0-9][a-zA-Z0-9-]{0,37}[a-zA-Z0-9]\/[a-zA-Z0-9_.-]{1,100}\/(issues|pull)\/\d+\/?$/,
          };

          // --- Type configuration ---

          const TYPE_CONFIG = {
            'extension-submission': {
              requiredFields: ['title', 'author', 'url', 'version_number', 'product_compatibility'],
              applicableFields: ['title', 'author', 'url', 'version_number', 'product_compatibility'],
            },
            'extension-update': {
              requiredFields: ['title', 'url', 'version_number'],
              applicableFields: ['title', 'author', 'url', 'version_number'],
            },
            'bcheck': {
              requiredFields: ['title', 'author', 'url'],
              applicableFields: ['title', 'author', 'url'],
            },
            'bambda': {
              requiredFields: ['title', 'author', 'url'],
              applicableFields: ['title', 'author', 'url'],
            },
          };

          // --- Validate type ---

          const VALID_TYPES = Object.keys(TYPE_CONFIG);
          if (!VALID_TYPES.includes(type)) {
            core.setOutput('error_message', `Invalid type: "${type}". Must be one of: ${VALID_TYPES.join(', ')}`);
            return;
          }

          const config = TYPE_CONFIG[type];
          const errors = [];

          // --- Sanitize text fields ---

          const title = sanitizeText(rawTitle, 200);
          const author = config.applicableFields.includes('author') ? sanitizeText(rawAuthor, 100) : '';

          // --- Validate URL ---

          let url = '';
          let urlValidated = false;
          if (config.applicableFields.includes('url')) {
            urlValidated = true;
            if (rawUrl && rawUrl.length <= 500) {
              const trimmedUrl = rawUrl.trim();
              if (URL_PATTERNS[type].test(trimmedUrl)) {
                url = trimmedUrl;
              } else {
                errors.push(`Invalid URL format for type "${type}"`);
              }
            } else if (rawUrl && rawUrl.length > 500) {
              errors.push('URL exceeds maximum length of 500 characters');
            }
          }

          // --- Validate version number ---

          let versionNumber = '';
          if (config.applicableFields.includes('version_number') && rawVersion) {
            const trimmedVersion = rawVersion.trim();
            if (/^[0-9a-zA-Z.-]+$/.test(trimmedVersion) && trimmedVersion.length <= 50) {
              versionNumber = trimmedVersion;
            } else {
              errors.push('Invalid version format. Only alphanumeric characters, dots, and hyphens are allowed (max 50 chars)');
            }
          }

          // --- Validate product compatibility ---

          let productCompatibility = '[]';
          if (config.applicableFields.includes('product_compatibility') && rawCompatibility) {
            try {
              const parsed = JSON.parse(rawCompatibility);
              const ALLOWED_VALUES = ['Community', 'DAST', 'Burp AI'];
              if (!Array.isArray(parsed)) {
                errors.push('product_compatibility must be a JSON array');
              } else if (parsed.some(v => !ALLOWED_VALUES.includes(v))) {
                errors.push(`product_compatibility contains invalid values. Allowed: ${ALLOWED_VALUES.join(', ')}`);
              } else {
                productCompatibility = JSON.stringify(parsed);
              }
            } catch (e) {
              errors.push('product_compatibility is not valid JSON');
            }
          }

          // --- Check required fields ---

          const fieldValues = { title, author, url, version_number: versionNumber, product_compatibility: productCompatibility };
          const missingFields = config.requiredFields.filter(field => {
            if (field === 'url' && urlValidated && !url) return false; // already reported as invalid format
            const value = fieldValues[field];
            return !value || value === '[]';
          });
          if (missingFields.length > 0) {
            errors.push(`Missing required fields: ${missingFields.join(', ')}`);
          }

          // --- Set outputs ---

          if (errors.length > 0) {
            core.setOutput('error_message', errors.join('; '));
            core.setOutput('title', '');
            core.setOutput('author', '');
            core.setOutput('url', '');
            core.setOutput('version_number', '');
            core.setOutput('product_compatibility', '[]');
          } else {
            core.setOutput('error_message', '');
            core.setOutput('title', title);
            core.setOutput('author', author);
            core.setOutput('url', url);
            core.setOutput('version_number', versionNumber);
            core.setOutput('product_compatibility', productCompatibility);
          }
```

- [ ] **Step 2: Commit**

```bash
git add action.yml
git commit -m "feat: add composite action for input sanitization"
```

---

### Task 2: Create test workflow

**Files:**
- Create: `.github/workflows/test.yml`

- [ ] **Step 1: Create `.github/workflows/test.yml`**

This workflow exercises the action against itself (`uses: ./`) with a matrix of test cases. Each test job runs the action and asserts expected outputs.

**Important:** All test assertion steps pass action outputs via `env:` to avoid interpolating user-controlled data into shell contexts — practicing the same defense the action is designed to enforce.

```yaml
name: Test sanitizer action

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test-bambda-valid:
    name: "bambda: valid issue inputs"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: bambda
          title: "Add filter for HTTP status codes"
          author: testuser123
          url: "https://github.com/PortSwigger/bambdas/issues/42"
      - name: Assert outputs
        env:
          TITLE: ${{ steps.sanitize.outputs.title }}
          AUTHOR: ${{ steps.sanitize.outputs.author }}
          URL: ${{ steps.sanitize.outputs.url }}
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$TITLE" = "Add filter for HTTP status codes"
          test "$AUTHOR" = "testuser123"
          test "$URL" = "https://github.com/PortSwigger/bambdas/issues/42"
          test "$ERROR" = ""

  test-bambda-valid-pr:
    name: "bambda: valid PR inputs"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: bambda
          title: "Fix response filter"
          author: contributor42
          url: "https://github.com/PortSwigger/bambdas/pull/7"
      - name: Assert outputs
        env:
          TITLE: ${{ steps.sanitize.outputs.title }}
          URL: ${{ steps.sanitize.outputs.url }}
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$TITLE" = "Fix response filter"
          test "$URL" = "https://github.com/PortSwigger/bambdas/pull/7"
          test "$ERROR" = ""

  test-bcheck-valid:
    name: "bcheck: valid issue inputs"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: bcheck
          title: "Add XSS detection check"
          author: securityresearcher
          url: "https://github.com/PortSwigger/BChecks/issues/15"
      - name: Assert outputs
        env:
          TITLE: ${{ steps.sanitize.outputs.title }}
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$TITLE" = "Add XSS detection check"
          test "$ERROR" = ""

  test-extension-submission-valid:
    name: "extension-submission: valid inputs"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: extension-submission
          title: "My Cool Extension"
          author: "ExtensionDev"
          url: "https://github.com/ExtensionDev/my-cool-extension"
          version_number: "1.2.3"
          product_compatibility: '["Community","DAST"]'
      - name: Assert outputs
        env:
          TITLE: ${{ steps.sanitize.outputs.title }}
          AUTHOR: ${{ steps.sanitize.outputs.author }}
          URL: ${{ steps.sanitize.outputs.url }}
          VERSION: ${{ steps.sanitize.outputs.version_number }}
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$TITLE" = "My Cool Extension"
          test "$AUTHOR" = "ExtensionDev"
          test "$URL" = "https://github.com/ExtensionDev/my-cool-extension"
          test "$VERSION" = "1.2.3"
          test "$ERROR" = ""

  test-extension-update-valid:
    name: "extension-update: valid inputs"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: extension-update
          title: "Update My Extension"
          url: "https://github.com/PortSwigger/my-extension/pull/5"
          version_number: "2.0.0"
      - name: Assert outputs
        env:
          TITLE: ${{ steps.sanitize.outputs.title }}
          URL: ${{ steps.sanitize.outputs.url }}
          VERSION: ${{ steps.sanitize.outputs.version_number }}
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$TITLE" = "Update My Extension"
          test "$URL" = "https://github.com/PortSwigger/my-extension/pull/5"
          test "$VERSION" = "2.0.0"
          test "$ERROR" = ""

  test-extension-update-author-optional:
    name: "extension-update: author is optional"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: extension-update
          title: "Update My Extension"
          url: "https://github.com/PortSwigger/my-extension/pull/5"
          version_number: "2.0.0"
      - name: Assert no error
        env:
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$ERROR" = ""

  test-malicious-title:
    name: "Malicious title is sanitized"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: bambda
          title: 'Test <script>alert("xss")</script> `$(whoami)`'
          author: testuser
          url: "https://github.com/owner/repo/issues/1"
      - name: Assert dangerous chars stripped
        env:
          TITLE: ${{ steps.sanitize.outputs.title }}
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          # Should not contain < > " ' `
          if echo "$TITLE" | grep -q '[<>"`'"'"']'; then
            echo "FAIL: title still contains dangerous characters: $TITLE"
            exit 1
          fi
          test "$ERROR" = ""

  test-newline-injection:
    name: "Newlines in title are replaced with spaces"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: bambda
          title: "Line1\nLine2\rLine3\tTabbed"
          author: testuser
          url: "https://github.com/owner/repo/issues/1"
      - name: Assert no newlines or tabs in output
        env:
          TITLE: ${{ steps.sanitize.outputs.title }}
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          if echo "$TITLE" | grep -Pq '[\r\n\t]'; then
            echo "FAIL: title still contains newlines or tabs: $TITLE"
            exit 1
          fi
          test "$ERROR" = ""

  test-max-length-title:
    name: "Title exceeding 200 chars is truncated"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: bambda
          title: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          author: testuser
          url: "https://github.com/owner/repo/issues/1"
      - name: Assert title is truncated to 200 chars
        env:
          TITLE: ${{ steps.sanitize.outputs.title }}
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          len=${#TITLE}
          if [ "$len" -gt 200 ]; then
            echo "FAIL: title length is $len, expected <= 200"
            exit 1
          fi
          test "$ERROR" = ""

  test-invalid-url-bambda:
    name: "bambda: rejects non-GitHub URL"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: bambda
          title: "Test"
          author: testuser
          url: "https://evil.com/exfil?data=secret"
      - name: Assert error
        env:
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$ERROR" != ""

  test-invalid-url-extension:
    name: "extension-submission: rejects non-repo URL"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: extension-submission
          title: "My Extension"
          author: dev
          url: "https://github.com/owner/repo/issues/1"
          version_number: "1.0.0"
          product_compatibility: '["Community"]'
      - name: Assert error - issues URL not valid for extension-submission
        env:
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$ERROR" != ""

  test-missing-required-fields-bambda:
    name: "bambda: missing author produces error"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: bambda
          title: "Test"
          url: "https://github.com/owner/repo/issues/1"
      - name: Assert error mentions missing author
        env:
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          if ! echo "$ERROR" | grep -qi "author"; then
            echo "FAIL: error_message should mention missing author: $ERROR"
            exit 1
          fi

  test-missing-required-fields-extension:
    name: "extension-submission: missing version produces error"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: extension-submission
          title: "My Extension"
          author: dev
          url: "https://github.com/dev/my-extension"
          product_compatibility: '["Community"]'
      - name: Assert error mentions missing version
        env:
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          if ! echo "$ERROR" | grep -qi "version"; then
            echo "FAIL: error_message should mention missing version_number: $ERROR"
            exit 1
          fi

  test-invalid-version:
    name: "extension-submission: invalid version format"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: extension-submission
          title: "My Extension"
          author: dev
          url: "https://github.com/dev/my-extension"
          version_number: "1.0; rm -rf /"
          product_compatibility: '["Community"]'
      - name: Assert error
        env:
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$ERROR" != ""

  test-invalid-product-compatibility:
    name: "extension-submission: invalid product compatibility"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: extension-submission
          title: "My Extension"
          author: dev
          url: "https://github.com/dev/my-extension"
          version_number: "1.0.0"
          product_compatibility: '["Community","InvalidProduct"]'
      - name: Assert error
        env:
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$ERROR" != ""

  test-invalid-type:
    name: "Invalid type produces error"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: invalid-type
          title: "Test"
      - name: Assert error
        env:
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$ERROR" != ""

  test-url-trailing-slash:
    name: "URL with trailing slash accepted"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: extension-submission
          title: "My Extension"
          author: dev
          url: "https://github.com/dev/my-extension/"
          version_number: "1.0.0"
          product_compatibility: '["Community"]'
      - name: Assert accepted
        env:
          URL: ${{ steps.sanitize.outputs.url }}
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$URL" = "https://github.com/dev/my-extension/"
          test "$ERROR" = ""

  test-non-applicable-fields-ignored:
    name: "bambda: version_number is ignored"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Run sanitizer
        id: sanitize
        uses: ./
        with:
          type: bambda
          title: "Test"
          author: testuser
          url: "https://github.com/owner/repo/issues/1"
          version_number: "1.0.0"
      - name: Assert version_number is empty (not applicable)
        env:
          VERSION: ${{ steps.sanitize.outputs.version_number }}
          ERROR: ${{ steps.sanitize.outputs.error_message }}
        run: |
          test "$VERSION" = ""
          test "$ERROR" = ""
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "test: add CI workflow to exercise sanitizer action"
```

---

## Chunk 2: Update bambdas Workflows

### Task 3: Update bambdas issue-webhook.yml

**Files:**
- Modify: `~/code/bambdas/.github/workflows/issue-webhook.yml` (entire file)

- [ ] **Step 1: Replace `issue-webhook.yml`**

Replace the entire file contents with:

```yaml
name: Issues Webhook

on:
  issues:
    types: [opened, reopened]

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
        uses: fjogeleit/http-request-action@551353b829c3646756b2ec2b3694f819d7957495 # v2.0.0
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

> **Note:** Replace `<sha>` with the actual commit SHA of the shared action once it is published and tagged as `v1.0.0`.

- [ ] **Step 2: Verify no other changes needed**

Run: `cd ~/code/bambdas && git diff`

Confirm only `issue-webhook.yml` is changed.

---

### Task 4: Update bambdas pr-webhook.yml

**Files:**
- Modify: `~/code/bambdas/.github/workflows/pr-webhook.yml` (entire file)

- [ ] **Step 1: Replace `pr-webhook.yml`**

Replace the entire file contents with:

```yaml
name: Pull Request Webhook

on:
  pull_request_target:
    types: [opened, reopened]

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
          title: ${{ github.event.pull_request.title }}
          author: ${{ github.event.pull_request.user.login }}
          url: ${{ github.event.pull_request.html_url }}

      - name: Post to webhook
        if: steps.sanitize.outputs.error_message == ''
        uses: fjogeleit/http-request-action@551353b829c3646756b2ec2b3694f819d7957495 # v2.0.0
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

- [ ] **Step 2: Commit bambdas changes**

```bash
cd ~/code/bambdas
git add .github/workflows/issue-webhook.yml .github/workflows/pr-webhook.yml
git commit -m "security: replace vulnerable webhook steps with shared input sanitizer

Add hardened runner to both workflows. Replace direct shell execution of
user-controlled inputs with shared sanitization action and http-request-action,
eliminating command injection risk."
```

---

## Chunk 3: Update BChecks Workflows

### Task 5: Update BChecks issue_webhook.yml

**Files:**
- Modify: `~/code/BChecks/.github/workflows/issue_webhook.yml` (entire file)

- [ ] **Step 1: Replace `issue_webhook.yml`**

Replace the entire file contents with:

```yaml
name: Issues Webhook

on:
  issues:
    types: [opened, reopened]

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
          type: bcheck
          title: ${{ github.event.issue.title }}
          author: ${{ github.event.issue.user.login }}
          url: ${{ github.event.issue.html_url }}

      - name: Post to webhook
        if: steps.sanitize.outputs.error_message == ''
        uses: fjogeleit/http-request-action@551353b829c3646756b2ec2b3694f819d7957495 # v2.0.0
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

> **Note:** This adds `if: github.event.repository.fork == false` which was previously missing from BChecks.

---

### Task 6: Update BChecks pr_webhook.yml

**Files:**
- Modify: `~/code/BChecks/.github/workflows/pr_webhook.yml` (entire file)

- [ ] **Step 1: Replace `pr_webhook.yml`**

Replace the entire file contents with:

```yaml
name: Pull Request Webhook

on:
  pull_request_target:
    types: [opened, reopened]

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
          type: bcheck
          title: ${{ github.event.pull_request.title }}
          author: ${{ github.event.pull_request.user.login }}
          url: ${{ github.event.pull_request.html_url }}

      - name: Post to webhook
        if: steps.sanitize.outputs.error_message == ''
        uses: fjogeleit/http-request-action@551353b829c3646756b2ec2b3694f819d7957495 # v2.0.0
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

- [ ] **Step 2: Commit BChecks changes**

```bash
cd ~/code/BChecks
git add .github/workflows/issue_webhook.yml .github/workflows/pr_webhook.yml
git commit -m "security: replace vulnerable webhook steps with shared input sanitizer

Add fork guard to both workflows (previously missing). Replace direct shell
execution of user-controlled inputs with shared sanitization action and
http-request-action, eliminating command injection risk."
```

---

## Chunk 4: Update extension-portal

### Task 7: Update extension-portal process-created-issue.yml

**Files:**
- Modify: `~/code/extension-portal/.github/workflows/process-created-issue.yml:16-127` (the `extract-issue-details` job)

This is the most complex change. The existing `extract-issue-details` job currently does both extraction AND sanitization/validation in a single `actions/github-script` step. We need to:

1. Strip the sanitization/validation logic from the extract step (keep only raw extraction)
2. Add the extract step output for `type`
3. Add a new sanitize step using the shared action
4. Update job outputs to reference the sanitize step for sanitized values and the sanitize step's error_message

- [ ] **Step 1: Replace the `extract-issue-details` job**

Replace lines 16-127 of `process-created-issue.yml` with:

```yaml
  extract-issue-details:
    if: |
      contains(github.event.issue.body, 'template:01-submit-extension') ||
      contains(github.event.issue.body, 'template:02-submit-update')
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
    outputs:
      url: ${{ steps.sanitize.outputs.url }}
      version_number: ${{ steps.sanitize.outputs.version_number }}
      author: ${{ steps.sanitize.outputs.author }}
      title: ${{ steps.sanitize.outputs.title }}
      error_message: ${{ steps.sanitize.outputs.error_message }}
      product_compatibility: ${{ steps.sanitize.outputs.product_compatibility }}

    steps:
      - name: Extract submission details
        id: extract
        uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7
        with:
          script: |
            const body = context.payload.issue.body || '';
            const EMPTY_RESPONSE = '_No response_';

            const extractField = (pattern, defaultValue = null) => {
              const match = body.match(pattern);
              return match ? match[1].trim() : defaultValue;
            };

            // Determine type
            let type = '';
            if (body.includes('template:01-submit-extension')) {
              type = 'extension-submission';
            } else if (body.includes('template:02-submit-update')) {
              type = 'extension-update';
            }
            core.setOutput('type', type);

            // Extract raw title
            core.setOutput('title', context.payload.issue.title || '');

            // Extract raw author
            const author = extractField(/### Author display name\s+([^\n]+)/) || '';
            core.setOutput('author', author === EMPTY_RESPONSE ? '' : author);

            // Extract raw URL
            let url = '';
            if (type === 'extension-submission') {
              url = extractField(/### Extension URL\s+([^\s]+)/) || '';
            } else if (type === 'extension-update') {
              url = extractField(/### Pull request URL\s+([^\s]+)/) || '';
            }
            core.setOutput('url', url === EMPTY_RESPONSE ? '' : url);

            // Extract raw version number
            const versionNumber = extractField(/### Version number\s+([^\n]+)/) || '';
            core.setOutput('version_number', versionNumber === EMPTY_RESPONSE ? '' : versionNumber);

            // Extract product compatibility
            const compatibilityOptions = ['Community', 'DAST', 'Burp AI'];
            const productCompatibility = compatibilityOptions.filter(label =>
              body.includes(`- [x] ${label}`) || body.includes(`- [X] ${label}`)
            );
            core.setOutput('product_compatibility', JSON.stringify(productCompatibility));

      - name: Sanitize and validate inputs
        id: sanitize
        uses: PortSwigger/extensibility-submission-input-sanitizer@<sha> # v1.0.0
        with:
          type: ${{ steps.extract.outputs.type }}
          title: ${{ steps.extract.outputs.title }}
          author: ${{ steps.extract.outputs.author }}
          url: ${{ steps.extract.outputs.url }}
          version_number: ${{ steps.extract.outputs.version_number }}
          product_compatibility: ${{ steps.extract.outputs.product_compatibility }}
```

- [ ] **Step 2: Verify downstream jobs are unaffected**

The downstream jobs (`validate-extension`, `submit-extension`, `submit-update`, `post-comment`, `close-issue`, `notify-zoom`) all reference `needs.extract-issue-details.outputs.*` which are now wired to the sanitize step's outputs. No changes needed to downstream jobs.

Verify by scanning references:

Run: `cd ~/code/extension-portal && grep -n 'needs.extract-issue-details.outputs' .github/workflows/process-created-issue.yml`

All references should still resolve correctly since the job outputs point to `steps.sanitize.outputs.*`.

- [ ] **Step 3: Commit extension-portal changes**

```bash
cd ~/code/extension-portal
git add .github/workflows/process-created-issue.yml
git commit -m "security: use shared input sanitizer for issue processing

Split extraction from sanitization in extract-issue-details job. Raw field
extraction now happens in a dedicated step, with validation delegated to the
shared extensibility-submission-input-sanitizer action. Removes inline
sanitizeText(), validateVersion(), and validateUrl() functions."
```

---

## Chunk 5: Tag and Publish

### Task 8: Tag the shared action for consumption

**Files:** None (git operations only)

- [ ] **Step 1: Tag the shared action**

```bash
cd ~/code/extension-portal-details-action
git tag v1.0.0
```

- [ ] **Step 2: Note the SHA for consumers**

```bash
git rev-parse v1.0.0
```

Use this SHA to replace all `<sha>` placeholders in the consuming repos' workflow files before pushing.

- [ ] **Step 3: Update consuming repos with actual SHA**

Replace `PortSwigger/extensibility-submission-input-sanitizer@<sha> # v1.0.0` in all four consuming workflow files with the actual SHA from step 2.

Amend the commits in bambdas, BChecks, and extension-portal with the correct SHA, or create follow-up commits.
