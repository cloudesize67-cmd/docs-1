# Claude Code Session Notes

## Pending: Deploy Claude Code GitHub Action to all repos

The user requested this on 2026-06-06. Complete this before closing.

### What to do
Set up the Claude Code GitHub Action in every active repo so the user can comment `@claude fix this` on any PR to get automated fixes.

### Repos that need the Action added
- [ ] `cloudesize67-cmd/xdk` (priority — has ~28 open Jules PRs with failures)
- [ ] `cloudesize67-cmd/aegis-net`
- [ ] `cloudesize67-cmd/Veritas_misinformation_system`
- [ ] `cloudesize67-cmd/All-projects`
- [ ] `cloudesize67-cmd/Aidevelopment`
- [ ] `cloudesize67-cmd/Integrate-models`
- [ ] `cloudesize67-cmd/gemini`

### Workflow file to add to each repo

Create `.github/workflows/claude.yml`:

```yaml
name: Claude Code
on:
  issue_comment:
    types: [created]
  pull_request_review_comment:
    types: [created]

jobs:
  claude:
    if: contains(github.event.comment.body, '@claude')
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: anthropics/claude-code-action@beta
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Then add `ANTHROPIC_API_KEY` as a secret in each repo under Settings → Secrets → Actions.

### Once set up
On the `xdk` repo, comment `@claude fix all CI failures and merge clean PRs` on the Jules PR backlog to bulk-resolve the ~28 open performance PRs.
