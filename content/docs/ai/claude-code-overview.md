---
title: Claude Code Overview
description: An overview of Claude Code, Anthropic's AI coding agent for terminals, IDEs, and the web.
---

<a href="https://claude.ai/code" target="_blank">Claude Code</a> is an AI coding agent from Anthropic that works directly in your codebase. You describe what you need, and Claude handles the implementation—reading files, writing changes, running tests, and opening pull requests.

## What Claude Code can do

- **Onboard to codebases** - Uses agentic search to map and explain an entire codebase in seconds, without manual context selection.
- **Triage issues into PRs** - Integrates with GitHub, GitLab, and CLI tools to go from reading an issue to submitting a pull request entirely from the terminal.
- **Make multi-file edits** - Understands dependencies across a project and makes coordinated changes across multiple files.
- **Run your toolchain** - Uses your existing test suites, build systems, and command-line tools without requiring a separate setup.

## Where it runs

Claude Code is available in several environments:

| Environment | Access |
|---|---|
| Terminal | `npm install -g @anthropic-ai/claude-code` |
| VS Code / Cursor / Devin Desktop | [VS Code extension](https://marketplace.visualstudio.com/items?itemName=anthropic.claude-code) |
| JetBrains IDEs | [JetBrains plugin](https://plugins.jetbrains.com/plugin/27310-claude-code-beta-) |
| Web and mobile | [claude.ai/code](https://claude.ai/code) |
| Slack | Available via the Slack app directory |

## Models

Claude Code works with the following Claude models:

- **Opus 4.8** - Most capable; also available in Fast mode (2.5× faster, higher cost)
- **Sonnet 4.6** - Balanced capability and speed
- **Haiku 4.5** - Fastest and most cost-efficient

Enterprise users can run Claude Code through existing Amazon Bedrock or Google Cloud Vertex AI instances.

## Plans

Claude Code is included in Claude subscription plans and available through the Claude API.

| Plan | Description | Price |
|---|---|---|
| **Pro** | Short coding sprints in small codebases; access to Sonnet 4.6 and Opus 4.8 | $20/month (or $17/month billed annually) |
| **Max 5x** | Everyday use in larger codebases | $100/month |
| **Max 20x** | Power users with the most access | $200/month |

API usage is billed at [standard API pricing](https://anthropic.com/pricing#api) with no markup.

## Security

Claude Code runs locally in your terminal and communicates directly with model APIs—no backend server or remote code index is involved. It asks for permission before modifying files or running commands.

## System requirements

Claude Code runs on macOS, Linux, and Windows. See the [official setup guide](https://code.claude.com/docs/en/overview) for full system requirements.

## Using Claude Code with Railway

Railway provides first-class Claude Code integration through:

- **[Claude Code plugin](/ai/claude-code-plugin)** - Installs the `use-railway` skill, hooks, and scripts through Claude Code's plugin marketplace.
- **[Agent skills](/ai/agent-skills)** - The `use-railway` skill works with Claude Code and other AI assistants to deploy services, manage environments, and query metrics from the terminal.
- **[MCP server](/ai/mcp-server)** - Connects Claude Code directly to your Railway infrastructure via the Model Context Protocol.
