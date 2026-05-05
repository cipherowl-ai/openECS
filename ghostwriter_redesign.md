# Ghostwriter Redesign Proposal

## Goals
Build a multi-agent writing system that continuously improves article quality for selected audiences while enforcing factual accuracy.

## Core Concepts

### 1) Audience Library
- A repository of audience profiles stored as Markdown files (`audiences/*.md`).
- Each profile captures:
  - Audience name and segment
  - Preferences and tone
  - Content expectations
  - Trust/skepticism heuristics
  - “Good vs bad” examples


### 1.1) Audience-Specific Agent API Selection
- Each audience can be mapped to a different agent API/provider/model based on quality, cost, latency, and compliance requirements.
- API selection is part of task execution strategy, not hardcoded globally.
- Fallback chains should exist per audience (primary -> secondary -> offline/manual).

Example policy:

```yaml
audience_agent_policy:
  engineers:
    primary:
      provider: openai
      api: responses
      model: gpt-5
    fallback:
      provider: anthropic
      api: messages
      model: claude-sonnet
  founders:
    primary:
      provider: openai
      api: responses
      model: gpt-5-mini
  legal:
    primary:
      provider: internal
      api: compliance_llm
      model: legal-review-v2
```

Runtime rules:
- If an audience weight is `0`, skip its agent call entirely.
- Route calls through an `AgentRouter` that enforces per-audience policy and captures telemetry.
- Store `provider`, `api`, `model`, latency, and cost per evaluation event for auditability.

### 2) Task Data Model
A task defines **what we are optimizing for** and **which audiences matter**.

```yaml
id: task_123
title: "Improve launch blog post"
article_id: art_789
objective: "Increase clarity and conversion intent"
constraints:
  max_tokens_per_revision: 3000
  style_guardrails: ["no hype", "plain language"]
audience_weights:
  engineers: 0.7
  founders: 0.3
  legal: 0.0   # not selected
optimization_goal:
  type: weighted_multi_objective
  metrics:
    - clarity
    - trust
    - persuasiveness
status: active
```

Rules:
- `0` weight = audience excluded from optimization.
- Non-zero weights are normalized before scoring.

### 3) Article + Version Lineage
Articles are immutable across revisions and stored as a lineage graph.

Entities:
- `Article`: stable identity
- `ArticleVersion`: snapshot of text + metadata
- `RevisionEdge`: parent-child relationship (`version_n -> version_n+1`)

Each version tracks:
- Source version(s)
- Applied edits / rationale
- Scores by audience and aggregate
- Validation outcome

### 4) Editor Role
Editor is the optimizer.

Inputs:
- Current article version
- Task objective + audience weights
- Audience feedback set

Responsibilities:
- Aggregate audience feedback by weight
- Propose revision strategy
- Produce next candidate version
- Explain tradeoffs in change summary

### 5) Validator Role
Validator is an independent fact-checking gate.

Responsibilities:
- Verify claims, dates, statistics, citations
- Classify issues by severity: `blocker`, `major`, `minor`
- Return structured report with evidence links

Gate policy:
- Any `blocker` prevents promotion of a candidate version.
- Non-blocking issues can pass with remediation tasks.

### 6) Auto-Research Loop
Continuous improvement loop:
1. Select active task + current best version
2. Collect weighted audience feedback
3. Editor creates candidate revision
4. Validator fact-checks candidate
5. Score candidate against objective
6. If improved and valid, promote candidate
7. Repeat until convergence / budget exhausted

Stop conditions:
- No improvement over `N` iterations
- Max iteration or cost budget reached
- Human stop

## Suggested Data Schema (Logical)

### `audiences`
- `id`, `name`, `path`, `metadata`, `updated_at`

### `tasks`
- `id`, `article_id`, `objective`, `constraints`, `status`, `created_at`

### `task_audience_weights`
- `task_id`, `audience_id`, `weight`, `agent_policy_id`

### `audience_agent_policies`
- `id`, `audience_id`, `provider`, `api`, `model`, `fallback_json`, `constraints_json`

### `articles`
- `id`, `slug`, `owner`, `created_at`

### `article_versions`
- `id`, `article_id`, `parent_version_id`, `content`, `editor_notes`, `created_at`

### `version_scores`
- `version_id`, `audience_id`, `metric`, `score`, `explanation`

### `validation_reports`
- `id`, `version_id`, `status`, `issues_json`, `sources_json`, `created_at`

## Scoring Model

Overall score for a version:

`overall = Σ(weight_audience * audience_score)`

Where:
- `audience_score` can be a weighted blend of metrics: clarity, relevance, trust, conversion fit.
- Validation penalty applies when unresolved major issues exist.

## Orchestration Boundaries
- **Editor service**: generation + revision planning
- **Audience evaluators**: feedback simulators or real reviewers
- **Agent router**: policy-based per-audience API/model selection with fallback
- **Validator service**: fact checking / evidence verification
- **Lineage store**: versions, scores, and reports
- **Loop orchestrator**: scheduling, stopping logic, and promotion

## Minimal API Surface
- `POST /tasks`
- `PATCH /tasks/{id}/weights`
- `POST /articles/{id}/versions`
- `POST /versions/{id}/evaluate`
- `POST /versions/{id}/validate`
- `POST /tasks/{id}/iterate`
- `POST /versions/{id}/promote`

## Rollout Plan
1. Implement data model and lineage first.
2. Add weighted audience scoring + per-audience agent routing policies.
3. Add Editor loop with deterministic prompts.
4. Add Validator gating.
5. Enable automated iterative mode with budgets.
6. Add observability (score deltas, provider/model performance, failure reasons, validator precision).

## Success Metrics
- Higher weighted audience score over baseline versions
- Fewer factual errors per promoted version
- Faster convergence (iterations to stable improvement)
- Clear audit trail for every promoted revision
