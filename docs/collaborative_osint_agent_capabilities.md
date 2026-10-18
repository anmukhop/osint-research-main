# Collaborative OSINT Agent Capabilities

This document summarizes the collaborative capabilities of the OSINT research agent, with emphasis on the Team View and Team Context features. It is intended as a short framing document for HCI research discussions about small-team investigation workflows.

## Overview

The OSINT agent supports small teams working together on external research targets, such as CTF-style OSINT challenges. Team members can run tool-backed queries, inspect each other's results, and use shared browsing context to coordinate next steps. The system combines query history, agent-generated results, and context-aware suggestions in a single workspace so users can maintain awareness of what the team is doing without leaving the investigation flow.

## Collaborative Capabilities

**Shared Team View**

The Team View gives members a common workspace with three coordinated areas: recent team queries, query/result details, and the Team Context pane. Historical queries can be selected from the left pane and inspected in the center, while the right pane keeps current browsing context visible. This supports lightweight coordination by making prior actions, tool outputs, and active research direction visible to everyone.

**In-Place Query Review**

Query results are shown inside the team workspace instead of forcing users into a separate page. This lets users compare their own work with teammates' results, follow up on another member's query, and continue asking new questions while preserving team context. Running queries can continue in the background, reducing interruption when users navigate or switch attention.

**Team Context Pane**

The Team Context pane summarizes recent browsing and search activity across team members. It highlights shared themes, per-user focus areas, and an AI-generated suggestion that is grounded in recent activity. The suggestion is intended to be forward-looking: it should avoid repeating completed work and instead recommend a tool-backed next step that can advance the investigation.

**AI Suggestions and Auto-Run Results**

When Context mode is on, the system can generate one confident AI suggestion based on recent team activity. If the suggestion is relevant, the agent can run the query and add the result to the team workspace. This creates a bridge between passive awareness of teammate activity and active investigative support.

## Collaboration and User Experience Value

These features can improve small-team OSINT work in several ways:

- Reduce duplicated effort by exposing recent queries, browsing themes, and completed tool use.
- Improve shared situational awareness by showing what each teammate appears to be investigating.
- Support smoother handoffs by allowing one user to inspect and build on another user's query result.
- Help teams identify useful next actions by converting shared browsing context into tool-backed AI suggestions.
- Keep users in one workspace, reducing context switching between query execution, history review, and team awareness.

## HCI Research Scenarios

### Scenario 1: Reducing Duplicate Work During Parallel Investigation

Two team members investigate the same external target from different angles. One member searches for public infrastructure, while another reviews technology profiles and domain information. In the Team View, both users can see recent queries and shared browsing themes. The Team Context pane identifies overlap and suggests a forward-looking query, such as checking DNS or subdomain data, rather than repeating the pages already visited.

**Research value:** This scenario demonstrates how shared query history and context summaries can reduce redundant work and improve coordination in loosely structured team investigations.

### Scenario 2: Supporting Handoff and Continuity

A team member runs a tool-backed query and then shifts attention to another task. A second member opens the Team View, selects the earlier query from Recent Searches, reviews the result in the center pane, and asks a follow-up using the previous output as context. The right-side Team Context remains visible, helping the second member understand how the query fits into the team's broader activity.

**Research value:** This scenario shows how persistent shared results and in-place follow-up can support asynchronous collaboration and reduce the cost of resuming another person's investigative thread.

### Scenario 3: Turning Passive Browsing Awareness Into Action

Both team members browse different web resources related to the same target. The Team Context pane summarizes the common theme and produces one concise AI suggestion explaining why a specific tool-backed query would help. The system auto-runs the relevant query and adds the result to the Team View, where both members can inspect it and decide what to do next.

**Research value:** This scenario highlights how an AI agent can transform ambient awareness signals into actionable support, while keeping users in control through visible results and shared context.

## Summary

The collaborative OSINT agent is designed to support small teams by combining shared query history, in-place result review, team browsing context, and forward-looking AI suggestions. For HCI research, the key contribution is the integration of coordination support directly into the work surface, helping users understand teammate activity, avoid duplicated effort, and move investigations forward with less context switching.
