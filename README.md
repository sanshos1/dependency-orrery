# Dependency Orrery

Dependency Orrery is a reusable GenLayer reachability audit. A maintainer freezes a public dependency manifest, a runtime import trace, and an advisory. Independent validators re-fetch every record, verify exact digests, and settle whether the affected package is actually reachable in the observed application.

Unlike a vulnerability name lookup, the result contains a closed finding and, only when affected, the exact ordered path from the application root to the vulnerable package. Duplicate source sets and repeat finalization are rejected.

## Lifecycle

`open_scan` → `resolve_scan` → immutable `FINALIZED` record. Any wallet may open and resolve a scan; ownership remains attributable. The frontend exposes the complete lifecycle and distinguishes submitted, accepted, and finalized transactions.

## Sources and outputs

- Manifest: installed package names and versions.
- Runtime trace: observed imports or execution path.
- Advisory: affected range and reachability condition.
- Output: `AFFECTED`, `CLEAR`, or `INDETERMINATE`, package, ordered path, and one closed reason code.

## Verify

Run `python -m pytest -q`. Live deployment evidence is written to `deployment.json` and `evidence/live-run.json`.
