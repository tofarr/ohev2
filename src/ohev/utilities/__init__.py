"""Cross-cutting utilities shared across features.

Hosts reusable building blocks that are not specific to a single resource —
search filters, helpers, etc. Kept separate from `routers → services →
repositories → models` (AGENTS.md §4) so shared behavior is not copy-pasted
across resources.
"""
