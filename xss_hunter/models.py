"""Wire models for the three MCP tools.

The three result arrays are separate by design:
  * ``confirmed``       -- survived observe + fresh-context replay + evidence;
  * ``tested_held``     -- tried, did not execute, with a reason;
  * ``could_not_proceed`` -- blocked, with the missing input named in ``needs``.

Only ``confirmed`` may be called a finding. Held and blocked are run status.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ErrorInfo(BaseModel):
    code: str
    message: str
    needs: str | None = None
    checkpoint: str | None = None


class Target(BaseModel):
    url: str
    host: str
    scope: Literal["allowed", "refused", "unknown"]


class ReplayProof(BaseModel):
    verified: bool
    session: Literal["fresh"]
    nonce: str
    signal: str


class Finding(BaseModel):
    finding_id: str
    context: str
    sub_context: str
    payload: str
    nonce: str
    signal: str
    signal_detail: str
    requires_interaction: bool
    replay: ReplayProof
    evidence: str
    reproduce: str
    browser: str
    timestamp: str


class Held(BaseModel):
    context: str
    sub_context: str | None = None
    reason: str
    detail: str
    payloads_tried: int = 0


class Blocked(BaseModel):
    stage: str
    reason: str
    needs: str


class Limits(BaseModel):
    duration_ms: int
    http_requests: int
    payloads_sent: int
    browser_contexts: int


class ScopeRefusal(BaseModel):
    ts: str
    host: str
    url: str
    reason: str
    checkpoint: str


class Totals(BaseModel):
    confirmed: int
    tested_held: int
    could_not_proceed: int


class ScanResponse(BaseModel):
    status: Literal["completed", "refused", "blocked", "invalid"]
    run_id: str
    target: Target
    parameter: str
    confirmed: list[Finding] = Field(default_factory=list)
    tested_held: list[Held] = Field(default_factory=list)
    could_not_proceed: list[Blocked] = Field(default_factory=list)
    limits: Limits
    scope_refusals: list[ScopeRefusal] = Field(default_factory=list)
    truncated: bool = False
    totals: Totals
    error: ErrorInfo | None = None


class Artifact(BaseModel):
    path: str
    sha256: str
    bytes: int


class Evidence(BaseModel):
    finding_id: str
    run_id: str
    url: str
    parameter: str
    context: str
    sub_context: str
    payload: str
    nonce: str
    signal: str
    signal_detail: str
    requires_interaction: bool
    replay: ReplayProof
    timestamp: str
    browser: str
    artifacts: list[Artifact]
    reproduce: str
    finding_sha256: str


class EvidenceResponse(BaseModel):
    status: Literal["ok", "invalid"]
    finding: Evidence | None = None
    error: ErrorInfo | None = None


class ScopeResponse(BaseModel):
    hosts: list[str]
    count: int
    ports_matter: bool = True
    wildcards: bool = False
    note: str
    error: ErrorInfo | None = None
