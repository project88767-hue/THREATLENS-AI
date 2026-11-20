from typing import Any, Literal
from pydantic import BaseModel, Field


IndicatorType = Literal["URL", "IP", "DOMAIN", "EMAIL", "CVE"]
SeverityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
VerdictType = Literal["CLEAN", "SUSPICIOUS", "MALICIOUS", "INFO"]
ProviderMode = Literal["LIVE", "PUBLIC_LIVE", "DEMO_FALLBACK", "RATE_LIMITED", "ERROR"]


class UrlScanRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)


class IpScanRequest(BaseModel):
    ip: str = Field(..., min_length=3, max_length=128)


class DomainScanRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)


class EmailScanRequest(BaseModel):
    raw_headers: str = Field(default="", max_length=50000)
    body: str = Field(default="", max_length=100000)
    subject: str | None = Field(default=None, max_length=500)
    sender: str | None = Field(default=None, max_length=320)


class CveScanRequest(BaseModel):
    cve_id: str = Field(..., min_length=2, max_length=120)


class AssistantMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(..., max_length=8000)


class AssistantRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    context: dict[str, Any] = Field(default_factory=dict)
    history: list[AssistantMessage] = Field(default_factory=list)


class MitreTechnique(BaseModel):
    id: str
    name: str
    tactic: str


class AiExplanation(BaseModel):
    overview: str
    why_flagged: list[str]
    mitre_techniques: list[MitreTechnique]
    recommended_actions: list[str]
    is_simulated_ai: bool = True


class ScoreFactor(BaseModel):
    factor: str
    points: int
    max_points: int
    reason: str
    source: str
    is_simulated: bool = False


class EvidenceItem(BaseModel):
    provider: str
    category: str
    title: str
    verdict: VerdictType
    weight: int = Field(ge=0, le=100)
    details: dict[str, Any] = Field(default_factory=dict)
    is_simulated: bool = False


class ProviderStatus(BaseModel):
    mode: ProviderMode
    latency_ms: int = 0
    message: str = ""


class ExtractedRelation(BaseModel):
    source_type: str
    source_value: str
    source_label: str
    target_type: str
    target_value: str
    target_label: str
    relation: str
    confidence: int = Field(default=80, ge=0, le=100)


class AnalysisResponse(BaseModel):
    indicator_type: IndicatorType
    target: str
    normalized_target: str
    risk_score: int = Field(ge=0, le=100)
    severity: SeverityLevel
    confidence: int = Field(ge=0, le=100)
    verdict: Literal["CLEAN", "SUSPICIOUS", "MALICIOUS"]
    summary: str
    ai_explanation: AiExplanation
    score_breakdown: list[ScoreFactor]
    evidence: list[EvidenceItem]
    provider_status: dict[str, ProviderStatus]
    extracted_relations: list[ExtractedRelation] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssistantResponse(BaseModel):
    reply: str
    suggested_questions: list[str]
    mitre_mappings: list[MitreTechnique]
    recommended_steps: list[str]
    is_simulated_ai: bool
