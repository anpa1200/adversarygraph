from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from app.core.database import Base


class SectorPack(Base):
    __tablename__ = "sector_packs"

    id = Column(Integer, primary_key=True)
    sector_id = Column(String(100), unique=True, index=True, nullable=False)
    sector_name = Column(String(255), nullable=False)
    sector_summary = Column(Text, default="")
    relevance_to_nvidia = Column(Text, default="")
    relevant_nvidia_products = Column(JSONB, default=list)       # list[str]
    crown_jewel_assets = Column(JSONB, default=list)
    likely_threat_actors = Column(JSONB, default=list)
    adversary_motivations = Column(JSONB, default=list)
    common_attack_surfaces = Column(JSONB, default=list)
    likely_attack_paths = Column(JSONB, default=list)
    intelligence_requirements = Column(JSONB, default=list)
    priority_intelligence_requirements = Column(JSONB, default=list)  # PIRs
    early_warning_indicators = Column(JSONB, default=list)
    relevant_ioc_types = Column(JSONB, default=list)
    relevant_ttp_categories = Column(JSONB, default=list)
    mitre_attack_focus = Column(JSONB, default=list)             # list of tactic names
    vulnerability_intelligence_focus = Column(JSONB, default=list)
    supply_chain_risk_focus = Column(JSONB, default=list)
    product_security_relevance = Column(Text, default="")
    telemetry_requirements = Column(JSONB, default=list)
    hunting_opportunities = Column(JSONB, default=list)
    detection_engineering_opportunities = Column(JSONB, default=list)
    mitigation_recommendations = Column(JSONB, default=list)
    engineering_follow_up_actions = Column(JSONB, default=list)
    psirt_relevance = Column(Text, default="")
    customer_risk_considerations = Column(JSONB, default=list)
    executive_summary_points = Column(JSONB, default=list)
    analyst_notes = Column(Text, default="")
    confidence_level = Column(String(20), default="Medium", index=True)  # High/Medium/Low/Unknown
    source_requirements = Column(JSONB, default=list)
    pack_source = Column(String(100), default="nvidia", index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
