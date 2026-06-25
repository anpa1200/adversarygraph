from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from app.core.database import Base


class RetroHuntSignal(Base):
    __tablename__ = "retrohunt_signals"

    id = Column(Integer, primary_key=True)
    # Source identifier: nvd | github_advisory | cisa_kev | exploitdb
    source = Column(String(50), index=True, nullable=False)
    # Signal classification: cve | exploit | advisory | report
    signal_type = Column(String(50), index=True, nullable=False)
    # Unique external ID (source-prefixed to allow same CVE from multiple sources)
    external_id = Column(String(255), unique=True, index=True, nullable=False)

    title = Column(Text, nullable=False)
    body = Column(Text, default="")
    url = Column(Text, default="")

    published_at = Column(DateTime(timezone=True), index=True, nullable=True)
    severity = Column(String(20), default="unknown", index=True)  # critical/high/medium/low/unknown
    cvss_score = Column(Float, nullable=True)

    # Intelligence tags
    sector_tags = Column(JSONB, default=list)    # list of sector_ids from sector_packs
    tech_tags = Column(JSONB, default=list)      # list of technology category labels
    cve_ids = Column(JSONB, default=list)        # extracted CVE-XXXX-XXXXX strings
    product_tags = Column(JSONB, default=list)   # specific product/vendor mentions

    raw_json = Column(JSONB, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_retrohunt_sector_tags", "sector_tags", postgresql_using="gin"),
        Index("ix_retrohunt_tech_tags", "tech_tags", postgresql_using="gin"),
        Index("ix_retrohunt_cve_ids", "cve_ids", postgresql_using="gin"),
    )
