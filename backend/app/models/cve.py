from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class CVESource(Base):
    """External vulnerability feed used to collect CVE Library context."""

    __tablename__ = "cve_sources"

    source_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    label: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(80))
    url: Mapped[str] = mapped_column(String(1000), default="")
    enabled: Mapped[bool] = mapped_column(default=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sync_status: Mapped[str] = mapped_column(String(50), default="configured")
    sync_error: Mapped[str] = mapped_column(Text, default="")


class CVERecord(Base):
    """Normalized CVE record with CVSS score fields and raw source payload retained for review."""

    __tablename__ = "cve_records"
    __table_args__ = (UniqueConstraint("cve_id", name="uq_cve_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    source_id: Mapped[str | None] = mapped_column(ForeignKey("cve_sources.source_id", ondelete="SET NULL"), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    published: Mapped[str | None] = mapped_column(String(50), nullable=True)
    last_modified: Mapped[str | None] = mapped_column(String(50), nullable=True)
    vuln_status: Mapped[str] = mapped_column(String(80), default="")
    cvss_version: Mapped[str] = mapped_column(String(20), default="")
    cvss_score: Mapped[str] = mapped_column(String(20), default="")
    cvss_severity: Mapped[str] = mapped_column(String(30), default="")
    cvss_vector: Mapped[str] = mapped_column(String(255), default="")
    cwe_ids: Mapped[list] = mapped_column(JSONB, default=list)
    cpe_matches: Mapped[list] = mapped_column(JSONB, default=list)
    references: Mapped[list] = mapped_column(JSONB, default=list)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    known_exploited: Mapped[bool] = mapped_column(default=False)
    kev_due_date: Mapped[str] = mapped_column(String(50), default="")
    kev_required_action: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    technique_links: Mapped[list["CVETechniqueLink"]] = relationship(back_populates="cve")
    ioc_links: Mapped[list["CVEIOCLink"]] = relationship(back_populates="cve")
    actor_links: Mapped[list["CVEActorLink"]] = relationship(back_populates="cve")


class CVETechniqueLink(Base):
    """Evidence-backed relationship between a CVE and an ATT&CK technique."""

    __tablename__ = "cve_technique_links"
    __table_args__ = (UniqueConstraint("cve_id", "attack_id", "source_id", name="uq_cve_technique_source"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), ForeignKey("cve_records.cve_id", ondelete="CASCADE"), index=True)
    attack_id: Mapped[str] = mapped_column(String(40), index=True)
    source_id: Mapped[str] = mapped_column(String(120), index=True)
    relationship_type: Mapped[str] = mapped_column(String(80), default="exploitation-enables")
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    evidence: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    cve: Mapped["CVERecord"] = relationship(back_populates="technique_links")


class CVEIOCLink(Base):
    """Evidence-backed relationship between a CVE and an IOC/observable."""

    __tablename__ = "cve_ioc_links"
    __table_args__ = (UniqueConstraint("cve_id", "indicator_id", "source_id", name="uq_cve_ioc_source"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), ForeignKey("cve_records.cve_id", ondelete="CASCADE"), index=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("ioc_indicators.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(String(120), index=True)
    relationship_type: Mapped[str] = mapped_column(String(80), default="observed-with")
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    evidence: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    cve: Mapped["CVERecord"] = relationship(back_populates="ioc_links")


class CVEActorLink(Base):
    """Evidence-backed relationship between a CVE and an ATT&CK actor/group."""

    __tablename__ = "cve_actor_links"
    __table_args__ = (UniqueConstraint("cve_id", "actor_attack_id", "source_id", name="uq_cve_actor_source"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), ForeignKey("cve_records.cve_id", ondelete="CASCADE"), index=True)
    actor_attack_id: Mapped[str] = mapped_column(String(40), index=True)
    actor_name: Mapped[str] = mapped_column(String(255), index=True, default="")
    source_id: Mapped[str] = mapped_column(String(120), index=True)
    relationship_type: Mapped[str] = mapped_column(String(80), default="reported-used-by")
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    evidence: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    cve: Mapped["CVERecord"] = relationship(back_populates="actor_links")
