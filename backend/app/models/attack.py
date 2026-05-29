from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AttackVersion(Base):
    """Tracks an ingested ATT&CK version for a specific domain."""

    __tablename__ = "attack_versions"
    __table_args__ = (UniqueConstraint("domain", "version", name="uq_domain_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(50), index=True)  # enterprise-attack
    version: Mapped[str] = mapped_column(String(20))             # 19.1
    is_latest: Mapped[bool] = mapped_column(Boolean, default=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    tactics: Mapped[list["Tactic"]] = relationship(back_populates="version")
    techniques: Mapped[list["Technique"]] = relationship(back_populates="version")
    groups: Mapped[list["AptGroup"]] = relationship(back_populates="version")


class Tactic(Base):
    __tablename__ = "tactics"
    __table_args__ = (UniqueConstraint("attack_id", "version_id", name="uq_tactic_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(20), index=True)  # TA0001
    name: Mapped[str] = mapped_column(String(255))
    shortname: Mapped[str] = mapped_column(String(100))              # initial-access
    description: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(String(500), default="")
    domain: Mapped[str] = mapped_column(String(50))
    version_id: Mapped[int] = mapped_column(ForeignKey("attack_versions.id"))

    version: Mapped["AttackVersion"] = relationship(back_populates="tactics")
    techniques: Mapped[list["Technique"]] = relationship(
        secondary="technique_tactics", back_populates="tactics"
    )


class Technique(Base):
    __tablename__ = "techniques"
    __table_args__ = (UniqueConstraint("attack_id", "version_id", name="uq_technique_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(20), index=True)   # T1566 or T1566.001
    stix_id: Mapped[str] = mapped_column(String(100), index=True)     # attack-pattern--uuid
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(String(500), default="")
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_attack_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    platforms: Mapped[list] = mapped_column(JSONB, default=list)      # ["Windows", "Linux"]
    data_sources: Mapped[list] = mapped_column(JSONB, default=list)
    detection: Mapped[str] = mapped_column(Text, default="")
    domain: Mapped[str] = mapped_column(String(50))
    version_id: Mapped[int] = mapped_column(ForeignKey("attack_versions.id"))
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False)

    version: Mapped["AttackVersion"] = relationship(back_populates="techniques")
    tactics: Mapped[list["Tactic"]] = relationship(
        secondary="technique_tactics", back_populates="techniques"
    )
    group_usages: Mapped[list["AptGroupTechnique"]] = relationship(back_populates="technique")


class TechniqueTactic(Base):
    __tablename__ = "technique_tactics"

    technique_id: Mapped[int] = mapped_column(
        ForeignKey("techniques.id", ondelete="CASCADE"), primary_key=True
    )
    tactic_id: Mapped[int] = mapped_column(
        ForeignKey("tactics.id", ondelete="CASCADE"), primary_key=True
    )


class AptGroup(Base):
    __tablename__ = "apt_groups"
    __table_args__ = (UniqueConstraint("attack_id", "version_id", name="uq_group_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(20), index=True)   # G0001
    stix_id: Mapped[str] = mapped_column(String(100), index=True)    # intrusion-set--uuid
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    aliases: Mapped[list] = mapped_column(JSONB, default=list)        # ["Cozy Bear", ...]
    url: Mapped[str] = mapped_column(String(500), default="")
    domain: Mapped[str] = mapped_column(String(50))
    version_id: Mapped[int] = mapped_column(ForeignKey("attack_versions.id"))

    version: Mapped["AttackVersion"] = relationship(back_populates="groups")
    technique_usages: Mapped[list["AptGroupTechnique"]] = relationship(back_populates="group")


class AptGroupTechnique(Base):
    """Maps an APT group to the techniques it uses, with usage context."""

    __tablename__ = "apt_group_techniques"
    __table_args__ = (
        UniqueConstraint("group_id", "technique_id", name="uq_group_technique"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("apt_groups.id", ondelete="CASCADE"))
    technique_id: Mapped[int] = mapped_column(ForeignKey("techniques.id", ondelete="CASCADE"))
    use_description: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSONB, default=list)

    group: Mapped["AptGroup"] = relationship(back_populates="technique_usages")
    technique: Mapped["Technique"] = relationship(back_populates="group_usages")
