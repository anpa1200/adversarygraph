"""Offline release/rollback regression against an explicitly disposable PostgreSQL DB.

Run with DB_NAME=attack_test and ATTACK_TEST_BUNDLE_DIR pointing to pinned bundles.
The database must be empty. This script creates only ATT&CK tables and a tag catalog;
it refuses all other database names and never drops databases or existing tables.
"""
import json
import os
from pathlib import Path

from sqlalchemy import func, inspect, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import Base
from app.models import attack
from app.models.intelligence import IntelligenceTag
from app.services.attck import ingestor


def validate():
    if settings.db_name != 'attack_test' or settings.db_user != 'attack_test':
        raise RuntimeError('Only the disposable attack_test database and user are allowed')
    engine = ingestor._sync_engine
    if inspect(engine).get_table_names():
        raise RuntimeError('Disposable database must be empty')
    tables = [obj.__table__ for obj in vars(attack).values() if isinstance(obj, type) and hasattr(obj, '__table__')]
    tables.append(IntelligenceTag.__table__)
    Base.metadata.create_all(engine, tables=tables)
    cache = Path(os.environ['ATTACK_TEST_BUNDLE_DIR'])
    expected = {'enterprise-attack': (15, 706), 'mobile-attack': (12, 125), 'ics-attack': (12, 104)}
    evidence = {}
    for domain, counts in expected.items():
        ingestor.ingest_domain(domain, cache / f'{domain}-20.0.json', '20.0')
        with Session(engine) as session:
            version = session.scalar(select(attack.AttackVersion).where(attack.AttackVersion.domain == domain, attack.AttackVersion.is_latest.is_(True)))
            observed = tuple(session.scalar(select(func.count()).select_from(model).where(model.version_id == version.id)) for model in (attack.Tactic, attack.Technique))
            assert observed == counts, (domain, observed)
            evidence[domain] = {'version': version.version, 'tactics': observed[0], 'techniques': observed[1]}
    # Real prior release, then select existing v20 again: regression for is_latest.
    ingestor.ingest_domain('ics-attack', cache / 'ics-attack-19.2.json', '19.2')
    with Session(engine) as session:
        old = session.scalar(select(attack.AttackVersion).where(attack.AttackVersion.domain == 'ics-attack', attack.AttackVersion.is_latest.is_(True)))
        assert old.version == '19.2'
        old_count = session.scalar(select(func.count()).select_from(attack.Technique).where(attack.Technique.version_id == old.id))
    ingestor.ingest_domain('ics-attack', cache / 'ics-attack-20.0.json', '20.0')
    with Session(engine) as session:
        versions = session.scalars(select(attack.AttackVersion).where(attack.AttackVersion.domain == 'ics-attack')).all()
        assert [(v.version, v.is_latest) for v in sorted(versions, key=lambda v: v.version)] == [('19.2', False), ('20.0', True)]
        assert session.scalar(select(func.count()).select_from(attack.Technique).where(attack.Technique.version_id == old.id)) == old_count
        assert session.scalar(select(func.count()).select_from(attack.AttackVersion).where(attack.AttackVersion.is_latest.is_(True))) == 3
        for version in versions:
            rows = session.scalars(select(attack.StixObject).where(attack.StixObject.version_id == version.id, attack.StixObject.attack_id.in_(['T0807', 'T0853']))).all()
            assert len(rows) == 2
            if version.version == '20.0':
                assert all(row.is_deprecated for row in rows)
        evidence['rollback'] = {'19.2_snapshot_preserved': old_count, '20.0_reactivated': True, 'one_current_version_per_domain': True}
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    validate()
