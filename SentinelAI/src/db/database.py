"""SQLAlchemy relational persistence for detection results.

Stores PCAP analyses, incidents, risk scores, and MITRE mappings so results
can be queried and surfaced by the API / dashboard after the fact.
"""

import logging
from typing import Any, cast

from sqlalchemy import (
    Column,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

logger = logging.getLogger(__name__)

Base = declarative_base()

DEFAULT_DB_URL = "sqlite:///sentinelai.db"


def build_engine(db_url: str = DEFAULT_DB_URL):
    kwargs: dict[str, Any] = {"echo": False, "future": True}
    if db_url.startswith("sqlite:///:memory:"):
        kwargs["poolclass"] = StaticPool
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(db_url, **kwargs)
    Base.metadata.create_all(engine)
    return engine


def make_session_factory(db_url: str = DEFAULT_DB_URL):
    engine = build_engine(db_url)
    return sessionmaker(bind=engine, expire_on_commit=False)


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True)
    pcap_path = Column(String, nullable=False)
    packets = Column(Integer, default=0)
    flows = Column(Integer, default=0)
    total_incidents = Column(Integer, default=0)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, index=True)
    src_ip = Column(String, index=True)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="minimal")
    events = Column(Integer, default=0)
    targets = Column(Integer, default=0)
    tactics = Column(Text, default="")
    techniques = Column(Text, default="")


class Database:
    def __init__(self, db_url: str = DEFAULT_DB_URL):
        self.session_factory = make_session_factory(db_url)
        logger.info("Database ready at %s", db_url)

    def save_analysis(self, pcap: str, packets: int, flows: int, total_incidents: int) -> int:
        with self.session_factory() as session:
            a = Analysis(
                pcap_path=pcap,
                packets=packets,
                flows=flows,
                total_incidents=total_incidents,
            )
            session.add(a)
            session.commit()
            return cast(int, a.id)

    def save_incidents(self, analysis_id: int, incident_rows: list[dict]) -> None:
        with self.session_factory() as session:
            for row in incident_rows:
                kwargs = dict(row)
                kwargs.setdefault("analysis_id", analysis_id)
                session.add(Incident(**kwargs))
            session.commit()

    def list_analyses(self) -> list[dict]:
        with self.session_factory() as session:
            rows = session.query(Analysis).order_by(Analysis.id.desc()).all()
            return [
                {c.name: getattr(a, c.name) for c in Analysis.__table__.columns}
                for a in rows
            ]

    def list_incidents(self, analysis_id: int | None = None) -> list[dict]:
        with self.session_factory() as session:
            q = session.query(Incident)
            if analysis_id is not None:
                q = q.filter(Incident.analysis_id == analysis_id)
            rows = q.order_by(Incident.risk_score.desc()).all()
            return [
                {c.name: getattr(i, c.name) for c in Incident.__table__.columns}
                for i in rows
            ]
