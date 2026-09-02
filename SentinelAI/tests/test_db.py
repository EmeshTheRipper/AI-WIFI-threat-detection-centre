"""Tests for the SQLAlchemy persistence layer."""

import pandas as pd

from src.db import Database


def test_db_save_and_list_analysis():
    db = Database("sqlite:///:memory:")
    aid = db.save_analysis("test.pcap", 10, 8, 3)
    analyses = db.list_analyses()
    assert len(analyses) == 1
    assert analyses[0]["id"] == aid
    assert analyses[0]["packets"] == 10
    assert analyses[0]["flows"] == 8


def test_db_save_incidents_and_filter():
    db = Database("sqlite:///:memory:")
    aid = db.save_analysis("x.pcap", 5, 5, 2)
    db.save_incidents(aid, [
        {"src_ip": "1.1.1.1", "risk_score": 80.0, "risk_level": "critical",
         "events": 3, "targets": 2, "tactics": "Discovery", "techniques": "T1046"},
        {"src_ip": "2.2.2.2", "risk_score": 10.0, "risk_level": "minimal",
         "events": 1, "targets": 1, "tactics": "", "techniques": ""},
    ])
    all_inc = db.list_incidents()
    assert len(all_inc) == 2
    filtered = db.list_incidents(analysis_id=aid)
    assert len(filtered) == 2
    assert filtered[0]["src_ip"] == "1.1.1.1"  # sorted by risk desc


def test_db_multiple_analyses_isolated():
    db = Database("sqlite:///:memory:")
    a1 = db.save_analysis("a.pcap", 1, 1, 1)
    a2 = db.save_analysis("b.pcap", 1, 1, 1)
    assert a1 != a2
    assert len(db.list_analyses()) == 2
