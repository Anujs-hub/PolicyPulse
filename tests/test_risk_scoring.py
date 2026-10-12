import pytest

from app.services.risk_scoring import compute_risk, risk_level

BASE = dict(sensitivity="low", action="read", device_trust="trusted", mfa_verified=True,
            failed_logins=0, access_context="normal", rbac_permitted=True)


def risk(**kw):
    return compute_risk(**{**BASE, **kw})


def test_minimum_score_is_zero():
    r = risk()
    assert r.score == 0 and r.level == "low"


def test_score_is_capped_at_100():
    r = risk(sensitivity="critical", action="admin", device_trust="untrusted", mfa_verified=False,
             failed_logins=100, access_context="anonymized_network", rbac_permitted=False)
    assert r.score == 100 and r.level == "critical"
    assert sum(f.points for f in r.factors) > 100  # raw sum exceeds the cap


@pytest.mark.parametrize("score,level", [(0, "low"), (29, "low"), (30, "medium"), (59, "medium"),
                                         (60, "high"), (79, "high"), (80, "critical"), (100, "critical")])
def test_level_boundaries(score, level):
    assert risk_level(score) == level


@pytest.mark.parametrize("failed,points", [(0, 0), (1, 5), (4, 20), (5, 25), (6, 25), (50, 25)])
def test_failed_login_points_are_capped(failed, points):
    pts = {f.factor: f.points for f in risk(failed_logins=failed).factors}
    assert pts["failed_logins"] == points


def test_individual_factors():
    assert risk(sensitivity="critical").score == 30
    assert risk(action="delete").score == 10
    assert risk(device_trust="unmanaged").score == 15
    assert risk(mfa_verified=False).score == 15
    assert risk(access_context="unusual_location").score == 15
    assert risk(rbac_permitted=False).score == 20


def test_scoring_is_deterministic():
    assert risk(sensitivity="high", failed_logins=2) == risk(sensitivity="high", failed_logins=2)
