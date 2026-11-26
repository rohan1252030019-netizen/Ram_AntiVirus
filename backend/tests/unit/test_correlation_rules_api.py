"""Regression tests for ``GET /api/v1/correlation/rules``.

The endpoint used to 500 for every tenant: ``correlation_engine.list_rules()``
returns a mix of plain dicts (YAML packs) and ``app.schemas.rule.Rule`` models
(Sigma packs), and the route fed both straight into ``RuleOut``. The Sigma rules
carry a ``RuleCondition`` object instead of a dict, so pydantic raised
``ValidationError: 1 validation error for RuleOut`` and the whole response died.
"""

from __future__ import annotations

from app.api.correlation import _rule_out
from app.schemas.rule import Rule, RuleCondition


def test_dict_rule_serialises():
    out = _rule_out(
        {
            "id": "custom_rule",
            "title": "Custom rule",
            "description": "desc",
            "severity": "high",
            "mitre": ["T1059"],
            "enabled": True,
            "source": "custom",
            "condition": {"event_type": "process_start"},
        }
    )

    assert out.id == "custom_rule"
    assert out.title == "Custom rule"
    assert out.condition == {"event_type": "process_start"}


def test_sigma_rule_model_serialises():
    rule = Rule(
        id="sigma_test_rule",
        name="Sigma rule name",
        severity="critical",
        condition=RuleCondition(event_type="http_request", count_threshold=3),
        techniques=["T1190"],
    )

    out = _rule_out(rule)

    assert out.id == "sigma_test_rule"
    # `title` is the API field; Rule stores it as `name` and syncs `title`.
    assert out.title == "Sigma rule name"
    assert out.severity == "critical"
    assert out.mitre == ["T1190"]
    assert out.condition["event_type"] == "http_request"
    assert out.condition["count_threshold"] == 3


def test_every_loaded_rule_serialises():
    """The exact failure mode: one bad rule killed the whole list."""
    from app.services.correlation_engine import correlation_engine

    rules = correlation_engine.list_rules()
    assert rules, "expected the rule packs to load"

    out = [_rule_out(r) for r in rules]

    assert len(out) == len(rules)
    assert all(isinstance(item.condition, dict) for item in out)
    assert all(item.id for item in out)
