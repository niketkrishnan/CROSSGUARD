"""Tests for ingestion/k8s_ingestion.py -- IRSA bridge detection (C2).

These tests don't need a live cluster: find_irsa_mappings() just reads
.metadata attributes off whatever ServiceAccount-shaped objects you pass
it, so we build tiny fake objects that mimic the kubernetes-client shape.
"""

import types

from ingestion.k8s_ingestion import find_irsa_mappings, IRSA_ANNOTATION_KEY


def _fake_sa(name, namespace="default", annotations=None):
    """Build a minimal stand-in for a kubernetes-client V1ServiceAccount --
    just enough structure (.metadata.name/.namespace/.annotations) for
    find_irsa_mappings to work against."""
    sa = types.SimpleNamespace()
    sa.metadata = types.SimpleNamespace()
    sa.metadata.name = name
    sa.metadata.namespace = namespace
    sa.metadata.annotations = annotations
    return sa


def test_find_irsa_mappings_single_annotated_sa():
    sa = _fake_sa(
        "vulnerable-sa",
        "default",
        {IRSA_ANNOTATION_KEY: "arn:aws:iam::000000000000:role/admin-role"},
    )
    mappings = find_irsa_mappings([sa])
    assert mappings == [
        {
            "service_account": "vulnerable-sa",
            "namespace": "default",
            "aws_role_arn": "arn:aws:iam::000000000000:role/admin-role",
        }
    ]


def test_find_irsa_mappings_ignores_sa_without_annotation():
    sa_plain = _fake_sa("normal-sa", "default", annotations=None)
    sa_other_annotation = _fake_sa(
        "other-sa", "default", {"some-other-key": "irrelevant"}
    )
    mappings = find_irsa_mappings([sa_plain, sa_other_annotation])
    assert mappings == []


def test_find_irsa_mappings_multiple_service_accounts_only_one_annotated():
    # Mirrors Benchmark 3 from the eval plan: several SAs/pods, only one
    # has the IRSA bridge -- the tool must isolate exactly that one.
    sas = [
        _fake_sa("sa-1", "default"),
        _fake_sa("sa-2", "default"),
        _fake_sa(
            "sa-vulnerable",
            "default",
            {IRSA_ANNOTATION_KEY: "arn:aws:iam::000000000000:role/admin-role"},
        ),
        _fake_sa("sa-4", "default"),
        _fake_sa("sa-5", "default"),
    ]
    mappings = find_irsa_mappings(sas)
    assert len(mappings) == 1
    assert mappings[0]["service_account"] == "sa-vulnerable"


def test_find_irsa_mappings_across_namespaces():
    sas = [
        _fake_sa(
            "sa-a", "team-a",
            {IRSA_ANNOTATION_KEY: "arn:aws:iam::000000000000:role/role-a"},
        ),
        _fake_sa(
            "sa-b", "team-b",
            {IRSA_ANNOTATION_KEY: "arn:aws:iam::000000000000:role/role-b"},
        ),
    ]
    mappings = find_irsa_mappings(sas)
    assert {m["namespace"] for m in mappings} == {"team-a", "team-b"}


def test_find_irsa_mappings_empty_list():
    assert find_irsa_mappings([]) == []
