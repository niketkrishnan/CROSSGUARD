"""main.build_result must keep the suppression log and exposure findings even with zero paths."""
import networkx as nx

from main import build_result


def test_result_keeps_audit_fields_when_no_paths():
    G = nx.DiGraph()
    G.graph["suppressed_edges"] = [{"source": "a", "target": "b", "type": "irsa_bridge", "reason": "r"}]
    G.graph["wildcard_trust_roles"] = [{"role": "arn:x", "status": "unrestricted", "is_admin": True}]
    aws = {"users": [], "roles": [], "groups": []}
    k8s = {"service_accounts": [], "roles": [], "cluster_roles": []}
    r = build_result(aws, k8s, [], G, [], [], "strict")
    assert r["paths"] == [] and r["semantics"] == "strict"
    assert r["suppressed_edges"][0]["reason"] == "r"
    assert r["wildcard_trust_roles"][0]["status"] == "unrestricted"
