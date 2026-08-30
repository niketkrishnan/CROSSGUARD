#!/usr/bin/env python3
"""
scale_sweep_trial.py -- ONE isolated trial: build a synthetic graph of
the requested size, run the REAL find_all_cross_layer_paths against it,
print a single CSV line, then exit. Intended to be invoked as a fresh
subprocess per (size, trial) so OS-level process isolation prevents the
resource-contention artifact documented earlier in this evaluation.

Synthetic graph construction mirrors the real benchmark suite's
node/edge-type distribution:
  - ~45% of nodes are K8s ServiceAccounts (type="k8s_serviceaccount"),
    each a potential entry point (find_k8s_entry_points matches any
    type starting with "k8s").
  - ~55% of nodes are AWS roles (type="aws_role"); ~3% of AWS roles are
    flagged is_admin=True (matches the "sink" definition find_admin_nodes
    uses).
  - Edges are a mix of irsa_bridge (K8s SA -> AWS role, one per SA,
    matching the always-exactly-one-IRSA-annotation real-world pattern),
    iam:PassRole and sts:AssumeRole (AWS role -> AWS role chains of
    random length 1-3), group_membership, and rbac (K8s-internal) --
    proportioned to land close to the real benchmark suite's observed
    edges/nodes ratio (~0.89) at every tested size.

Usage: python3 scale_sweep_trial.py <n_nodes> <trial_seed>
Prints: nodes,edges,trial_seed,paths_found,pathfinding_seconds
"""

import random
import sys
import time

import networkx as nx

sys.path.insert(0, "/home/zoro/projects/iam-k8s-privesc")
from pathfinder.search import find_all_cross_layer_paths  # noqa: E402


def build_synthetic_graph(n_nodes: int, seed: int) -> nx.DiGraph:
    rng = random.Random(seed)
    G = nx.DiGraph()

    n_k8s = int(n_nodes * 0.45)
    n_aws = n_nodes - n_k8s
    n_admin = max(1, int(n_aws * 0.03))

    k8s_nodes = [f"k8s:sa:default:sa{i}" for i in range(n_k8s)]
    aws_nodes = [f"arn:aws:iam::000000000000:role/role{i}" for i in range(n_aws)]
    admin_set = set(rng.sample(aws_nodes, n_admin))

    for n in k8s_nodes:
        G.add_node(n, type="k8s_serviceaccount")
    for n in aws_nodes:
        G.add_node(n, type="aws_role", is_admin=(n in admin_set))

    # irsa_bridge: every K8s SA binds to exactly one AWS role (real-world
    # pattern -- one IRSA annotation per ServiceAccount)
    for sa in k8s_nodes:
        target = rng.choice(aws_nodes)
        G.add_edge(sa, target, type="irsa_bridge")

    # AWS-side chains: each AWS role has a 1-3-hop chance of PassRole or
    # AssumeRole to another AWS role, occasionally reaching an admin node
    edge_types = ["iam:PassRole", "sts:AssumeRole"]
    for role in aws_nodes:
        if rng.random() < 0.35:  # not every role chains further
            chain_len = rng.randint(1, 3)
            current = role
            for _ in range(chain_len):
                target = rng.choice(aws_nodes)
                if target == current:
                    continue
                G.add_edge(current, target, type=rng.choice(edge_types))
                current = target

    # occasional K8s-internal rbac edges and group_membership edges to
    # round out the edge-type distribution toward the ~0.89 edges/node
    # ratio observed in the real benchmark suite
    current_edges = G.number_of_edges()
    target_edges = int(n_nodes * 0.89)
    extra_needed = max(0, target_edges - current_edges)
    all_nodes = k8s_nodes + aws_nodes
    for _ in range(extra_needed):
        a = rng.choice(all_nodes)
        b = rng.choice(all_nodes)
        if a == b:
            continue
        etype = "rbac" if a in k8s_nodes and b in k8s_nodes else "group_membership"
        G.add_edge(a, b, type=etype)

    return G


def main():
    n_nodes = int(sys.argv[1])
    trial_seed = int(sys.argv[2])

    G = build_synthetic_graph(n_nodes, trial_seed)

    t0 = time.perf_counter()
    paths = find_all_cross_layer_paths(G)
    t1 = time.perf_counter()

    print(f"{G.number_of_nodes()},{G.number_of_edges()},{trial_seed},{len(paths)},{t1 - t0:.4f}")


if __name__ == "__main__":
    main()
