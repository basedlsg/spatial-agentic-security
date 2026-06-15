"""Graph-isomorphism attacker: voxel-adjacency graph congruence (networkx).

Used to detect shape congruence (a generalized neighbor-copy leak: is the secret
piece the same shape, up to relabeling, as a revealed piece?) and to collapse a
candidate set to distinct shape-classes. Degrades to a conservative answer if
networkx is unavailable.
"""

from __future__ import annotations

from spatial_swarm.spatial_lab.shapes import neighbors6
from spatial_swarm.spatial_puzzle.solvers import optional

NAME = "graph_iso"


def _voxel_graph(piece):
    nx = optional.module(NAME)
    g = nx.Graph()
    piece = frozenset(piece)
    g.add_nodes_from(piece)
    for v in piece:
        for nb in neighbors6(v):
            if nb in piece and v < nb:
                g.add_edge(v, nb)
    return g


def pieces_isomorphic(a, b) -> bool:
    if not optional.available(NAME):
        return False
    from networkx.algorithms.isomorphism import GraphMatcher

    a, b = frozenset(a), frozenset(b)
    if len(a) != len(b):
        return False
    ga, gb = _voxel_graph(a), _voxel_graph(b)
    if ga.number_of_edges() != gb.number_of_edges():
        return False
    return GraphMatcher(ga, gb).is_isomorphic()


def congruence_leak(target_piece, revealed_pieces) -> bool:
    """True if the target shape matches any revealed piece up to rotation/relabeling."""

    return any(pieces_isomorphic(target_piece, p) for p in revealed_pieces)


def count_shape_classes(candidates) -> int:
    reps: list = []
    for c in candidates:
        if not any(pieces_isomorphic(c, r) for r in reps):
            reps.append(frozenset(c))
    return len(reps)
