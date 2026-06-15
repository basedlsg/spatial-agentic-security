"""Hidden-constraint polycube features: geometry-derived connectors (published only
as a lossy histogram), coarse topology bands, asymmetry and cavity helpers.

Connector symbols are a deterministic function of local face geometry, so an
attacker CAN compute them on a candidate (otherwise a clue could not prune). The
defense is to publish only a coarse, many-to-one projection (histogram / band) and
to reject any puzzle a single projection uniquely identifies (see rejection.py).
"""

from __future__ import annotations

from spatial_swarm.crypto.hashing import sha256_hex
from spatial_swarm.spatial_lab.rotations import apply_set, normalize_to_origin
from spatial_swarm.spatial_lab.shapes import (
    DIRS,
    _perp_axes,
    complement_components,
    is_connected,
    neighbors6,
    topology_signature,
)

Coord = tuple[int, int, int]


def internal_faces(piece, target) -> list[tuple[Coord, Coord]]:
    piece, target = frozenset(piece), frozenset(target)
    faces = []
    for v in piece:
        for d in DIRS:
            nb = (v[0] + d[0], v[1] + d[1], v[2] + d[2])
            if nb in target and nb not in piece:
                faces.append((v, d))
    return faces


def connector_symbol(piece, v: Coord, d: Coord, alphabet_size: int) -> int:
    """Geometry-derived connector symbol from the local in-plane occupancy pattern."""

    u, w = _perp_axes(d)
    occ = []
    for su in (-1, 1):
        for sw in (-1, 1):
            nb = (v[0] + su * u[0] + sw * w[0], v[1] + su * u[1] + sw * w[1], v[2] + su * u[2] + sw * w[2])
            occ.append(1 if nb in piece else 0)
    digest = int(sha256_hex({"d": list(d), "occ": occ}), 16)
    return digest % alphabet_size


def connector_histogram(piece, target, alphabet_size: int) -> tuple[int, ...]:
    """Lossy public projection: per-symbol counts over internal faces (placement dropped)."""

    counts = [0] * alphabet_size
    pf = frozenset(piece)
    for v, d in internal_faces(pf, target):
        counts[connector_symbol(pf, v, d, alphabet_size)] += 1
    return tuple(counts)


def topology_band(piece, bucket: int = 2) -> tuple[int, ...]:
    """Coarse, many-to-one bucketing of the (pose-invariant) topology signature."""

    return tuple(s // bucket for s in topology_signature(piece))


def is_asymmetric(piece) -> bool:
    """True iff the piece has a trivial rotational stabilizer (24 distinct rotated images)."""

    images = {frozenset(normalize_to_origin(apply_set(r, piece))) for r in range(24)}
    return len(images) == 24


def has_cavity(piece) -> bool:
    """True iff the piece encloses an internal void (complement has a bounded component)."""

    return complement_components(piece) >= 1


def carve_cavity(rng, piece):
    """Best-effort: remove an interior cell to create an enclosed void; return (piece, carved).

    Only possible when a cell is fully surrounded; impossible for small pieces, in which
    case the piece is returned unchanged with carved=False.
    """

    piece = set(piece)
    interior = [c for c in piece if all(nb in piece for nb in neighbors6(c))]
    if not interior:
        return frozenset(piece), False
    cell = interior[rng.randrange(len(interior))]
    candidate = piece - {cell}
    if is_connected(candidate) and complement_components(candidate) > complement_components(piece):
        return frozenset(candidate), True
    return frozenset(piece), False
