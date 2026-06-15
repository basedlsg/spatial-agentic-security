"""Voxel shapes: target generation, connected partition, connectors, topology.

A target is a connected voxel object of exactly n*k cells, partitioned into n
connected k-voxel pieces. Connectors and topology signatures are derived from the
real pieces and published as constraints for the assembly attacker (Lab B); the
real piece always satisfies its own signatures, and two different subsets can share
a signature, so they are genuine (lossy) constraints.
"""

from __future__ import annotations

import random
from collections import deque

from spatial_swarm.crypto.hashing import sha256_hex

Coord = tuple[int, int, int]

DIRS: tuple[Coord, ...] = (
    (1, 0, 0), (-1, 0, 0), (0, 1, 0), (0, -1, 0), (0, 0, 1), (0, 0, -1),
)


def neighbors6(c: Coord) -> list[Coord]:
    x, y, z = c
    return [(x + dx, y + dy, z + dz) for dx, dy, dz in DIRS]


def is_connected(voxels) -> bool:
    voxels = frozenset(voxels)
    if not voxels:
        return False
    start = next(iter(voxels))
    seen = {start}
    queue = deque([start])
    while queue:
        cur = queue.popleft()
        for nb in neighbors6(cur):
            if nb in voxels and nb not in seen:
                seen.add(nb)
                queue.append(nb)
    return len(seen) == len(voxels)


def _box_dims(volume: int) -> tuple[int, int, int]:
    """Dims of a box with capacity >= volume, as close to a cube as possible."""

    side = 1
    while side**3 < volume:
        side += 1
    return (side, side, side)


def generate_target(rng: random.Random, n: int, k: int, mode: str = "random_polycube") -> frozenset[Coord]:
    """A connected voxel set of exactly n*k cells."""

    total = n * k
    if mode == "solid_box":
        # Row-major fill of a box, taking the first `total` cells (connected prefix).
        ax, ay, az = _box_dims(total)
        cells: list[Coord] = []
        for x in range(ax):
            for y in range(ay):
                for z in range(az):
                    cells.append((x, y, z))
                    if len(cells) == total:
                        return frozenset(cells)
        return frozenset(cells)
    if mode == "random_polycube":
        start = (0, 0, 0)
        blob = {start}
        frontier = set(neighbors6(start))
        while len(blob) < total:
            choices = sorted(frontier)
            pick = choices[rng.randrange(len(choices))]
            blob.add(pick)
            frontier.discard(pick)
            for nb in neighbors6(pick):
                if nb not in blob:
                    frontier.add(nb)
        return frozenset(blob)
    raise ValueError(f"unknown target mode {mode!r}")


def _agent_id(i: int) -> str:
    return f"agent_{i:03d}"


def _snake_cells(volume: int) -> list[Coord]:
    """A boustrophedon path of `volume` cells; consecutive cells are face-adjacent."""

    ax, ay, az = _box_dims(volume)
    out: list[Coord] = []
    for x in range(ax):
        ys = range(ay) if x % 2 == 0 else range(ay - 1, -1, -1)
        for y in ys:
            zs = range(az) if (x + y) % 2 == 0 else range(az - 1, -1, -1)
            for z in zs:
                out.append((x, y, z))
                if len(out) == volume:
                    return out
    return out


def generate_partitioned(
    rng: random.Random, n: int, k: int, mode: str = "grown", max_attempts: int = 400
) -> tuple[frozenset[Coord], dict[str, frozenset[Coord]]]:
    """Build a connected n*k voxel object together with its n connected k-pieces.

    Pieces are generated directly (not partitioned after the fact): each piece grows
    by accretion into free space (so it can never stall), and pieces after the first
    seed adjacent to the existing object so the union stays connected.
    """

    if mode == "solid_box":
        cells = _snake_cells(n * k)
        pieces = {_agent_id(i + 1): frozenset(cells[i * k:(i + 1) * k]) for i in range(n)}
        return frozenset(cells), pieces

    if mode == "grown":
        for _ in range(max_attempts):
            blob: set[Coord] = set()
            pieces_list: list[frozenset[Coord]] = []
            ok = True
            for i in range(n):
                if i == 0:
                    seed: Coord = (0, 0, 0)
                else:
                    cand = sorted({nb for v in blob for nb in neighbors6(v) if nb not in blob})
                    if not cand:
                        ok = False
                        break
                    seed = cand[rng.randrange(len(cand))]
                region = {seed}
                blob.add(seed)
                while len(region) < k:
                    frontier = sorted(
                        {nb for v in region for nb in neighbors6(v) if nb not in blob}
                    )
                    if not frontier:
                        ok = False
                        break
                    pick = frontier[rng.randrange(len(frontier))]
                    region.add(pick)
                    blob.add(pick)
                if not ok:
                    break
                pieces_list.append(frozenset(region))
            if ok and len(blob) == n * k:
                return frozenset(blob), {_agent_id(i + 1): pieces_list[i] for i in range(n)}
        raise RuntimeError("failed to grow a connected partitioned object; try more attempts")

    raise ValueError(f"unknown partition mode {mode!r}")


# --------------------------------------------------------------------------- #
# Connector signatures (published constraint for the assembly attacker)
# --------------------------------------------------------------------------- #


def _perp_axes(d: Coord) -> tuple[Coord, Coord]:
    if d[0] != 0:
        return ((0, 1, 0), (0, 0, 1))
    if d[1] != 0:
        return ((1, 0, 0), (0, 0, 1))
    return ((1, 0, 0), (0, 1, 0))


def _face_descriptor(piece: frozenset[Coord], v: Coord, d: Coord) -> tuple:
    """Local stud/hole pattern of one boundary face: direction + in-plane occupancy."""

    u, w = _perp_axes(d)
    occ = []
    for su in (-1, 1):
        for sw in (-1, 1):
            nb = (v[0] + su * u[0] + sw * w[0], v[1] + su * u[1] + sw * w[1], v[2] + su * u[2] + sw * w[2])
            occ.append(1 if nb in piece else 0)
    return (d, tuple(occ))


def connector_signature(piece, target) -> str:
    """Hash of the multiset of internal-boundary face descriptors (facing other pieces)."""

    piece = frozenset(piece)
    target = frozenset(target)
    faces = []
    for v in piece:
        for d in DIRS:
            nb = (v[0] + d[0], v[1] + d[1], v[2] + d[2])
            if nb in target and nb not in piece:  # face shared with another piece
                faces.append(_face_descriptor(piece, v, d))
    return sha256_hex({"kind": "connector_signature", "faces": sorted(map(list, _as_lists(faces)))})


def _as_lists(faces) -> list:
    return [[list(d), list(occ)] for (d, occ) in faces]


# --------------------------------------------------------------------------- #
# Topology signature (published constraint; rotation+translation invariant)
# --------------------------------------------------------------------------- #


def surface_area(piece) -> int:
    piece = frozenset(piece)
    exposed = 0
    for v in piece:
        for nb in neighbors6(v):
            if nb not in piece:
                exposed += 1
    return exposed


def _bounding_box(piece) -> tuple[Coord, Coord]:
    xs = [p[0] for p in piece]
    ys = [p[1] for p in piece]
    zs = [p[2] for p in piece]
    return (min(xs), min(ys), min(zs)), (max(xs), max(ys), max(zs))


def complement_components(piece) -> int:
    """Number of 6-connected components of the bounding-box cells not in the piece."""

    piece = frozenset(piece)
    if not piece:
        return 0
    (mnx, mny, mnz), (mxx, mxy, mxz) = _bounding_box(piece)
    box = {
        (x, y, z)
        for x in range(mnx, mxx + 1)
        for y in range(mny, mxy + 1)
        for z in range(mnz, mxz + 1)
    }
    empties = box - piece
    seen: set[Coord] = set()
    components = 0
    for cell in empties:
        if cell in seen:
            continue
        components += 1
        seen.add(cell)
        queue = deque([cell])
        while queue:
            cur = queue.popleft()
            for nb in neighbors6(cur):
                if nb in empties and nb not in seen:
                    seen.add(nb)
                    queue.append(nb)
    return components


def articulation_count(piece) -> int:
    """Number of voxels whose removal disconnects the piece."""

    piece = frozenset(piece)
    if len(piece) <= 1:
        return 0
    count = 0
    for v in piece:
        rest = piece - {v}
        if rest and not is_connected(rest):
            count += 1
    return count


def topology_signature(piece) -> tuple[int, int, int, int]:
    """(size, surface_area, complement_components, articulation_count) -- pose invariant."""

    piece = frozenset(piece)
    return (len(piece), surface_area(piece), complement_components(piece), articulation_count(piece))
