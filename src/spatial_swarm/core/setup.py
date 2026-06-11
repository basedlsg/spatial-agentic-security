"""Ephemeral birth setup for USAG swarms."""

from __future__ import annotations

from dataclasses import dataclass

from nacl.public import PrivateKey

from spatial_swarm.core.epoch import Epoch
from spatial_swarm.core.registry import AgentRegistration
from spatial_swarm.core.sidecar import Sidecar
from spatial_swarm.crypto.keys import deterministic_signing_key, generate_gateway_private_key
from spatial_swarm.geometry.finite_grid import Coord, FiniteGrid
from spatial_swarm.geometry.fragment import Fragment, cut_puzzle, generate_full_puzzle
from spatial_swarm.protocol.policies import estimate_envelope


@dataclass(frozen=True)
class SetupReport:
    full_puzzle_deleted: bool
    seed_deleted: bool
    setup_shutdown: bool


@dataclass(frozen=True)
class SetupArtifacts:
    registry_epoch: str
    private_key: PrivateKey
    grid: FiniteGrid
    registrations: list[AgentRegistration]
    sidecars: dict[str, Sidecar]
    report: SetupReport


class EphemeralSetup:
    """Creates the puzzle once, distributes pieces, then erases setup state."""

    def __init__(
        self,
        agent_count: int,
        fragment_size: int,
        seed: int,
        p: int,
        timeout_ms: float,
    ) -> None:
        self.agent_count = agent_count
        self.fragment_size = fragment_size
        self.p = p
        self.timeout_ms = timeout_ms
        self._seed: int | None = seed
        self._full_puzzle: set[Coord] | None = None
        self._fragments: dict[str, Fragment] | None = None
        self._shutdown = False

    @property
    def seed_material(self) -> int | None:
        return self._seed

    @property
    def full_puzzle(self) -> set[Coord] | None:
        return self._full_puzzle

    @property
    def fragments(self) -> dict[str, Fragment] | None:
        return self._fragments

    @property
    def shutdown_complete(self) -> bool:
        return self._shutdown

    def run(self) -> SetupArtifacts:
        if self._seed is None:
            raise RuntimeError("setup has already shut down")

        grid = FiniteGrid(p=self.p)
        epoch = Epoch(index=1).epoch_id
        private_key = generate_gateway_private_key(self._seed)
        self._full_puzzle = generate_full_puzzle(
            self.agent_count * self.fragment_size,
            self._seed,
            grid,
        )
        self._fragments = cut_puzzle(
            self._full_puzzle,
            self.agent_count,
            self.fragment_size,
            self.p,
        )

        registrations: list[AgentRegistration] = []
        sidecars: dict[str, Sidecar] = {}
        for agent_id, fragment in self._fragments.items():
            signing_key = deterministic_signing_key(self._seed, agent_id)
            envelope = estimate_envelope(
                agent_id=agent_id,
                epoch=epoch,
                fragment_size=self.fragment_size,
                p=self.p,
                timeout_ms=self.timeout_ms,
            )
            sidecar = Sidecar(
                fragment=fragment,
                signing_key=signing_key,
                gateway_public_key=private_key.public_key,
                epoch=epoch,
                envelope=envelope,
            )
            registrations.append(
                AgentRegistration(
                    agent_id=agent_id,
                    verify_key=sidecar.verify_key,
                    fragment_commitment=sidecar.fragment_commitment,
                    envelope=envelope,
                    fragment_size=fragment.size,
                    p=fragment.p,
                )
            )
            sidecars[agent_id] = sidecar

        self._erase()
        return SetupArtifacts(
            registry_epoch=epoch,
            private_key=private_key,
            grid=grid,
            registrations=registrations,
            sidecars=sidecars,
            report=SetupReport(
                full_puzzle_deleted=self._full_puzzle is None,
                seed_deleted=self._seed is None,
                setup_shutdown=self._shutdown,
            ),
        )

    def _erase(self) -> None:
        self._full_puzzle = None
        self._fragments = None
        self._seed = None
        self._shutdown = True
