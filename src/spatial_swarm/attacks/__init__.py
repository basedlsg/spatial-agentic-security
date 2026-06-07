"""Executable USAG adversaries."""

from spatial_swarm.attacks.duplicate_agent import DuplicateAgent
from spatial_swarm.attacks.fake_agent import RandomFakeAgent
from spatial_swarm.attacks.malformed_agent import MalformedAgent
from spatial_swarm.attacks.overbudget_agent import OverBudgetAgent, UnderBudgetAgent
from spatial_swarm.attacks.replay_agent import ReplayAgent
from spatial_swarm.attacks.slow_agent import SlowAgent
from spatial_swarm.attacks.stolen_piece_agent import StolenSinglePieceAgent
from spatial_swarm.attacks.wrong_message_agent import WrongMessageAgent

__all__ = [
    "DuplicateAgent",
    "MalformedAgent",
    "OverBudgetAgent",
    "RandomFakeAgent",
    "ReplayAgent",
    "SlowAgent",
    "StolenSinglePieceAgent",
    "UnderBudgetAgent",
    "WrongMessageAgent",
]
