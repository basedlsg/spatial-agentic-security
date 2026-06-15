"""Import firewall for optional external solvers.

External solver wheels (OR-Tools, PySAT, Z3, networkx) may be missing on some
platforms / Python versions. Each solver entrypoint checks availability here and
degrades to a recorded `solver_unavailable` result instead of crashing the build,
so the pure-Python core (DLX exact-cover + ESU enumeration) always runs.
"""

from __future__ import annotations

import importlib
from typing import Optional


def _try(modname: str):
    try:
        return importlib.import_module(modname), None
    except Exception as exc:  # pragma: no cover - platform dependent
        return None, str(exc)


_MODULES = {
    "cp_sat": "ortools.sat.python.cp_model",
    "sat": "pysat.solvers",
    "smt": "z3",
    "graph_iso": "networkx",
}

_MODULE: dict[str, object] = {}
ERRORS: dict[str, Optional[str]] = {}
for _name, _mod in _MODULES.items():
    obj, err = _try(_mod)
    _MODULE[_name] = obj
    ERRORS[_name] = err

AVAILABILITY: dict[str, bool] = {name: _MODULE[name] is not None for name in _MODULES}


def available(name: str) -> bool:
    """True if the external solver `name` imported successfully (unknown names: True)."""

    return AVAILABILITY.get(name, True)


def import_error(name: str) -> Optional[str]:
    return ERRORS.get(name)


def module(name: str):
    return _MODULE.get(name)
