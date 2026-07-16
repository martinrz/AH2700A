"""Backend name -> factory registry, so the GUI's backend dropdown and any
config/workspace file can refer to backends by a stable string name."""

from __future__ import annotations

from typing import Callable

from revbench.core.isa import ISABackend

_FACTORIES: dict[str, Callable[[], ISABackend]] = {}


def register(name: str, factory: Callable[[], ISABackend]) -> None:
    _FACTORIES[name] = factory


def create(name: str) -> ISABackend:
    try:
        factory = _FACTORIES[name]
    except KeyError:
        raise KeyError(f"no ISA backend registered as {name!r}; available: {sorted(_FACTORIES)}")
    return factory()


def available() -> list[str]:
    return sorted(_FACTORIES)


def _register_builtin_backends() -> None:
    """Deferred import so importing this module never requires capstone to
    be installed unless an M68K backend instance is actually requested."""
    if "m68k" not in _FACTORIES:
        def _make_m68k() -> ISABackend:
            from revbench.backends.m68k.backend import M68KBackend
            return M68KBackend()
        register("m68k", _make_m68k)


_register_builtin_backends()
