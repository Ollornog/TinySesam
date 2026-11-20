"""Factor chains with alternatives (T-34) — pure functions over names, no state.

A chain (`config.login_chain`) is a list of **steps**. A step names one factor (`"totp"`) or
alternatives separated by `|` (`"password|passkey"`): any one of them satisfies the step. The type
stays `list[str]`, so a chain without `|` means exactly what it meant before.

**A factor satisfies at most one step.** `["password|passkey", "totp|passkey"]` with nothing but a
passkey is NOT complete — otherwise one tap would count as two factors. In a strict chain the
factors must also have arrived in the order of the steps.

The functions here are the one source of that rule for the engine (`TinySesam._chain_satisfied`,
`_next_login_step`), the configuration (`pin_as_first_factor`) and the configuration check. Chains
are short (a handful of steps, a session holds each factor name once), so the search is a plain
backtracking/augmenting-path search, not something clever.
"""
from __future__ import annotations

from typing import Iterable, Optional, Sequence


def steps(chain: Optional[Iterable]) -> list[tuple[str, ...]]:
    """The steps of a chain, each as a tuple of its alternatives (trimmed, duplicates dropped)."""
    out: list[tuple[str, ...]] = []
    for entry in chain or ():
        options: list[str] = []
        for part in str(entry).split("|"):
            name = part.strip()
            if name and name not in options:
                options.append(name)
        out.append(tuple(options))
    return out


def factors(chain: Optional[Iterable]) -> set[str]:
    """Every factor name the chain mentions, alternatives included."""
    return {f for step in steps(chain) for f in step}


def first_step(chain: Optional[Iterable]) -> tuple[str, ...]:
    """The alternatives of the first step (the one that identifies the account), or `()`."""
    st = steps(chain)
    return st[0] if st else ()


def satisfied(chain: Sequence, done: Sequence[str], strict: bool) -> bool:
    """Does the list of provided factors satisfy every step — each step by its own factor and, if
    `strict`, in the order of the steps?"""
    st = steps(chain)
    got = list(dict.fromkeys(done or ()))

    def place(i: int, after: int, used: frozenset) -> bool:
        if i == len(st):
            return True
        for pos, name in enumerate(got):
            if name in st[i] and pos not in used and (not strict or pos > after):
                if place(i + 1, pos, used | {pos}):
                    return True
        return False

    return place(0, -1, frozenset())


def _match(st: list[tuple[str, ...]], have: Iterable[str]) -> dict:
    """Maximum matching step → factor (each factor once), steps tried in chain order.

    Returns `{factor: step index}`. A step that is matched once stays matched (augmenting paths only
    move it to another factor), so the steps left over are the LAST ones that cannot be covered —
    "what is missing" reads in chain order."""
    pool = set(have or ())
    owner: dict = {}

    def augment(i: int, seen: set) -> bool:
        for name in st[i]:
            if name in pool and name not in seen:
                seen.add(name)
                if name not in owner or augment(owner[name], seen):
                    owner[name] = i
                    return True
        return False

    for i in range(len(st)):
        augment(i, set())
    return owner


def uncovered(chain: Sequence, have: Iterable[str]) -> list[int]:
    """Indexes of the steps that the factors in `have` cannot cover (each factor once)."""
    st = steps(chain)
    covered = set(_match(st, have).values())
    return [i for i in range(len(st)) if i not in covered]


def covered(chain: Sequence, have: Iterable[str]) -> list[int]:
    """Indexes of the steps that the factors in `have` can cover (each factor once)."""
    return sorted(set(_match(steps(chain), have).values()))


def assignable(chain: Sequence) -> bool:
    """Can the chain be satisfied at all — every step by a factor of its own? (`["password",
    "password"]` cannot: one password satisfies one step.)"""
    st = steps(chain)
    return all(st) and not uncovered(chain, factors(chain))


def next_options(chain: Sequence, done: Sequence[str]) -> list[str]:
    """The factors that move the sign-in on: the alternatives of the first step (in chain order) for
    which a factor not provided yet would cover one more step. `[]` when none would.

    For a chain without alternatives this is the first factor not in `done` — the rule up to
    T-34. The order of the steps is deliberately not considered here (as before): it decides
    whether the chain is satisfied, not which page comes next."""
    st = steps(chain)
    got = list(dict.fromkeys(done or ()))
    base = len(_match(st, got))
    for step in st:
        gain = [f for f in step if f not in got and len(_match(st, got + [f])) > base]
        if gain:
            return gain
    return []

