<p align="center"><img src="docs/wizard.png" alt="TinySesam" width="60" height="60"></p>

<h1 align="center">Contributing</h1>

<p align="center"><b>English</b> · <a href="i18n/CONTRIBUTING.de.md">Deutsch</a></p>

Thanks for taking the time. TinySesam is an authentication library — a small surface that other
projects trust with their front door. A change that keeps that surface small and obvious is usually
the better change.

## Ground rules

1. **Tests belong to the change, not to the cleanup.** If you change behaviour, change a test in the
   same commit. Documentation and `CHANGELOG.md` move with it too.
2. **The suite must be repeatable.** Run `./scripts/check.sh` twice — both runs green. A test that
   fails on the second run is broken, not the code. The residue check enforces it.
3. **Security changes are not cosmetic.** Anything touching sessions, guards, factor chains, token
   handling or the login flow gets a test that would fail without the fix. "It obviously works" is
   not a review.
4. **No personal names in the repository.** No private hostnames, no service domains, no customer
   names — not in code, docs, tests or commit messages. Identity is fine (author, contact e-mail,
   repo URL); infrastructure is not. `tests/test_repo.py` enforces this.
5. **Everything optional stays optional.** A feature (a new factor, a provider) must not become a
   hard dependency of the core. The frontend is replaceable; keep it that way.

## Workflow

Work on a feature branch. CI does not run there — `ci-local` (or `./scripts/check.sh`) is your safety
net. Open a pull request; CI runs on the PR and on `main`, and `main` merges only when it is green.

```bash
git switch -c my-change
python -m venv .venv && . .venv/bin/activate
pip install -e ".[all]"
git config core.hooksPath .githooks    # once per clone; runs the suite before every push
# ... edit, then:
./scripts/check.sh
```

## Style

Match the surrounding code: same naming, same comment density. A comment states a constraint the
code cannot show — not what the next line does. German is the project language for docs and
comments; identifiers stay in English.

## Reporting a vulnerability

Do **not** open a public issue for security problems. Use GitHub's private vulnerability reporting
(the *Report a vulnerability* button under *Security*), or write to admin@ollornog.de. See
[`SECURITY.md`](SECURITY.md).
