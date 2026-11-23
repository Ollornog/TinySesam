# Contributing

<b>English</b> · <a href="i18n/CONTRIBUTING.de.md">Deutsch</a>
<br /><br />

Thanks for taking the time. TinySesam is an authentication library — a small surface that other
projects trust with their front door. A change that keeps that surface small and obvious is usually
the better change.

## Ground rules

1. **Tests belong to the change, not to the cleanup.** If you change behaviour, change a test in the
   same commit. Documentation and `CHANGELOG.md` move with it too.
2. **The suite must be repeatable.** The nightly repeat run (`nightly-repeat`: the CI suite twice on
   `main`) checks it; before a push the fast pre-push hook is enough, the header of `.githooks/pre-push` names the switch for the full gate. A test
   that fails on the second run is broken, not the code. The residue check enforces it.
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

## Testing a commit before a release

A commit between two releases carries the version of the last release. `pip install "tinysesam @ git+…@<sha>"` over an
installed release reports "already satisfied" and installs nothing — the service keeps running the old code (or, on a
restart in between, a half-replaced one). Force the reinstall — with the dependencies, which is safe also when the
commit adds or changes an extra or a dependency, or when you switch extras (say to `[all]`):

```bash
pip install --force-reinstall "tinysesam[all] @ git+https://github.com/Ollornog/TinySesam.git@<sha>"
```

Quicker, when neither the extras nor the dependencies change: add `--no-deps` — only the package is replaced. With a
changed extra that leaves packages missing.

Restart the service afterwards; `pip freeze | grep -i tinysesam` names the commit that is installed.

## Style

Match the surrounding code: same naming, same comment density. A comment states a constraint the
code cannot show — not what the next line does. The project language is English: identifiers
(functions, classes, parameters, variables, constants, file names), database table and column
names, comments, docstrings, documentation, commit messages and pull requests are written in English.
German exists only as a translation of the interface (`lang="de"`, `i18n/`). `tests/test_english_code.py`
enforces this: a German word in an identifier, a file name, SQL or a comment makes the suite red.

## Reporting a bug

Run `python -m tinysesam diagnose` (gateway image: `python -m tinysesam.gateway diagnose`) and open the link it prints:
it fills the bug form with a redacted report — no network request, nothing sent until you submit. See the README,
["Reporting a bug"](README.md#reporting-a-bug).

## Reporting a vulnerability

Do **not** open a public issue for security problems. Use GitHub's private vulnerability reporting
(the *Report a vulnerability* button under *Security*), or write to tinysesam-github@ollornog.de. See
[`SECURITY.md`](SECURITY.md).

<br /><br />
<p align="right"><img src="docs/wizard.png" alt="TinySesam" width="60" height="60"></p>
