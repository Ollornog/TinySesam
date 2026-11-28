"""PROBE (T-139, never merged): a script filter whose end-tag regex misses upper case."""
import re

SCRIPT = re.compile(r"<script>.*?</script>", re.S)


def strip_scripts(text: str) -> str:
    return SCRIPT.sub("", text)


assert strip_scripts("a<script>x</script>b") == "ab"
print("  ✓ probe")
