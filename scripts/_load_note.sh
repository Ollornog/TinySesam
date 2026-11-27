#!/usr/bin/env bash
# Load note at failure (kit 0.64.0) — copied here by `repokit sync`, do not edit by hand.
#
# WHY (PO 2026-11-23, "red with a load note" instead of yellow, no automatic retry): a job that failed on a busy runner
# looks like any other red job. Measured: check jobs of a private repo ran 31 instead of 16 min on a runner that had
# 4 instead of 8 cores. One line at the failure makes "red under load" visible in seconds.
#
# Use as the last step of a job:
#
#       - name: Load at failure
#         if: failure()
#         run: scripts/_load_note.sh
#
# The kit templates (dependabot auto-merge, nightly-repeat) have no checkout; `repokit` renders the body between the
# markers below into their jobs, so this file is the only source.
#
# Output, one line, the same in three places:
#   - the job summary ($GITHUB_STEP_SUMMARY), as a bullet
#   - an annotation `::notice title=load-at-failure::<line>` (readable via the check-run annotations API)
#   - the job log
# Line format (fields separated by " · ", a field that cannot be read is left out, never guessed):
#   load-at-failure: runner=<name> host=<host> cores=<n>[ ci_cores=<n>][ cpu_quota=<n>] loadavg=<1m>/<5m>/<15m>
#   psi_cpu=<avg10>/<avg60> psi_mem=<avg10>/<avg60> psi_io=<avg10>/<avg60> mem_free=<MiB>/<MiB> job=<m>m<s>s
# PSI is the "some" line of /proc/pressure/* (percent of time at least one task waited). Job time is measured from the
# event file the runner writes at job start ($GITHUB_EVENT_PATH).
# It never fails the job further: every read is guarded, the exit code is always 0.
# Cores are read from the cgroup (the CPUs this job may use), else /proc/cpuinfo (lxcfs shows the container's) — read,
# not detected for workers: the worker count stays the env CI_KERNE (the kit hygiene forbids core detection there).
# >>> body
fields=()
fields+=("runner=${RUNNER_NAME:-?}" "host=$(uname -n 2>/dev/null || echo '?')")
cpus=""
if read -r cpuset 2>/dev/null < /sys/fs/cgroup/cpuset.cpus.effective && [ -n "$cpuset" ]; then
  cpus="$(awk -v s="$cpuset" 'BEGIN { n = split(s, t, ","); for (i = 1; i <= n; i++) c += (split(t[i], r, "-") == 2) ? r[2] - r[1] + 1 : 1; print c }')"
fi
[ -n "$cpus" ] || cpus="$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)" || cpus='?'
cores_field="cores=$cpus"
[ -n "${CI_KERNE:-}" ] && cores_field+=" ci_cores=$CI_KERNE"
if read -r q p 2>/dev/null < /sys/fs/cgroup/cpu.max && [ "$q" != max ] && [ "${p:-0}" -gt 0 ] 2>/dev/null; then
  cores_field+=" cpu_quota=$(awk -v q="$q" -v p="$p" 'BEGIN { printf "%.1f", q / p }')"
fi
fields+=("$cores_field")
if read -r l1 l5 l15 _ 2>/dev/null < /proc/loadavg; then fields+=("loadavg=$l1/$l5/$l15"); fi
for art in cpu memory io; do
  z="$(grep -m1 '^some' "/proc/pressure/$art" 2>/dev/null)" || continue
  a10="${z#*avg10=}"; a10="${a10%% *}"; a60="${z#*avg60=}"; a60="${a60%% *}"
  fields+=("psi_${art/memory/mem}=$a10/$a60")
done
mem="$(awk '/^MemAvailable:/ { a = $2 } /^MemTotal:/ { t = $2 } END { if (a && t) printf "%d/%d", a / 1024, t / 1024 }' /proc/meminfo 2>/dev/null)"
[ -n "$mem" ] && fields+=("mem_free=${mem}MiB")
if [ -n "${GITHUB_EVENT_PATH:-}" ] && start="$(stat -c %Y "$GITHUB_EVENT_PATH" 2>/dev/null)"; then
  d=$(( $(date +%s) - start )); fields+=("job=$((d / 60))m$((d % 60))s")
fi
line="load-at-failure: $(printf '%s · ' "${fields[@]}")"; line="${line% · }"
echo "$line"
echo "::notice title=load-at-failure::$line"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && ! { printf -- '- %s\n' "$line" >> "$GITHUB_STEP_SUMMARY"; } 2>/dev/null; then
  echo "job summary not writable — the line is in the log and the annotation"
fi
exit 0
# <<< body
