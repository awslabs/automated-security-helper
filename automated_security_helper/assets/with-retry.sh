#!/bin/bash
# Retry a command up to $max times with exponential backoff.
#
# `-o pipefail` belongs on the inner shell, not this one. pipefail is a shell
# option rather than an environment variable, so it does not cross a `bash -c`
# boundary: setting it here would leave the command on line 5 running with
# bash's default behaviour, where a pipeline reports only its *last* command's
# status.
#
# That distinction is the whole point of this script. Almost every caller is a
# piped network install of the form
#
#     with-retry 'curl -sSfL https://.../install.sh | sh -s -- -b /usr/local/bin'
#
# and `sh` exits 0 when curl dies and hands it an empty stdin. Without pipefail
# on the inner shell the pipeline "succeeds", this loop exits on the first
# attempt, and the retry never happens -- the failure surfaces several layers
# later as a missing binary. Observed on 2026-08-20: curl hit
# "(35) Recv failure: Connection reset by peer" fetching grype's installer, no
# retry was attempted, and the build died at the next step with
# "grype: not found" (exit 127).
set -o pipefail
# Overridable so the retry behaviour can be exercised without waiting out the
# real backoff. Defaults are what every Dockerfile caller gets.
#
# Five attempts, not three. Three gave sleeps of 5s and 10s, so the whole retry
# window was about 15 seconds plus the time the attempts themselves took, and the
# thing being retried is a GitHub-hosted runner's egress. Measured on run
# 35246976698, that egress was impaired for longer than the window: the syft
# install made three attempts at 16:41:55, 16:42:01 and 16:42:12 and every one of
# them failed to resolve a host, exhausting the budget after 17 seconds while the
# impairment continued. In the same run, on a different runner, the docker pull in
# unit-test (ubuntu-24.04-arm, py3.11) failed DNS resolution for 2m16s straight.
# A budget shorter than the outage it exists to ride out is a budget that only
# ever converts a slow network into a failed build.
#
# Five attempts with the doubling below sleeps 5s, 10s, 20s and 40s: a 75-second
# window, which covers the 17-second case with room and is the same order as the
# longer one. Not raised further because the cost is paid on genuinely-broken
# builds too -- a Dockerfile with fourteen with-retry call sites should not spend
# ten minutes discovering that a URL is permanently 404, and `curl -f` failures of
# that kind are not distinguishable here from a transient one.
max=${WITH_RETRY_MAX_ATTEMPTS:-5}; delay=${WITH_RETRY_DELAY:-5}; attempt=1

# Both knobs feed integer arithmetic below -- `$((delay * 2))` and
# `[ $attempt -le $max ]` -- and bash arithmetic cannot parse a non-integer.
# A fractional WITH_RETRY_DELAY such as 0.1, which is the obvious way to ask for
# a fast-but-nonzero backoff, made `delay=$((delay * 2))` a syntax error. That
# error aborts the enclosing `while` WITHOUT aborting the script (there is no
# `set -e` here, and adding one would change how the attempt loop reports), so
# exactly ONE attempt ran and the script still printed "All 3 attempts failed"
# and exited 1. The attempt count was wrong and the only message anybody reads
# said otherwise, which is precisely why no assertion on that message could see
# it. Reject the bad value instead of retrying once and misreporting it.
#
# `case` rather than a regex or `expr` so this stays dependency-free: it runs in
# the container build stage before most of the toolchain exists.
#
# The `''` arm of both cases is unreachable today, and worth keeping anyway. It is
# unreachable because the assignments above use `${VAR:-default}`, and `:-`
# substitutes for null as well as for unset -- so WITH_RETRY_DELAY="" yields 5,
# not an error, and neither variable can be empty by the time it reaches here.
# Kept because an empty $delay is the one input that would make `$((10#$delay))`
# below a syntax error rather than a wrong number, so the day someone changes
# `:-` to `-` the guard is already in place. The messages describe the value they
# rejected rather than claiming the arm fires.
case $max in
  '' | *[!0-9]*)
    echo "with-retry: WITH_RETRY_MAX_ATTEMPTS must be a non-negative integer, got '$max'" >&2
    exit 2
    ;;
esac
# All digits is not the same as in range for the attempt count either. `test`
# reads its integer operands as 64-bit values and answers anything larger with
# "integer expression expected" and status 2. The `[ "$max" -lt 1 ]` guard below
# is an `if` condition, so that status reads as false and the guard passes; the
# `while` condition then fails the same way and the loop body never runs. The
# script printed "All N attempts failed" and exited 1 without having run the
# command once -- the never-ran-but-reported hazard that guard exists to stop.
#
# Count the digits after stripping padding, on a copy, so the later messages
# still show the value the caller set. Eighteen digits always fit in 63 bits.
digits=$max
while [ "${#digits}" -gt 1 ] && [ "${digits#0}" != "$digits" ]; do digits=${digits#0}; done
if [ "${#digits}" -gt 18 ]; then
  echo "with-retry: WITH_RETRY_MAX_ATTEMPTS must be at most 18 digits, got '$max'" >&2
  exit 2
fi
case $delay in
  '' | *[!0-9]*)
    echo "with-retry: WITH_RETRY_DELAY must be a whole number of seconds, got '$delay'" >&2
    exit 2
    ;;
esac
# All digits is not the same as decimal. `$(( ))` reads a leading zero as octal,
# so the guard above accepts values the arithmetic below cannot evaluate: 08 and
# 09 are not valid octal, and `delay=$((delay * 2))` died on them with
#
#     with-retry.sh: line NN: 08: value too great for base (error token is "08")
#
# reproducing the exact failure this guard was added to stop. One of three
# attempts ran and "All 3 attempts failed" printed anyway, because the arithmetic
# error aborts the `while` without aborting the script.
#
# 010 was worse for being silent: `sleep` parses its argument in base 10 while
# `$(( ))` parses it in base 8, so one string produced two different numbers.
# Measured, the recorded sleeps were 010 then 16 -- ten seconds, then sixteen,
# which is a doubling of neither.
#
# Strip the padding textually first, before any arithmetic touches it. That makes
# the length test below exact -- it measures the value's digits rather than the
# padding's -- so the rejection message can name the real magnitude.
while [ "${#delay}" -gt 1 ] && [ "${delay#0}" != "$delay" ]; do delay=${delay#0}; done
# All digits is also not the same as in range, and past 2^63-1 `$(( ))` wraps
# SILENTLY: measured in bash, $((10#9223372036854775808)) is
# -9223372036854775808 with exit 0 and no diagnostic. That is a worse failure than
# the octal one because it is not an error anywhere. With
# WITH_RETRY_DELAY=9223372036854775808, all digits and so accepted by the guard
# above, the recorded sleeps were -9223372036854775808 then 0: GNU sleep rejects a
# negative interval and exits 1, that status is unchecked, the doubling wraps the
# rest to zero, and all three attempts run back-to-back with NO backoff at all --
# precisely the protection this script exists to provide, silently removed.
#
# So bound the magnitude, not just the character set. 86400 is one day, well past
# any plausible install backoff and far below the wrap. This also closes a hole
# that predates the base-10 fix and needs no overflow to reach it: 99999999 is
# eight digits, wraps nothing, and asked `sleep` for 3.2 years.
#
# Length first, and the short-circuit matters: at most five digits means at most
# 99999, so `$(( ))` cannot wrap and the comparison that follows is meaningful.
# Reversing the two would evaluate the arithmetic on the very input that overflows.
if [ "${#delay}" -gt 5 ] || [ "$((10#$delay))" -gt 86400 ]; then
  echo "with-retry: WITH_RETRY_DELAY must be at most 86400 seconds (24h), got '$delay'" >&2
  exit 2
fi
# `10#` forces base 10, so a leading zero stops mattering. Redundant with the
# padding strip above and kept regardless: it is a local, one-token guarantee that
# does not depend on that loop being right, and it cannot overflow now that the
# length is bounded. Only $delay needs any of this.
#
# $max reaches `test` alone, which parses its integer operands in base 10 --
# `[ 9 -le 010 ]` is true -- so 010 already meant ten attempts consistently, and
# normalizing it would change a path that was already correct. That safety depends
# on this script using `[` exclusively: `[[ ]]` evaluates its operands
# arithmetically, so converting these tests to `[[ ]]` would silently reintroduce
# octal on the attempt count.
delay=$((10#$delay))
# Guarded separately, and only once $max is known to be numeric so `-lt` is
# safe. max=0 would skip the loop entirely and then report "All 0 attempts
# failed" with exit 1 -- a failure indistinguishable from the command having
# been run and failed, when it was never run at all.
if [ "$max" -lt 1 ]; then
  echo "with-retry: WITH_RETRY_MAX_ATTEMPTS must be at least 1, got '$max'" >&2
  exit 2
fi

# The same hazard as max=0 above with the sign flipped, which makes it worse: a
# *success* indistinguishable from the command having been run and succeeded,
# when it was never run at all. `bash -c ""` exits 0, so an empty command takes
# the `&& exit 0` on the first pass of the loop below and this script reports a
# clean run having done nothing.
#
# In a Dockerfile that means `RUN with-retry "$SOME_ARG"` with SOME_ARG unset or
# renamed produces a layer that does nothing, exits 0, and lets the build die
# several steps later at a missing binary -- the failure mode described at the
# top of this file, arrived at from the other direction.
#
# Testing the joined command rather than `$#`: a quoted expansion of an unset
# variable still passes one argument, so `$#` is 1 while `$*` is empty, and that
# is the likelier of the two shapes. `case` for the same reason as above -- this
# runs in the container build stage before most of the toolchain exists.
#
# The arguments are joined with single spaces into one command string, the way
# `eval` joins its own, and that string is what `bash -c` parses. That is the
# contract: callers pass one quoted command (the usage at the top of this file),
# and any further arguments are more words of the same command line. An argument
# that carries spaces or shell metacharacters is therefore not kept as one word;
# quote it inside the command string.
case "$*" in
  *[![:space:]]*) ;;
  *)
    echo "with-retry: no command given" >&2
    exit 2
    ;;
esac

# Exit statuses that are never retried, and are passed through as the script's
# own status. A retry is for a failure the next attempt can cure: a reset
# connection, a host that did not resolve. install-pinned-tool exits 3 on a
# SHA256 mismatch against a pinned digest, and its docstring says that status
# is "never retried" so a caller can tell it from a network failure; this loop
# retried it five times anyway, on every pinned install in the Dockerfile,
# and then reported exit 1. One mismatch on a pinned digest is disqualifying,
# and a second fetch of the same bytes either reproduces it or quietly turns a
# supply-chain control into a coin flip. Space-separated; the same `case` idiom
# as the knobs above.
#
# 2 is in the default as well. install-pinned-tool exits 2 for a request that
# can never succeed: an unknown tool or bundle, a platform with no asset, a
# non-https URL, a half-applied version bump. Another attempt repeats the same
# refusal, so retrying it five times only delays the build by the whole backoff
# window and then reports a generic failure. A caller that wraps a command which
# uses 2 for a transient failure sets WITH_RETRY_NO_RETRY_EXITS to its own list,
# and a list set explicitly replaces this default rather than extending it.
fatal=${WITH_RETRY_NO_RETRY_EXITS:-2 3}
for code in $fatal; do
  case $code in
    '' | *[!0-9]*)
      echo "with-retry: WITH_RETRY_NO_RETRY_EXITS must be space-separated exit statuses, got '$fatal'" >&2
      exit 2
      ;;
  esac
done

while [ $attempt -le $max ]; do
  bash -o pipefail -c "$*" && exit 0
  rc=$?
  for code in $fatal; do
    if [ "$rc" -eq "$code" ]; then
      echo "with-retry: exit $rc is not retried (WITH_RETRY_NO_RETRY_EXITS='$fatal'); giving up after attempt $attempt/$max" >&2
      exit "$rc"
    fi
  done
  # Announce and take the backoff only when an attempt actually follows it.
  # Unguarded, the final pass printed "Attempt 3/3 failed, retrying in 20s...",
  # slept the full 20 seconds, left the loop, and then printed "All 3 attempts
  # failed" -- two adjacent lines contradicting each other, and 20 seconds of
  # dead wall clock on every failing invocation in the Dockerfile. The message
  # and the sleep are guarded together because either one alone is still wrong:
  # a silent 20-second pause, or a promised retry that never comes.
  if [ "$attempt" -lt "$max" ]; then
    echo "Attempt $attempt/$max failed, retrying in ${delay}s..." >&2
    sleep $delay
    # The 86400 ceiling checked above covers the first interval only. Doubling it
    # on every attempt walks past a day within a few attempts and, with a large
    # attempt count, past 2^63, where `$(( ))` wraps silently to a negative
    # number: GNU sleep rejects that, nothing checks its status, and the
    # remaining attempts run back to back. Cap every interval at the same
    # ceiling. The doubled value is at most twice the ceiling before it is
    # capped, so the arithmetic cannot wrap.
    delay=$((delay * 2))
    if [ "$delay" -gt 86400 ]; then delay=86400; fi
  fi
  attempt=$((attempt + 1))
done
echo "All $max attempts failed" >&2; exit 1
