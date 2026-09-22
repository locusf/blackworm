-- Timing and statistics utilities for the Blackworm benchmark scaffolding.
--
-- These helpers wrap `IO.monoNanosNow` to measure wall-clock durations of
-- arbitrary `IO` actions and reduce a series of samples down to summary
-- statistics (min/max/mean/median/stddev) plus human-readable formatting
-- for durations and throughput.
namespace Bench

/-- Run `act`, returning its result together with the elapsed wall-clock
time in nanoseconds. -/
def timeIO {α : Type} (act : IO α) : IO (α × Nat) := do
  let start ← IO.monoNanosNow
  let result ← act
  let stop ← IO.monoNanosNow
  return (result, stop - start)

/-- Run `act` purely for its timing, discarding the result. -/
def timeIO' (act : IO Unit) : IO Nat := do
  let (_, elapsed) ← timeIO act
  return elapsed

/-- Summary statistics for a series of nanosecond duration samples. -/
structure Stats where
  samples  : Nat
  totalNs  : Nat
  minNs    : Nat
  maxNs    : Nat
  meanNs   : Float
  medianNs : Float
  stddevNs : Float
  deriving Inhabited, Repr

/-- Reduce a non-empty array of nanosecond durations to `Stats`. Returns
`Stats` with all-zero fields for an empty input. -/
def computeStats (durations : Array Nat) : Stats :=
  if durations.isEmpty then
    { samples := 0, totalNs := 0, minNs := 0, maxNs := 0,
      meanNs := 0.0, medianNs := 0.0, stddevNs := 0.0 }
  else
    let n := durations.size
    let total := durations.foldl (init := 0) (· + ·)
    let mn := durations.foldl (init := durations[0]!) min
    let mx := durations.foldl (init := durations[0]!) max
    let mean := total.toFloat / n.toFloat
    let sorted := durations.qsort (· < ·)
    let median :=
      if n % 2 == 1 then
        (sorted[n / 2]!).toFloat
      else
        ((sorted[n / 2 - 1]!).toFloat + (sorted[n / 2]!).toFloat) / 2.0
    let variance :=
      (durations.foldl (init := 0.0)
        (fun acc d => acc + (d.toFloat - mean) * (d.toFloat - mean))) / n.toFloat
    { samples := n, totalNs := total, minNs := mn, maxNs := mx,
      meanNs := mean, medianNs := median, stddevNs := variance.sqrt }

/-- Format a nanosecond duration (as a `Float` to keep sub-nanosecond
precision from averages) using an auto-scaled unit: ns, µs, ms, or s. -/
def formatDuration (ns : Float) : String :=
  if ns < 1000.0 then
    s!"{ns.toUInt64} ns"
  else if ns < 1000000.0 then
    s!"{ns / 1000.0} µs"
  else if ns < 1000000000.0 then
    s!"{ns / 1000000.0} ms"
  else
    s!"{ns / 1000000000.0} s"

/-- Format a fixed-point-ish `Float` truncated to two decimal digits, since
Lean's default `Float` `toString` prints many digits. -/
def fmt2 (x : Float) : String :=
  let scaled := (x * 100.0).round
  let whole := (scaled / 100.0).toUInt64
  let frac := ((scaled - whole.toFloat * 100.0)).toUInt64
  s!"{whole}.{if frac < 10 then "0" else ""}{frac}"

/-- Throughput in MiB/s given a payload size in bytes and an elapsed time
in nanoseconds. -/
def throughputMiBs (bytes : Nat) (ns : Float) : Float :=
  if ns == 0.0 then 0.0
  else (bytes.toFloat / (1024.0 * 1024.0)) / (ns / 1000000000.0)

/-- Operations per second given an elapsed time in nanoseconds. -/
def opsPerSec (ns : Float) : Float :=
  if ns == 0.0 then 0.0 else 1000000000.0 / ns

end Bench
