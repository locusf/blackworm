-- Benchmarking scaffolding for the Blackworm dynamically generated
-- Feistel cipher and its OpenSSL-backed round functions.
--
-- Build and run:
--   lake build bench
--   lake exe bench [--warmup N] [--iters N] [--blocks N] [--only SUBSTR] [--csv PATH] [--list]
--
-- Every timed action is compiled by Lean's C backend just like the rest of
-- the project (see `.lake/build/ir/Bench/*.c` after building), so this is
-- also a convenient way to inspect the generated C for the benchmarked
-- code paths.
import Bench.Timing
import Bench.Suite

namespace Bench

structure Options where
  warmup    : Nat := 20
  iters     : Nat := 200
  blocks    : Nat := 64
  only      : Option String := none
  csvPath   : Option String := none
  listOnly  : Bool := false

def usage : String :=
"Blackworm benchmark scaffolding

Usage: bench [options]

Options:
  --warmup N     Untimed warmup iterations per case (default 20)
  --iters N      Timed iterations per case (default 200)
  --blocks N     Block count for multi-block cipher cases (default 64)
  --only SUBSTR  Only run cases whose name contains SUBSTR
  --csv PATH     Also write results as CSV to PATH
  --list         List available benchmark case names and exit
  --help         Show this message"

partial def parseArgs (args : List String) (opts : Options) : Except String Options :=
  match args with
  | [] => .ok opts
  | "--warmup" :: n :: rest =>
    match n.toNat? with
    | some v => parseArgs rest { opts with warmup := v }
    | none => .error s!"--warmup expects a natural number, got '{n}'"
  | "--iters" :: n :: rest =>
    match n.toNat? with
    | some v => parseArgs rest { opts with iters := v }
    | none => .error s!"--iters expects a natural number, got '{n}'"
  | "--blocks" :: n :: rest =>
    match n.toNat? with
    | some v => parseArgs rest { opts with blocks := v }
    | none => .error s!"--blocks expects a natural number, got '{n}'"
  | "--only" :: s :: rest => parseArgs rest { opts with only := some s }
  | "--csv" :: p :: rest => parseArgs rest { opts with csvPath := some p }
  | "--list" :: rest => parseArgs rest { opts with listOnly := true }
  | "--help" :: _ => .error usage
  | arg :: _ => .error s!"Unrecognized argument '{arg}'\n\n{usage}"

def selectCases (opts : Options) (cases : Array BenchCase) : Array BenchCase :=
  match opts.only with
  | none => cases
  | some substr => cases.filter (fun c => (c.name.splitOn substr).length > 1)

def resultRow (c : BenchCase) (s : Stats) : String :=
  let meanThroughput := throughputMiBs c.bytesPerOp s.meanNs
  s!"{c.name}\n  samples={s.samples}  min={formatDuration s.minNs.toFloat}  mean={formatDuration s.meanNs}  median={formatDuration s.medianNs}  max={formatDuration s.maxNs.toFloat}  stddev={formatDuration s.stddevNs}  throughput={fmt2 meanThroughput} MiB/s  ops/s={fmt2 (opsPerSec s.meanNs)}"

def csvRow (c : BenchCase) (s : Stats) : String :=
  s!"{c.name},{s.samples},{s.minNs},{fmt2 s.meanNs},{fmt2 s.medianNs},{s.maxNs},{fmt2 s.stddevNs},{fmt2 (throughputMiBs c.bytesPerOp s.meanNs)}"

def csvHeader : String :=
  "name,samples,min_ns,mean_ns,median_ns,max_ns,stddev_ns,throughput_mib_s"

def runSuite (opts : Options) : IO Unit := do
  let allCases ← defaultCases opts.blocks
  let cases := selectCases opts allCases
  if cases.isEmpty then
    IO.eprintln "No benchmark cases matched; use --list to see available names."
    return
  IO.println s!"Blackworm benchmark scaffolding — warmup={opts.warmup} iters={opts.iters} blocks={opts.blocks}"
  IO.println s!"Running {cases.size} case(s)...\n"
  let mut csvLines : Array String := #[csvHeader]
  for c in cases do
    let stats ← runCase opts.warmup opts.iters c
    IO.println (resultRow c stats)
    csvLines := csvLines.push (csvRow c stats)
  match opts.csvPath with
  | none => pure ()
  | some path =>
    IO.FS.writeFile path (String.intercalate "\n" csvLines.toList ++ "\n")
    IO.println s!"\nCSV results written to {path}"

def main (args : List String) : IO UInt32 := do
  if args.contains "--help" then
    IO.println usage
    return 0
  match parseArgs args {} with
  | .error msg =>
    IO.eprintln msg
    return 1
  | .ok opts =>
    if opts.listOnly then
      let cases ← defaultCases opts.blocks
      for c in cases do
        IO.println c.name
      return 0
    else
      runSuite opts
      return 0

end Bench

def main (args : List String) : IO UInt32 := Bench.main args
