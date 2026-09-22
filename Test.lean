-- Correctness test runner for the Blackworm dynamically generated Feistel
-- cipher chain.
--
-- Build and run:
--   lake build test
--   lake exe test
--
-- Exits 0 if every test case passes, 1 otherwise (so it can be used as a
-- CI gate, unlike `bench`, which never fails).
import Test.Suite

namespace Test

def main : IO UInt32 := do
  let cases ← defaultCases
  IO.println s!"Blackworm correctness tests — running {cases.size} case(s)...\n"
  let mut failures : Nat := 0
  for c in cases do
    let passed ← try
        c.run
      catch e =>
        IO.eprintln s!"  unexpected exception: {e.toString}"
        pure false
    if passed then
      IO.println s!"PASS  {c.name}"
    else
      IO.eprintln s!"FAIL  {c.name}"
      failures := failures + 1
  IO.println ""
  if failures == 0 then
    IO.println s!"All {cases.size} test case(s) passed."
    return 0
  else
    IO.eprintln s!"{failures}/{cases.size} test case(s) failed."
    return 1

end Test

def main (_args : List String) : IO UInt32 := Test.main
