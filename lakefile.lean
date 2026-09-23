import Lake
open System Lake DSL

def opensslIncludeArgs : Array String :=
  match get_config? opensslPrefix with
  | some dir => #["-I" ++ dir ++ "/include"]
  | none => #[]

def opensslLinkArgs : Array String :=
  (match get_config? opensslPrefix with
   | some dir => #["-L" ++ dir ++ "/lib"]
   | none => #[]) ++ #["-lssl", "-lcrypto"]

package blackworm where
  version := v!"0.1.0"
  keywords := #["math", "crypto"]
  moreLinkArgs := opensslLinkArgs
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`relaxedAutoImplicit, false⟩,
    ⟨`weak.linter.mathlibStandardSet, true⟩,
    -- Mathlib's header linter requires Apache wording; this project is GPLv3.
    ⟨`weak.linter.style.header, false⟩,
    ⟨`maxSynthPendingDepth, 3⟩]

require mathlib from git "https://github.com/leanprover-community/mathlib4" @ "v4.34.0"

target opensslObject pkg : FilePath := do
  let source ← inputFile (pkg.dir / "openssl_crypto.c") true
  buildO (pkg.buildDir / "native" / "openssl_crypto.o") source
    #["-I", (← getLeanIncludeDir).toString]
    (opensslIncludeArgs ++ #["-std=c11", "-O3", "-fPIC", "-Wall", "-Wextra"])
    "cc" getLeanTrace

extern_lib openssl_crypto pkg := do
  let object ← fetch (pkg.target ``opensslObject)
  buildStaticLib (pkg.buildDir / "lib" / nameToStaticLib "openssl_crypto") #[object]

@[default_target]
lean_lib Blackworm

lean_lib Bench
lean_lib Test

lean_exe bench where
  root := `Bench

lean_exe test where
  root := `Test
