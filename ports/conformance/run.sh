#!/usr/bin/env bash
# Run the shared vectors (spec/conformance) against the Python reference and every port.
#   ports/conformance/run.sh            all engines whose toolchain is installed
#   ports/conformance/run.sh node go    only these
# Exit code: 1 if any engine fails; an engine whose toolchain is missing is reported as skipped.
set -u
cd "$(dirname "$0")/../.."
ROOT=$PWD
V="${SMARTWATCH_VECTORS:-$ROOT/spec/conformance}"   # another vectors folder: SMARTWATCH_VECTORS=dir
want=("$@"); [ ${#want[@]} -eq 0 ] && want=(python node go rust java csharp php ruby)
fail=0
run() {  # name, required tool, command...
  local name=$1 tool=$2; shift 2
  if ! command -v "$tool" >/dev/null 2>&1; then echo "$name: skipped ($tool not installed)"; return; fi
  if out=$("$@" 2>&1); then echo "$out" | tail -1; else echo "$out" | tail -20; echo "$name: FAILED"; fail=1; fi
}
for e in "${want[@]}"; do
  case $e in
    python) run python python3 python3 -c "import sys; sys.path.insert(0,'src'); from sf_smartwatch.conformance import run_dir; t,f=run_dir('$V'); print(*f, sep='\n') if f else None; print(f'python: {t-len(f)}/{t} vectors passed' if not f else 'python: FAILED'); sys.exit(1 if f else 0)" ;;
    node) run node node node ports/node/test/conformance.js "$V" ;;
    go) run go go bash -o pipefail -c "cd ports/go && go vet ./... && go run ./cmd/conformance '$V'" ;;
    rust) run rust cargo bash -o pipefail -c "cd ports/rust && cargo run --quiet --offline --release --bin conformance '$V'" ;;
    java) run java javac bash -o pipefail -c "ports/java/build.sh && java -cp ports/java/build/classes cloud.smarttasks.smartwatch.Conformance '$V' 2>&1 | grep -v '^Picked up'" ;;
    csharp) run csharp dotnet bash -o pipefail -c "cd ports/csharp && dotnet run -c Release --project Conformance -- '$V' 2>&1 | tail -1" ;;
    php) run php php php ports/php/bin/conformance.php "$V" ;;
    ruby) run ruby ruby ruby ports/ruby/bin/conformance.rb "$V" ;;
    *) echo "unknown engine $e"; fail=1 ;;
  esac
done
exit $fail
