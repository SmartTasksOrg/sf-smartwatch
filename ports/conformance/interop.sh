#!/usr/bin/env bash
# Each port's interop program against the Python monitor (ports/conformance/interop.py).
#   ports/conformance/interop.sh            every port whose toolchain is installed
#   ports/conformance/interop.sh go ruby    only these
set -u
cd "$(dirname "$0")/../.."
want=("$@"); [ ${#want[@]} -eq 0 ] && want=(python node go rust java csharp php ruby)
fail=0
run() {  # name, required tool, build command (or ""), agent command...
  local name=$1 tool=$2 build=$3; shift 3
  if ! command -v "$tool" >/dev/null 2>&1; then echo "$name: skipped ($tool not installed)"; return; fi
  if [ -n "$build" ] && ! out=$(bash -o pipefail -c "$build" 2>&1); then echo "$out" | tail -20; echo "$name: build FAILED"; fail=1; return; fi
  if out=$(timeout 180 python3 ports/conformance/interop.py -- "$@" 2>&1); then echo "$name: $(echo "$out" | tail -1)"
  else echo "$out" | grep -v 'heartbeat failed' | tail -20; echo "$name: interop FAILED"; fail=1; fi
}
for e in "${want[@]}"; do
  case $e in
    python) run python python3 "" python3 ports/conformance/python_agent.py ;;
    node) run node node "" node ports/node/bin/interop.js ;;
    go) run go go "cd ports/go && go build -o /tmp/smartwatch-go-interop ./cmd/interop" /tmp/smartwatch-go-interop ;;
    rust) run rust cargo "cd ports/rust && cargo build --quiet --offline --release --bin interop" ports/rust/target/release/interop ;;
    java) run java javac "ports/java/build.sh" java -cp ports/java/build/classes cloud.smarttasks.smartwatch.Interop ;;
    csharp) run csharp dotnet "cd ports/csharp && dotnet build -c Release Interop -o /tmp/smartwatch-cs-interop" dotnet /tmp/smartwatch-cs-interop/Interop.dll ;;
    php) run php php "" php ports/php/bin/interop.php ;;
    ruby) run ruby ruby "" ruby ports/ruby/bin/interop.rb ;;
    *) echo "unknown port $e"; fail=1 ;;
  esac
done
exit $fail
