#!/bin/bash
set -euo pipefail
kubectl get crds  | awk '{print $1}' | grep istio | xargs -L 1 -I '{}' bash -c "echo '    ####   ';echo {}; kubectl get -A {}"
