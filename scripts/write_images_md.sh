#!/bin/sh
# Prints the pinned base images (from the Dockerfile) so the bundle records what it was built from.
cd "$(dirname "$0")/.."
echo "# Base images (pinned by digest)"
echo
grep -E "^FROM " Dockerfile | sed "s/--platform=[^ ]* //" | awk '{print "- `" $2 "`  (stage " $4 ")"}'
echo
echo "Bundle architecture: ${ARCH:-unknown}"
echo "Wheels: $(find intel/wheels -name "*.whl" | wc -l | tr -d ' ') files in intel/wheels/ (arch: ${ARCH:-unknown})"
