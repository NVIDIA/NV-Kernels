BaseOS Reviewer build validation canary
=======================================

DO NOT MERGE. This temporary documentation-only change exercises BaseOS
Reviewer kernel, NVIDIA GPU-driver, and DOCA module compilation for this
pull request's exact head. It changes no kernel behavior or shipping policy.

The canary validates GPU 615.71.09 and 580.178.04 with DOCA 3.3.0 on the
configured amd64 and arm64 build profiles. Compilation outcomes are separate
from Boro review findings. GPU/DOCA peer-memory pairing is not yet validated.
No kernel is booted and no driver is installed or loaded.
