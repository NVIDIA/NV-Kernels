.. SPDX-License-Identifier: GPL-2.0
.. include:: <isonum.txt>

========================================================
PCI Trusted Execution Environment Security Manager (TSM)
========================================================

Maturity Map
============

Given the high number of subsystem touch points and corresponding high
degree of complexity of enabling PCIe device assignment to confidential
guests, a staging tree is needed. The tsm.git#staging tree [1] provides
an integration point for related topics to mature, gain consensus, and
graduate to mainline. What follows is a rough break down of the enabling
topics by phases, the relative maturity of those topics, and the
architecture support for those topics.

NOTE! User ABIs are not final until they ship and are consumed in a
mainline release. The tsm.git#staging may regress and break user flows
from one snapshot to the next.

NOTE2! A topic can go backwards in score based on testing, ongoing
review, or cross-vendor integration failure.

The maturity scores are:

- [3] Mature: Work on this topic is complete the support is queued in
  linux-next or is already in mainline.

- [2] Stabilizing: Major consensus on the core implementation reached.
  At least one vendor implementation consumes the functionality. Final
  bug fixing, review comments, and/or second vendor consumer needed before
  graduating.

- [1] Initial: The proposal is still in the concept phase, has
  significant review feedback to overcome, or significant test/use case
  issues to resolve. The implementation demonstrates functionality,
  but is not considered final.

- [0] Known gap: Near term future work needed for fundamental enabling.
  Note, this is also the score when patches are available, but not yet
  integrated into tsm.git#staging.

- [X]: Out of scope, or long term future work that is not needed for
  fundamental enabling.

PHASE1: Link Encryption and Secure Session Establishment (host-side)
--------------------------------------------------------------------
Description: PCI/TSM core and TSM driver support to establish PCIe CMA
             (PCIe r7.0 section 6.31 Component Measurement and
             Authentication (CMA-SPDM)), and PCIe IDE (PCIe r7.0 section
             6.33 Integrity & Data Encryption (IDE).

* [3]: PCI/TSM core library
* [3]: PCI/IDE core library
* [3]: Sample Platform TSM driver pre-requisites
* [2]: Sample Platform TSM driver implementation
* [0]: Arch Platform TSM driver implementation
* [2]: PCI/TSM: Address Association support
* [2]: PCI/IDE: Unique Stream ID vs IDE_KM quirk

Arch Support: None

PHASE2: Device Lock and Accept (guest-side)
-------------------------------------------
Description: PCI/TSM core, TSM driver, and endpoint driver support to
             advance a device through the TDISP (PCIe r7.0 section 11
             TEE Device Interface Security Protocol (TDISP)) operational
             states (UNLOCKED => LOCKED => RUN).

* [1]: PCI/TSM lock+accept core infrastructure
* [1]: Device-core "accept" state, and TDISP aware driver infrastructure
* [1]: Sample Platform TSM driver implementation
* [0]: Arch Platform TSM driver implementation
* [1]: Sample Endpoint driver TDISP aware implementation
* [0]: Endpoint driver TDISP aware implementation

Arch Support: None

PHASE3: Private DMA and MMIO setup (host-side)
----------------------------------------------
Description: VFIO/IOMMUFD/KVM infrastructure support to establish
             private MMIO and DMA/IOMMU mappings.

* [1]: PCI/TSM bind core infrastructure
* [1]: PCI/TSM guest request infrastructure
* [1]: Sample Platform TSM driver implementation
* [0]: VFIO core infrastructure
* [0]: IOMMUFD core infrastructure
* [0]: Arch KVM support

Arch Support: None

PHASE4: Device Attestation (guest-side)
---------------------------------------
Description: User ABI to retrieve Certificates, Measurements, and TDISP
             Interface reports for consumption by a verifier.

* [0]: Core ABI (netlink)
* [0]: Sample Platform TSM driver implementation
* [0]: Arch Platform TSM implementation

Arch Support: None

Subsystem Interfaces
====================

.. kernel-doc:: include/linux/pci-ide.h
   :internal:

.. kernel-doc:: drivers/pci/ide.c
   :export:

.. kernel-doc:: include/linux/pci-tsm.h
   :internal:

.. kernel-doc:: drivers/pci/tsm.c
   :export:
