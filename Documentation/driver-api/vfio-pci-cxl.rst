.. SPDX-License-Identifier: GPL-2.0

=======================================
VFIO PCI CXL Type-2 device passthrough
=======================================

Overview
--------

Type-2 CXL devices are PCIe accelerators (GPUs, compute ASICs, and similar)
with coherent device memory on CXL.mem. DPA is mapped into host physical
address space through HDM decoders that the kernel's CXL subsystem owns. A
guest cannot program that hardware directly.

This ``vfio-pci`` mode hands a VMM:

- A read/write VFIO device region (COMP_REGS) that emulates the HDM decoder
  register block with CXL register rules enforced in kernel code.
- A mmapable VFIO device region (DPA) backed by the kernel-chosen host physical
  range for device memory.
- DVSEC config-space emulation so the guest cannot change host-owned CXL.io /
  CXL.mem enable bits.

Build with ``CONFIG_VFIO_CXL_CORE=y``. At runtime you can turn it off with::

    modprobe vfio-pci disable_cxl=1

or, in a variant driver, set ``vdev->disable_cxl = true`` before registration.


Device detection
----------------

At ``vfio_pci_core_register_device()`` the driver checks for a Type-2 style
setup. All of the following must hold:

1. CXL Device DVSEC present (PCIe DVSEC Vendor ID ``0x1E98``, DVSEC ID
   ``0x0000``).
2. ``Mem_Capable`` (bit 2) set in the CXL Capability register inside that DVSEC.
3. PCI class code is **not** ``0x050210`` (CXL Type-3 memory expander).
4. An HDM Decoder capability block reachable through the Register Locator DVSEC.
5. At least one HDM decoder committed by firmware with non-zero size.

The CXL spec labels "Type-2" as devices with both ``Mem_Capable`` and
``Cache_Capable``. This driver also takes ``Mem_Capable``-only devices
(``Cache_Capable=0``), which behave like Type-3 style accelerators without the
usual class code. ``VFIO_CXL_CAP_CACHE_CAPABLE`` exposes the cache bit to
userspace so a VMM can treat FLR differently when needed.

When detection succeeds, ``VFIO_DEVICE_FLAGS_CXL`` is ORed into
``vfio_device_info.flags`` together with ``VFIO_DEVICE_FLAGS_PCI``.

.. note::

   **Firmware must commit an HDM decoder before open.** The driver only
   discovers DPA range and size from a decoder that firmware already committed.
   Devices without that, or hot-plugged setups that never get it, are out of
   scope for now.

   Follow-up options under discussion include CXL range registers in the
   Device DVSEC (often enough on single-decoder parts), CDAT over DOE, mailbox
   Get Partition Info, or a future DVSEC field from the consortium for
   base/size/NUMA without extra side channels. There is also talk of a sysfs
   path, modeled on resizable BAR, where an orchestrator fixes the DPA window
   before vfio-pci binds so the driver still sees a committed range.


UAPI: VFIO_DEVICE_INFO_CAP_CXL
------------------------------

When ``VFIO_DEVICE_FLAGS_CXL`` is set, the device info capability chain
includes a ``vfio_device_info_cap_cxl`` structure (cap ID 6, version 1)::

    struct vfio_device_info_cap_cxl {
        struct vfio_info_cap_header header; /* id=6, version=1 */
        __u8   hdm_regs_bar_index;  /* BAR index containing component regs */
        __u8   reserved[3];
        __u32  flags;               /* VFIO_CXL_CAP_* flags */
        __u64  hdm_regs_offset;     /* byte offset within the BAR to the
                                     * CXL.mem register area start.  This
                                     * equals comp_reg_offset + CXL_CM_OFFSET
                                     * where CXL_CM_OFFSET = 0x1000. */
        __u32  dpa_region_index;    /* VFIO region index for DPA memory */
        __u32  comp_regs_region_index; /* VFIO region index for COMP_REGS */
    };
    /*
     * hdm_count and hdm_decoder_offset are intentionally absent from this
     * struct. Both are derivable from the COMP_REGS region. See the
     * "Deriving HDM info from COMP_REGS" section below.
     */

    #define VFIO_CXL_CAP_FIRMWARE_COMMITTED  (1 << 0)
    #define VFIO_CXL_CAP_CACHE_CAPABLE       (1 << 1)

``VFIO_CXL_CAP_FIRMWARE_COMMITTED``
    At least one HDM decoder was pre-committed by firmware. The DPA region
    is live at device open; the VMM can map it without waiting for a guest
    COMMIT cycle.

``VFIO_CXL_CAP_CACHE_CAPABLE``
    The device has an HDM-DB decoder (CXL.mem + CXL.cache). This mirrors the
    ``Cache_Capable`` bit from the CXL DVSEC Capability register. The kernel
    does not run Write-Back Invalidation (WBI) before FLR; with this flag set
    that stays the VMM's job.

DPA region size comes from ``VFIO_DEVICE_GET_REGION_INFO`` on
``dpa_region_index``, not from this struct.


VFIO regions
------------

A CXL device adds two device regions on top of the usual BARs. Their indices
are in ``dpa_region_index`` and ``comp_regs_region_index``.

DPA region (``VFIO_REGION_SUBTYPE_CXL``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Flags: ``READ | WRITE | MMAP``.

The backing store is the host physical range the kernel assigned for DPA. The
kernel maps it with ``memremap(MEMREMAP_WB)`` because CXL device memory on a
coherent link sits in the CPU cache hierarchy. That mapping is normal cached
memory, so ``copy_to/from_user`` works without extra barriers.

Page faults are lazy: PFNs are installed per page on first touch via
``vmf_insert_pfn``. ``mmap()`` does not populate the whole region up front.

Region read/write through the fd uses the same ``MEMREMAP_WB`` mapping with
``copy_to/from_user``. ``ioread``/``iowrite`` MMIO helpers are not used on
this path.

During FLR, ``unmap_mapping_range()`` drops user PTEs and ``region_active``
clears before the reset runs. Ongoing faults or region I/O then error instead
of touching a dead mapping. IOMMU ATC invalidation from the zap has to finish
before the device resets; doing it the other way around can leave an SMMU
waiting on a device that no longer responds.

After reset, the region comes back once ``COMMITTED`` shows up again in fresh
HDM hardware state. The VMM can fault pages in again without a new ``mmap()``.

COMP_REGS region (``VFIO_REGION_SUBTYPE_CXL_COMP_REGS``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Flags: ``READ | WRITE`` (no mmap).

Emulated registers for the CXL.mem slice of the component register block: the
CXL Capability Array header at offset 0, then the HDM Decoder capability
starting at ``hdm_decoder_offset`` (the byte offset derived by traversing the
CXL Capability Array — see "Deriving HDM info from COMP_REGS" below).
Region size from ``VFIO_DEVICE_GET_REGION_INFO`` covers the full capability
array prefix plus all HDM decoder blocks.

Only 32-bit, 32-bit-aligned accesses are allowed. 8- and 16-bit attempts get
``-EINVAL``.

Offsets below ``hdm_decoder_offset`` return the snapshot from device open.
Writes there are dropped (with a WARN); the capability array stays read-only.

From ``hdm_decoder_offset`` upward the kernel keeps a shadow
(``comp_reg_virt[]``) and applies field rules:

- At open, hardware HDM state is snapshotted. For firmware-committed decoders
  the LOCK bit is cleared and BASE_HI/BASE_LO are zeroed in the shadow so the
  VMM can program guest GPA; the host HPA is not carried in the shadow after
  that.
- ``COMMIT`` (bit 9 of CTRL): writing 1 sets ``COMMITTED`` (bit 10) in the
  shadow immediately. Real hardware stays committed; the shadow tracks what
  the guest should see.
- When LOCK is set, writes to BASE_HI and SIZE_HI are ignored so
  firmware-committed values survive.

Region type identifiers::

    /* type = PCI_VENDOR_ID_CXL | VFIO_REGION_TYPE_PCI_VENDOR_TYPE */
    #define VFIO_REGION_SUBTYPE_CXL           1  /* DPA memory region */
    #define VFIO_REGION_SUBTYPE_CXL_COMP_REGS 2  /* HDM register shadow */


BAR access
----------

``VFIO_DEVICE_GET_REGION_INFO`` for ``hdm_regs_bar_index`` reports the full
BAR size with ``READ | WRITE | MMAP`` flags and a
``VFIO_REGION_INFO_CAP_SPARSE_MMAP`` capability listing the GPU or
accelerator register windows — the mmappable parts of the BAR that do **not**
contain CXL component registers.

The number of sparse areas depends on where the CXL component register block
``[comp_reg_offset, comp_reg_offset + comp_reg_size)`` sits within the BAR:

* **Topology A** - component block at BAR end:
  ``[gpu_regs | comp_regs]`` → 1 area: ``[0, comp_reg_offset)``

* **Topology B** - component block at BAR start:
  ``[comp_regs | gpu_regs]`` → 1 area: ``[comp_reg_size, bar_len)``

* **Topology C** - component block in middle:
  ``[gpu_regs | comp_regs | gpu_regs]`` → 2 areas:
  ``[0, comp_reg_offset)`` and ``[comp_reg_offset + comp_reg_size, bar_len)``

VMMs **must** iterate all ``nr_areas`` entries; do not assume a single area or
that the first area starts at offset zero.

The GPU/accelerator register windows listed in the sparse capability **are**
physically mmappable: ``mmap()`` on the VFIO device fd at the corresponding
BAR offset succeeds and yields a host-physical-backed mapping suitable for
KVM stage-2 installation.

The CXL component register block itself **is not** mmappable.  Any ``mmap()``
request whose range overlaps ``[comp_reg_offset, comp_reg_offset +
comp_reg_size)`` returns ``-EINVAL``; those registers must be accessed through
the ``COMP_REGS`` device region.


DVSEC configuration space emulation
-----------------------------------

With ``CONFIG_VFIO_CXL_CORE=y``, vfio-pci installs a handler for
``PCI_EXT_CAP_ID_DVSEC`` (``0x23``) in the config access table. Non-CXL
devices fall through as before.

On CXL devices, writes to these DVSEC registers are caught and reflected in
``vdev->vconfig`` (shadow config space):

+--------------------+--------+--------------------------------------------------+
| Register           | Offset | Emulation                                        |
+====================+========+==================================================+
| CXL Control        | +0x0c  | RWL; IO_Enable held at 1; locked when Lock       |
|                    |        | bit 0 is set.                                    |
+--------------------+--------+--------------------------------------------------+
| CXL Status         | +0x0e  | Bit 14 (Viral_Status) is RW1CS.                  |
+--------------------+--------+--------------------------------------------------+
| CXL Control2       | +0x10  | Bits 1 and 2 forwarded to hardware.              |
+--------------------+--------+--------------------------------------------------+
| CXL Status2        | +0x12  | Bit 3 forwarded when Capability3 bit 3 is set.   |
+--------------------+--------+--------------------------------------------------+
| CXL Lock           | +0x14  | RWO; once set, Control becomes read-only until   |
|                    |        | conventional reset.                              |
+--------------------+--------+--------------------------------------------------+
| Range Base Hi/Lo   | varies | Stored in vconfig; Base Low [27:0] reserved bits |
|                    |        | cleared on write.                                |
+--------------------+--------+--------------------------------------------------+

Reads return the shadow. Read-only registers (Capability, Size High/Low) are
filled from hardware at open.


FLR and reset
-------------

FLR goes through ``vfio_pci_ioctl_reset()``. The CXL-specific part is:

1. ``vfio_cxl_prepare_reset()`` runs under the write side of
   ``memory_lock``. It clears ``region_active`` and calls
   ``unmap_mapping_range()`` on the DPA inode mapping so user PTEs go away.
   Concurrent faults or fd I/O hit the inactive flag and error. IOMMU ATC must
   drain before reset (see the DPA region notes above).

2. After FLR, ``vfio_cxl_finish_reset()`` reads HDM hardware again into
   ``comp_reg_virt[]``. If ``COMMITTED`` is set (common when firmware left the
   decoder committed), ``region_active`` turns back on and the VMM can refault
   without remapping.


Known limitations
-----------------

**Pre-committed HDM decoder required**
    See `Device detection`_ and the note there.

**CXL hot-plug not supported**
    Slots need to be present and programmed by firmware at boot.

**CXL.cache Write-Back Invalidation not implemented**
    For HDM-DB devices (``VFIO_CXL_CAP_CACHE_CAPABLE``), the kernel does not
    run WBI before FLR. The VMM must do it and expose Back-Invalidation in the
    guest topology where required.


VMM integration notes
---------------------

For a ``VFIO_CXL_CAP_FIRMWARE_COMMITTED`` device (what works today)::

    /* 1. Get device info and locate the CXL cap */
    vfio_device_get_info(fd, &dinfo);
    assert(dinfo.flags & VFIO_DEVICE_FLAGS_CXL);
    cxl = find_cap(&dinfo, VFIO_DEVICE_INFO_CAP_CXL);

    /* 2. Get DPA and COMP_REGS region sizes */
    get_region_info(fd, cxl->dpa_region_index, &dpa_ri);
    get_region_info(fd, cxl->comp_regs_region_index, &comp_ri);

    /* 3. Map DPA region at a guest physical address */
    gpa_base = allocate_guest_phys(dpa_ri.size);
    mmap(gpa_base, dpa_ri.size, PROT_READ|PROT_WRITE,
         MAP_SHARED|MAP_FIXED, vfio_fd,
         (off_t)cxl->dpa_region_index << VFIO_PCI_OFFSET_SHIFT);

    /* 4. Derive hdm_decoder_offset from COMP_REGS (see section below) */
    uint64_t hdm_decoder_offset = derive_hdm_offset(vfio_fd, comp_ri);

    /* 5. Write guest GPA into HDM Decoder 0 BASE via COMP_REGS pwrite */
    u32 base_hi = gpa_base >> 32;
    comp_off = (off_t)cxl->comp_regs_region_index << VFIO_PCI_OFFSET_SHIFT;
    pwrite(vfio_fd, &base_hi, 4,
           comp_off + hdm_decoder_offset + CXL_HDM_DECODER0_BASE_HIGH_OFFSET);

    /* 6. Build guest CXL topology using gpa_base and dpa_ri.size */
    build_cfmws(gpa_base, dpa_ri.size);

    /* 7. If CACHE_CAPABLE: issue WBI before any guest FLR */

Extra detail:

- DPA size is ``dpa_ri.size`` from region info.
- ``CXL_HDM_DECODER0_BASE_HIGH_OFFSET`` lives in ``include/uapi/cxl/cxl_regs.h``.
- On the BAR, ``mmaps[0].size`` from the sparse-mmap cap on
  ``hdm_regs_bar_index`` splits GPU MMIO (BAR fd) from the CXL block (COMP_REGS
  region).
- If ``VFIO_CXL_CAP_CACHE_CAPABLE`` is set, the guest CXL topology should
  advertise Back-Invalidation and the VMM should run WBI before FLR.


Deriving HDM info from COMP_REGS
---------------------------------

``hdm_decoder_offset`` and ``hdm_count`` are not in ``vfio_device_info_cap_cxl``
because both are directly readable from the ``COMP_REGS`` region.

**Finding hdm_decoder_offset:**

Read dwords from the COMP_REGS region starting at offset 0 (the CXL Capability
Array).  ``comp_off`` is the VFIO file offset for the COMP_REGS region:
``(off_t)cxl->comp_regs_region_index << VFIO_PCI_OFFSET_SHIFT``::

    /* Dword 0: CXL Capability Array Header */
    pread(fd, &hdr, 4, comp_off + 0);
    /* bits[15:0] must be 1 (CM_CAP_HDR_CAP_ID) */
    /* bits[31:24] = number of capability entries */
    num_caps = (hdr >> 24) & 0xff;  /* CXL_CM_CAP_HDR_ARRAY_SIZE_MASK */

    /* Walk entries at dword 1..num_caps */
    for (i = 1; i <= num_caps; i++) {
        pread(fd, &entry, 4, comp_off + i * 4);
        cap_id = entry & 0xffff;           /* CXL_CM_CAP_HDR_ID_MASK */
        if (cap_id == 0x5) {               /* CXL_CM_CAP_CAP_ID_HDM */
            hdm_decoder_offset = (entry >> 20) & 0xfff; /* CXL_CM_CAP_PTR_MASK */
            break;
        }
    }

**Finding hdm_count:**

Read the HDM Decoder Capability register (HDMC) at ``hdm_decoder_offset + 0``::

    pread(fd, &hdmc, 4, comp_off + hdm_decoder_offset);
    field = hdmc & 0xf;  /* CXL_HDM_DECODER_COUNT_MASK bits[3:0] */
    hdm_count = field ? field * 2 : 1;  /* 0→1, N→N*2 decoders */

All constants are in ``include/uapi/cxl/cxl_regs.h``.


Kernel configuration
--------------------

``CONFIG_VFIO_CXL_CORE`` (bool)
    CXL Type-2 passthrough in ``vfio-pci-core``. Needs ``CONFIG_VFIO_PCI_CORE``,
    ``CONFIG_CXL_BUS``, and ``CONFIG_CXL_MEM``.

References
----------

* CXL Specification 4.0, 8.1.3 - PCIe DVSEC for CXL Devices
* CXL Specification 4.0, 8.2.4.20 - CXL HDM Decoder Capability Structure
* ``include/uapi/linux/vfio.h`` - ``VFIO_DEVICE_INFO_CAP_CXL``,
  ``VFIO_REGION_SUBTYPE_CXL``, ``VFIO_REGION_SUBTYPE_CXL_COMP_REGS``
* ``include/uapi/cxl/cxl_regs.h`` - ``CXL_CM_OFFSET``,
  ``CXL_CM_CAP_HDR_ARRAY_SIZE_MASK``, ``CXL_CM_CAP_HDR_ID_MASK``,
  ``CXL_CM_CAP_PTR_MASK``, ``CXL_HDM_DECODER_COUNT_MASK``,
  ``CXL_HDM_DECODER0_BASE_HIGH_OFFSET``
