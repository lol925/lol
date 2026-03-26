# NordN200 KernelSU Build

GitHub Actions build for the OnePlus Nord N200 5G (DE2117) with KernelSU integration.

- **Kernel source:** LineageOS `android_kernel_oneplus_sm4350` (lineage-23.2)
- **Kernel version:** 5.4.x QGKI v1
- **Platform:** Qualcomm SM4350 (holi)

## Repo structure

```
.github/workflows/build.yml    — The build workflow
scripts/apply_ksu_hooks.py     — Patches fs/exec.c, fs/open.c, fs/read_write.c, drivers/input/input.c
anykernel/anykernel.sh         — AnyKernel3 config for the Nord N200
```

## How to build

1. Fork or create a repo with these files
2. Go to **Actions → Build Kernel with KernelSU**
3. Click **Run workflow**
4. Choose your KernelSU variant:
   - `sukisu-ultra` — recommended for first try
   - `kernelsu-next` — see note below about manager APK
5. Wait ~60 min on first build (much faster after ccache warms up)
6. Download the flashable zip from the workflow Artifacts

## Flashing

Flash in TWRP or any recovery that supports AnyKernel3 zips.  
The zip is an **A/B device** zip — it flashes to your active slot automatically.

> ⚠️ Always make a backup of your current boot partition before flashing.

## KernelSU Next — signature note

KernelSU Next embeds a public key in the kernel at build time and verifies
the manager APK's signature against it. You **must** use the official manager
APK from the same branch/commit as the kernel. The "KernelSU Next v2 signature
not found" error means the manager APK and kernel were built from different
commits or sources.

Download the matching manager from:
https://github.com/KernelSU-Next/KernelSU-Next/releases

## Why LTO is kept enabled

The `holi-qgki_defconfig` requires `CONFIG_LTO_CLANG=y`. Disabling it causes
missing hardware features (WiFi, Bluetooth, camera) because some Qualcomm BSP
drivers depend on LTO-specific symbol visibility. The KernelSU hooks are placed
in live, frequently-called code paths and will not be eliminated by LTO.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| KSU symbols missing from System.map | Hooks not applied / CONFIG_KSU not set |
| ksud not created (check with Magisk) | exec.c hook missing or wrong |
| Giant version number (283974...) | KernelSU git history missing — setup.sh handles this |
| "Signature not found" (KSU Next) | Manager APK doesn't match kernel build |
| EDL / kernel panic on manager open | Stale stubs or bad hook placement |

Build log is always uploaded as an artifact — check it first if anything fails.
