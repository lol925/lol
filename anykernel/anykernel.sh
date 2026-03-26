# AnyKernel3 AK3-Helper Script
# Osm0sis @ xda-developers
#
# Configured for: OnePlus Nord N200 5G (DE2117 / DE2118)
# Platform: Qualcomm SM4350 (Snapdragon 480) — holi
# A/B partition device — flashes to active slot automatically

## AnyKernel setup
# begin properties
properties() { '
kernel.string=NordN200 KernelSU Kernel
do.devicecheck=1
do.modules=0
do.systemless=1
do.cleanup=1
do.cleanuponabort=0
device.name1=DE2117
device.name2=DE2118
device.name3=OnePlus Nord N200 5G
device.name4=dre
supported.versions=11-14
supported.patchlevels=
'; }
# end properties

# AnyKernel install
## boot shell variables
block=/dev/block/bootdevice/by-name/boot;
is_slot_device=1;
ramdisk_compression=auto;
patch_vbmeta_flag=auto;

# import functions/variables and setup patching
. tools/ak3-core.sh;

# boot install
dump_boot;

# If a dtbo.img was included in the zip, flash it too
if [ -f "$ZIPFILE" ]; then
  if zipinfo -1 "$ZIPFILE" | grep -q "dtbo.img"; then
    flash_dtbo;
  fi
fi

write_boot;
## end boot install
