#!/usr/bin/env python3
"""
KernelSU Hook Applicator for non-GKI Linux 5.4 kernels
=======================================================
Patches the four standard kernel source files required for KernelSU
integration. Designed for the LineageOS android_kernel_oneplus_sm4350
(lineage-23.2) but works on most 5.4 AOSP/LineageOS kernels.

Why these four files?
  - fs/exec.c       → The #1 most critical hook. Without this, ksud is
                       never spawned and KernelSU is completely dead.
  - fs/open.c       → faccessat hook for the su binary access check.
  - fs/read_write.c → vfs_read hook for KernelSU's allow-list logic.
  - drivers/input/input.c → Volume-key combo for root toggle.

Usage:
  python3 apply_ksu_hooks.py [kernel_root]          # Apply hooks
  python3 apply_ksu_hooks.py [kernel_root] --verify  # Just verify
"""

import os
import sys
import argparse


# ─── Low-level helpers ────────────────────────────────────────────────────────

def read_file(path: str) -> str:
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def write_file(path: str, content: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


def already_patched(content: str, marker: str) -> bool:
    return marker in content


def insert_before_first(content: str, anchors: list, text: str):
    """
    Insert `text` before the first occurrence of any anchor in `anchors`.
    Returns (new_content, matched_anchor) or (None, None) on failure.
    """
    for anchor in anchors:
        idx = content.find(anchor)
        if idx != -1:
            return content[:idx] + text + content[idx:], anchor
    return None, None


def insert_before_in_func(content: str, func_sigs: list, anchors: list,
                           text: str, window: int = 10000):
    """
    Find the function (by any of func_sigs), then insert `text` before the
    first matching anchor within the function body (up to `window` bytes in).
    Returns (new_content, error_msg). error_msg is None on success.
    """
    for sig in func_sigs:
        func_pos = content.find(sig)
        if func_pos == -1:
            continue

        # Find the opening brace of the function body
        brace_pos = content.find('{', func_pos)
        if brace_pos == -1:
            return None, f"opening brace not found after '{sig[:40]}'"

        # Search for anchor within the function body window
        body_start = brace_pos + 1
        body_window = content[body_start: body_start + window]

        for anchor in anchors:
            a_pos = body_window.find(anchor)
            if a_pos != -1:
                abs_pos = body_start + a_pos
                return content[:abs_pos] + text + content[abs_pos:], None

        # Function found but none of the anchors matched
        return None, (
            f"function found but no anchor matched inside body.\n"
            f"  Tried anchors: {[a[:50] + '...' if len(a) > 50 else a for a in anchors]}"
        )

    return None, f"function signature not found. Tried: {[s[:60] for s in func_sigs]}"


def insert_after_in_func(content: str, func_sigs: list, anchors: list,
                          text: str, window: int = 10000):
    """
    Like insert_before_in_func but inserts AFTER the anchor.
    """
    for sig in func_sigs:
        func_pos = content.find(sig)
        if func_pos == -1:
            continue

        brace_pos = content.find('{', func_pos)
        if brace_pos == -1:
            return None, f"opening brace not found after '{sig[:40]}'"

        body_start = brace_pos + 1
        body_window = content[body_start: body_start + window]

        for anchor in anchors:
            a_pos = body_window.find(anchor)
            if a_pos != -1:
                abs_pos = body_start + a_pos + len(anchor)
                return content[:abs_pos] + text + content[abs_pos:], None

        return None, (
            f"function found but no anchor matched inside body.\n"
            f"  Tried anchors: {[a[:50] + '...' if len(a) > 50 else a for a in anchors]}"
        )

    return None, f"function signature not found."


# ─── Individual hook functions ────────────────────────────────────────────────

def hook_exec(kernel_root: str):
    """
    fs/exec.c — hook into do_execveat_common()

    This is THE most critical hook. KernelSU's ksud process is only ever
    spawned through the execve path. If this hook isn't applied, ksud will
    never be created, which explains why Magisk showed it missing.

    The hook is placed as the very first statement in do_execveat_common,
    before the IS_ERR(filename) check.
    """
    path = os.path.join(kernel_root, 'fs', 'exec.c')
    if not os.path.isfile(path):
        return False, "file not found"

    content = read_file(path)

    if already_patched(content, 'ksu_handle_execveat'):
        return True, "already patched"

    # ── Step 1: Insert extern declaration before the function ─────────────────
    declaration = (
        '#ifdef CONFIG_KSU\n'
        'extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n'
        '\t\t\tvoid *argv, void *envp, int *flags);\n'
        '#endif\n'
    )

    content, matched = insert_before_first(
        content,
        ['static int do_execveat_common(int fd, struct filename *filename,'],
        declaration
    )
    if content is None:
        return False, "declaration: function signature not found in fs/exec.c"

    # ── Step 2: Insert the call as first statement inside the function ────────
    call = (
        '#ifdef CONFIG_KSU\n'
        '\tksu_handle_execveat(&fd, &filename, argv, envp, &flags);\n'
        '#endif\n'
    )

    content, err = insert_before_in_func(
        content,
        ['static int do_execveat_common(int fd, struct filename *filename,'],
        [
            # Primary anchor — standard Linux 5.4
            '\tif (IS_ERR(filename))\n\t\treturn PTR_ERR(filename);',
            '\tif (IS_ERR(filename))',
            # Fallback — some Qualcomm BSP variants
            '\tretval = bprm_mm_init(bprm);',
            '\tchar *pathbuf = NULL;\n',
        ],
        call
    )
    if err:
        return False, f"call insertion: {err}"

    write_file(path, content)
    return True, "patched"


def hook_open(kernel_root: str):
    """
    fs/open.c — hook into do_faccessat()

    Used for the 'su' binary access check and root grant mechanism.
    Hook is placed before the first real executable statement.
    """
    path = os.path.join(kernel_root, 'fs', 'open.c')
    if not os.path.isfile(path):
        return False, "file not found"

    content = read_file(path)

    if already_patched(content, 'ksu_handle_faccessat'):
        return True, "already patched"

    declaration = (
        '#ifdef CONFIG_KSU\n'
        'extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n'
        '\t\t\tint *mode, int *flags);\n'
        '#endif\n'
    )

    call = (
        '#ifdef CONFIG_KSU\n'
        '\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n'
        '#endif\n'
    )

    content, matched = insert_before_first(
        content,
        [
            'long do_faccessat(int dfd, const char __user *filename, int mode)',
            # Some kernels expose it as a syscall wrapper only
            'SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)',
        ],
        declaration
    )
    if content is None:
        return False, "declaration: do_faccessat not found in fs/open.c"

    content, err = insert_before_in_func(
        content,
        [
            'long do_faccessat(int dfd, const char __user *filename, int mode)',
            'SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)',
        ],
        [
            '\tif (mode & ~S_IRWXO)',
            '\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n',
            '\tconst struct cred *old_cred;\n',
        ],
        call
    )
    if err:
        return False, f"call insertion: {err}"

    write_file(path, content)
    return True, "patched"


def hook_read_write(kernel_root: str):
    """
    fs/read_write.c — hook into vfs_read()

    Required for KernelSU's allow-list mechanism to intercept reads.
    Without this, root allow/deny decisions may not work correctly.
    """
    path = os.path.join(kernel_root, 'fs', 'read_write.c')
    if not os.path.isfile(path):
        return False, "file not found"

    content = read_file(path)

    if already_patched(content, 'ksu_handle_vfs_read'):
        return True, "already patched"

    declaration = (
        '#ifdef CONFIG_KSU\n'
        'extern int ksu_handle_vfs_read(struct file **file_ptr,\n'
        '\t\t\tchar __user **buf_ptr, size_t *count_ptr, loff_t **pos);\n'
        '#endif\n'
    )

    call = (
        '#ifdef CONFIG_KSU\n'
        '\tksu_handle_vfs_read(&file, &buf, &count, &pos);\n'
        '#endif\n'
    )

    content, matched = insert_before_first(
        content,
        ['ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)'],
        declaration
    )
    if content is None:
        return False, "declaration: vfs_read not found in fs/read_write.c"

    content, err = insert_before_in_func(
        content,
        ['ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)'],
        [
            '\tif (!(file->f_mode & FMODE_READ))',
            '\tssize_t ret;\n\n\tif (',
            '\tssize_t ret;\n',
        ],
        call
    )
    if err:
        return False, f"call insertion: {err}"

    write_file(path, content)
    return True, "patched"


def hook_input(kernel_root: str):
    """
    drivers/input/input.c — hook into input_handle_event()

    Used for the volume-key combo to toggle KernelSU root access.
    This is the least critical of the four hooks — the other three
    are required for core functionality.

    The hook is placed AFTER input_get_disposition() is called, so
    the disposition value is available.
    """
    path = os.path.join(kernel_root, 'drivers', 'input', 'input.c')
    if not os.path.isfile(path):
        return False, "file not found"

    content = read_file(path)

    if already_patched(content, 'ksu_handle_input_handle_event'):
        return True, "already patched"

    declaration = (
        '#ifdef CONFIG_KSU\n'
        'extern int ksu_handle_input_handle_event(unsigned int *type,\n'
        '\t\t\tunsigned int *code, int *value);\n'
        '#endif\n'
    )

    call = (
        '#ifdef CONFIG_KSU\n'
        '\tksu_handle_input_handle_event(&type, &code, &value);\n'
        '#endif\n'
    )

    # The function signature may span two lines — try both
    content, matched = insert_before_first(
        content,
        [
            'static void input_handle_event(struct input_dev *dev,\n\t\t\t       unsigned int type, unsigned int code, int value)',
            'static void input_handle_event(struct input_dev *dev,',
        ],
        declaration
    )
    if content is None:
        return False, "declaration: input_handle_event not found"

    # Insert AFTER the disposition line, not before it
    content, err = insert_after_in_func(
        content,
        [
            'static void input_handle_event(struct input_dev *dev,\n\t\t\t       unsigned int type, unsigned int code, int value)',
            'static void input_handle_event(struct input_dev *dev,',
        ],
        [
            '\tint disposition = input_get_disposition(dev, type, code, &value);\n',
            '\tint disposition = input_get_disposition(',
        ],
        call
    )
    if err:
        return False, f"call insertion: {err}"

    write_file(path, content)
    return True, "patched"


# ─── Hook registry ────────────────────────────────────────────────────────────

HOOKS = [
    ('fs/exec.c            (do_execveat_common)  [CRITICAL]', hook_exec,       'ksu_handle_execveat'),
    ('fs/open.c            (do_faccessat)',                   hook_open,       'ksu_handle_faccessat'),
    ('fs/read_write.c      (vfs_read)',                       hook_read_write, 'ksu_handle_vfs_read'),
    ('drivers/input/input.c(input_handle_event)',             hook_input,      'ksu_handle_input_handle_event'),
]


# ─── Main logic ───────────────────────────────────────────────────────────────

def apply_hooks(kernel_root: str) -> bool:
    print(f"Applying KernelSU hooks to: {kernel_root}\n")
    all_ok = True
    for label, fn, _ in HOOKS:
        ok, msg = fn(kernel_root)
        icon = '✓' if ok else '✗'
        print(f"  {icon}  {label}")
        if not ok:
            print(f"       ERROR: {msg}")
            all_ok = False
        else:
            print(f"       {msg}")
    print()
    return all_ok


def verify_hooks(kernel_root: str) -> bool:
    print(f"Verifying KernelSU hooks in: {kernel_root}\n")
    all_ok = True
    for label, fn, marker in HOOKS:
        # Determine the file path from the function's first path usage
        # We re-use the function just for its side-effect-free path logic,
        # but it's simpler to just check the marker directly.
        file_map = {
            hook_exec:       'fs/exec.c',
            hook_open:       'fs/open.c',
            hook_read_write: 'fs/read_write.c',
            hook_input:      'drivers/input/input.c',
        }
        filepath = os.path.join(kernel_root, file_map[fn])
        if os.path.isfile(filepath):
            found = marker in read_file(filepath)
            icon = '✓' if found else '✗'
            print(f"  {icon}  {label}")
            if not found:
                all_ok = False
        else:
            print(f"  ?  {label}  [file not found: {filepath}]")
            all_ok = False
    print()
    return all_ok


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Apply or verify KernelSU hooks in a Linux 5.4 kernel source tree'
    )
    parser.add_argument(
        'kernel_root', nargs='?', default='.',
        help='Path to kernel source root (default: current directory)'
    )
    parser.add_argument(
        '--verify', action='store_true',
        help='Verify hooks are applied without modifying any files'
    )
    args = parser.parse_args()

    kernel_root = os.path.abspath(args.kernel_root)

    # Basic sanity checks
    if not os.path.isdir(kernel_root):
        print(f"ERROR: '{kernel_root}' is not a directory")
        sys.exit(1)

    if not os.path.isfile(os.path.join(kernel_root, 'Makefile')):
        print(f"ERROR: '{kernel_root}' does not look like a kernel root (no Makefile)")
        sys.exit(1)

    if args.verify:
        ok = verify_hooks(kernel_root)
        if ok:
            print("All hooks are present.")
        else:
            print("One or more hooks are MISSING. Run without --verify to apply them.")
        sys.exit(0 if ok else 1)
    else:
        ok = apply_hooks(kernel_root)
        if ok:
            print("All hooks applied successfully.")
        else:
            print("One or more hooks FAILED. See errors above.")
            print("This usually means the kernel source structure is unexpected.")
            print("Open an issue with the error message and we can add a fallback anchor.")
        sys.exit(0 if ok else 1)
