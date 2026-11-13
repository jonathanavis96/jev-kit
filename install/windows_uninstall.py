#!/usr/bin/env python3
"""airlock: reverse a native-Windows install.

    py -3 install\\windows_uninstall.py --check-only
    py -3 install\\windows_uninstall.py
    py -3 install\\windows_uninstall.py --purge

Reverses exactly what install/windows_install.py did, in the opposite order:

  1. remove airlock's PreToolUse entry AND its SessionStart session-check
     entry from every settings.json they are in,
     BACKING EACH FILE UP to a timestamped sibling first. Only airlock's own
     entry is removed -- every other hook, key and value is left alone, and
     an empty `hooks` block left behind by the removal is cleaned up
  2. delete the Task Scheduler health-check task, if one was registered
  3. remove both launchers, the `current` junction and `current.txt`
  4. remove the release directories

CONFIG AND STATE SURVIVE BY DEFAULT, and that is deliberate: %APPDATA%\\airlock
holds the mode file, any per-rule overrides and -- most importantly -- the key
file, and %LOCALAPPDATA%\\airlock\\state holds the shadow log, which is the
record of what the guard would have done and the only reason to have run it
in shadow at all. `--purge` removes those too, and says what it removed. The
kit-level key file (%APPDATA%\\jev-kit\\env, the default) is shared by every
jev-kit component and is kept even by --purge, which says so. The key file is
never opened, never read and never printed by any path here.
"""
import argparse
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import windows_common as wc

sys.path.insert(0, wc.REPO_ROOT)
from airlock import paths


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="windows_uninstall.py",
        description="Reverse a native-Windows airlock install.")
    ap.add_argument("--check-only", action="store_true",
                    help="print what would be removed and remove nothing")
    ap.add_argument("--purge", action="store_true",
                    help="also delete config (including the key file) and state")
    ap.add_argument("--settings", action="append", default=[],
                    help="an extra settings.json to clean; repeatable")
    return ap.parse_args(argv)


def _is_airlock_hook(command, launcher):
    """Is this hook command airlock's?

    Matched on the launcher path when we know it, and otherwise on every file
    name airlock has ever used as an entry point plus its two launcher names
    -- the PreToolUse guard and the SessionStart session check.

    Deliberately narrow: removing a hook that is not ours would be the single
    worst thing an uninstaller could do, so this is a fixed list of names we
    wrote ourselves, never a substring like "airlock" that somebody else's
    hook could happen to contain.
    """
    if not isinstance(command, str):
        return False
    if launcher and launcher.lower() in command.lower():
        return True
    lowered = command.lower().replace("/", "\\")
    return any(token in lowered for token in (
        wc.LAUNCHER_NAME.lower(),
        wc.SESSION_LAUNCHER_NAME.lower(),
        "hooks\\airlock.py",
        "hooks\\airlock_session_check.py",
        "hooks\\plumbline.py",
        "hooks\\jev_guard.py",
    ))


def strip_hook(data, launcher):
    """Remove airlock's hook entries from a parsed settings.json, in place.
    Returns the list of command strings removed."""
    removed = []
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return removed
    for event, entries in list(hooks.items()):
        if not isinstance(entries, list):
            continue
        kept_entries = []
        for entry in entries:
            if not isinstance(entry, dict):
                kept_entries.append(entry)
                continue
            inner = entry.get("hooks")
            if not isinstance(inner, list):
                kept_entries.append(entry)
                continue
            kept_inner = []
            for h in inner:
                if isinstance(h, dict) and _is_airlock_hook(h.get("command"), launcher):
                    removed.append(h.get("command"))
                    continue
                kept_inner.append(h)
            if kept_inner:
                entry["hooks"] = kept_inner
                kept_entries.append(entry)
            elif len(entry) > 2:
                # The entry carried more than matcher+hooks; keep it, emptied,
                # rather than discarding fields somebody put there.
                entry["hooks"] = []
                kept_entries.append(entry)
        if kept_entries:
            hooks[event] = kept_entries
        else:
            del hooks[event]
    if not hooks:
        data.pop("hooks", None)
    return removed


def clean_settings(path, launcher, apply=True):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        return "not valid JSON (%s), refusing to touch it" % str(exc)[:120]
    removed = strip_hook(data, launcher)
    if not removed:
        return "no airlock hook present"
    if not apply:
        return "would remove %d hook entry(ies): %s" % (len(removed), ", ".join(
            str(c)[:80] for c in removed))
    saved = wc.backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=2) + "\n")
    return "removed %d hook entry(ies); backed up to %s" % (len(removed), saved)


def main(argv=None):
    args = parse_args(argv)
    if not wc.require_windows("install/windows_uninstall.py"):
        return 2
    apply = not args.check_only
    root = wc.install_root()
    launcher = wc.launcher_path()
    actions = []

    for path in (args.settings or wc.default_settings_files()):
        result = clean_settings(path, launcher, apply=apply)
        actions.append("settings %s: %s" % (path, result or "does not exist"))

    if wc.health_task_exists():
        if apply:
            ok, out = wc.delete_health_task()
            actions.append("Task Scheduler '%s': %s%s"
                           % (wc.TASK_NAME, "deleted" if ok else "FAILED",
                              "" if ok else " (%s)" % out))
        else:
            actions.append("Task Scheduler '%s': would delete" % wc.TASK_NAME)
    else:
        actions.append("Task Scheduler '%s': not registered" % wc.TASK_NAME)

    junction = wc.current_path()
    if os.path.isdir(junction):
        if apply:
            # rmdir removes the junction itself and never follows it into the
            # release directory, which is the whole reason not to use
            # shutil.rmtree here.
            code, out = wc.run(["cmd", "/c", "rmdir", junction])
            actions.append("current junction: %s"
                           % ("removed" if code == 0 else "FAILED (%s)" % out))
        else:
            actions.append("current junction: would remove %s" % junction)

    for path in (wc.pointer_path(), launcher, wc.session_launcher_path()):
        if os.path.isfile(path):
            if apply:
                os.remove(path)
                actions.append("removed %s" % path)
            else:
                actions.append("would remove %s" % path)

    releases = os.path.join(root, wc.RELEASES_NAME)
    if os.path.isdir(releases):
        if apply:
            shutil.rmtree(releases, ignore_errors=True)
            actions.append("removed release directory %s" % releases)
        else:
            actions.append("would remove release directory %s" % releases)

    config = str(paths.config_dir())
    state = str(paths.state_dir())
    if args.purge:
        for path, what in ((state, "state (the shadow log)"),
                           (config, "config (mode, rule overrides, and any key file kept there)")):
            if os.path.isdir(path):
                if apply:
                    shutil.rmtree(path, ignore_errors=True)
                    actions.append("purged %s: %s" % (what, path))
                else:
                    actions.append("would purge %s: %s" % (what, path))
        # The kit-level key file (the default one) is shared by every jev-kit
        # component, so uninstalling the guard leaves it. Say so: the purge
        # line used to claim it had gone.
        kit_key = os.path.join(str(paths.kit_config_dir()), "env")
        if os.path.isfile(kit_key):
            actions.append("kept the kit key file %s: every jev-kit component reads "
                           "it. Delete it by hand if nothing else uses it." % kit_key)
    else:
        actions.append("kept config %s (mode, rule overrides, key file)" % config)
        actions.append("kept state %s (the shadow log). Pass --purge to remove both."
                       % state)

    if apply and os.path.isdir(root) and not os.listdir(root):
        os.rmdir(root)
        actions.append("removed the now-empty %s" % root)

    print("airlock: native Windows uninstall%s" % (" (--check-only)" if not apply else ""))
    for a in actions:
        print("  %s" % a)
    if not apply:
        print("\n--check-only: nothing was changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
