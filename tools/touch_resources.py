Import("env")
import os
import glob

# .incbin is an assembler directive: SCons' dependency scanner only follows
# #include/#import lines, so the HTML (and any image) embedded by resources.h is
# invisible to the build graph. Editing res/dashboard.html alone would
# leave main.o stale and the firmware serving the old bytes.
#
# assets.h is #included by main.cpp, so touching it marks that object dirty:
# the recompile re-runs the assembler, which re-reads every .incbin path.
# Everything under res/ is watched, so images added later are covered
# without touching this script.

ROOT = str(env.get("PROJECT_DIR", "."))
HEADER = os.path.join(ROOT, "src", "resources.h")
ASSETS = sorted(
    p for p in glob.glob(os.path.join(ROOT, "res", "*")) if os.path.isfile(p)
)

if ASSETS and os.path.exists(HEADER):
    newest = max(os.path.getmtime(p) for p in ASSETS)
    if newest > os.path.getmtime(HEADER):
        os.utime(HEADER, None)
        print("[assets] %s touched -> main.cpp will be recompiled" % HEADER)
