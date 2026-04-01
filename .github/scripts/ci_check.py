import json
import os
import sys
import glob

CONFIG = "ci.config.json"

# --- 1. File Checks ---
if not os.path.isfile(CONFIG):
    print(f"❌ Error 404: {CONFIG} not found")
    sys.exit(404)

if os.path.getsize(CONFIG) == 0:
    print(f"❌ Error 400: {CONFIG} is empty")
    sys.exit(400)

# --- 2. Load JSON ---
try:
    with open(CONFIG, 'r') as f:
        data = json.load(f)
except json.JSONDecodeError:
    print(f"❌ JSON parse error: {CONFIG} is invalid")
    sys.exit(500)

def get_json(path):
    keys = path.split('.')
    val = data
    try:
        for k in keys:
            val = val[k]
        return val
    except (KeyError, TypeError):
        print(f"❌ Missing JSON key: {path}")
        sys.exit(422)

# --- 3. Logic & Rules ---
standalone = get_json('emscripten.standaloneWasm')
forbid_exit = get_json('emscripten.forbidExitRuntime')

print(f"• standaloneWasm = {standalone}")
print(f"• forbidExitRuntime = {forbid_exit}")

if standalone is True and forbid_exit is True:
    forbidden_found = False
    # Search all .sh files for the bad flags
    for filename in glob.iglob('./**/*.sh', recursive=True):
        with open(filename, 'r', errors='ignore') as f:
            content = f.read()
            if "EXIT_RUNTIME" in content or "--exit-runtime" in content:
                print(f"❌ Forbidden flag detected in: {filename}")
                forbidden_found = True
    
    if forbidden_found:
        sys.exit(451)

print("✔ Config validation complete")
