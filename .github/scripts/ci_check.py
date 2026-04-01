import json
import os
import sys
import glob

# Get script location to find the config file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(BASE_DIR, "ci.config.json")

# 1. Load and Verify Config
if not os.path.isfile(CONFIG):
    print(f"❌ Error: {CONFIG} not found")
    sys.exit(404)

try:
    with open(CONFIG, 'r') as f:
        data = json.load(f)
except json.JSONDecodeError:
    print(f"❌ Error: Invalid JSON in {CONFIG}")
    sys.exit(500)

# Helper to get nested JSON values
def get_val(path):
    keys = path.split('.')
    val = data
    try:
        for k in keys:
            val = val[k]
        return val
    except: return None

# 2. Extract Features
standalone = get_val('emscripten.standaloneWasm')
forbid_exit = get_val('emscripten.forbidExitRuntime')

# 3. Print "Enabled Features" Report
print("\n" + "="*30)
print("  ENABLED CI FEATURES")
print("="*30)
print(f"• Standalone WASM:    {'✅ ENABLED' if standalone else '❌ DISABLED'}")
print(f"• Forbid Exit Runtime: {'✅ ENABLED' if forbid_exit else '❌ DISABLED'}")
print("="*30 + "\n")

# 4. Enforce Rules
if standalone and forbid_exit:
    found_illegal = False
    # Scan entire repo for forbidden flags in .sh files
    for sh_file in glob.iglob(os.path.join(os.getcwd(), '**/*.sh'), recursive=True):
        with open(sh_file, 'r', errors='ignore') as f:
            content = f.read()
            if "EXIT_RUNTIME" in content or "--exit-runtime" in content:
                print(f"❌ VIOLATION: Forbidden flag found in {sh_file}")
                found_illegal = True
    
    if found_illegal:
        sys.exit(451)

print("✔ All checks passed.")
