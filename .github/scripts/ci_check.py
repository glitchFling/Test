import json
import os
import sys
import glob

def run_ci():
    # 1. FIND THE CONFIG (Search entire repo)
    config_matches = glob.glob('**/ci.config.json', recursive=True)
    if not config_matches:
        print("❌ Error: ci.config.json not found anywhere!")
        sys.exit(1)
    
    config_path = config_matches[0]
    print(f"🔍 Using config: {config_path}")

    # 2. LOAD AND CHECK THE TOGGLE
    with open(config_path, 'r') as f:
        try:
            data = json.load(f)
        except:
            print("❌ Error: Invalid JSON!")
            sys.exit(1)

    # Use .get() and compare strictly to True
    # This handles "false", null, or missing keys correctly
    is_enabled = data.get('ci')
    
    if is_enabled is not True:
        print(f"⏭️  CI is DISABLED (Value is: {is_enabled}). Skipping scan.")
        return

    # 3. RUN THE SCAN
    print("🚀 CI is ENABLED. Scanning...")
    found_violation = False
    for sh_file in glob.iglob('**/*.sh', recursive=True):
        with open(sh_file, 'r', errors='ignore') as f:
            if "EXIT_RUNTIME" in f.read():
                print(f"❌ VIOLATION: {sh_file}")
                found_violation = True

    if found_violation:
        sys.exit(451)
    print("✔ All clear.")

if __name__ == "__main__":
    run_ci()
