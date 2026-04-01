import json
import os
import sys
import glob

# Find config relative to the script location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "ci.config.json")

def run_ci():
    # 1. Load Config
    if not os.path.exists(CONFIG_PATH):
        print(f"❌ Error: {CONFIG_PATH} not found.")
        sys.exit(1)

    with open(CONFIG_PATH, 'r') as f:
        data = json.load(f)

    # 2. Check the "ci" Toggle
    if not data.get('ci', False):
        print("⏭️  CI is disabled in config. Skipping scan.")
        return

    print("🚀 CI Enabled: Scanning entire repo for forbidden flags...")

    # 3. Global Scan for forbidden strings
    # This hunts for "EXIT_RUNTIME" or "--exit-runtime" in any .sh file
    found_violation = False
    for sh_file in glob.iglob('**/*.sh', recursive=True):
        try:
            with open(sh_file, 'r', errors='ignore') as f:
                if any(token in f.read() for token in ["EXIT_RUNTIME", "--exit-runtime"]):
                    print(f"❌ VIOLATION found in: {sh_file}")
                    found_violation = True
        except Exception as e:
            print(f"⚠️  Skipping {sh_file}: {e}")

    if found_violation:
        sys.exit(451)

    print("✔ CI check complete. No violations found.")

if __name__ == "__main__":
    run_ci()
