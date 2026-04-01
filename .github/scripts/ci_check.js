const fs = require('fs');
const path = require('path');

function run() {
    // 1. Find Config
    const configPath = path.join(process.cwd(), 'ci.config.json');
    if (!fs.existsSync(configPath)) {
        console.error("❌ Error: ci.config.json not found!");
        process.exit(1);
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    // 2. Strict Check for the "ci" Toggle
    if (config.ci !== true) {
        console.log(`⏭️  CI is DISABLED (Value: ${config.ci}). Skipping next jobs.`);
        process.exit(0); 
    }

    console.log("🚀 CI ENABLED: Scanning repository for forbidden flags...");

    // 3. Scan Entire Repo for Forbidden Flags
    let foundViolation = false;
    function scan(dir) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                if (!['node_modules', '.git'].includes(entry.name)) scan(fullPath);
            } else if (entry.name.endsWith('.sh')) {
                const content = fs.readFileSync(fullPath, 'utf8');
                if (content.includes("EXIT_RUNTIME") || content.includes("--exit-runtime")) {
                    console.error(`❌ VIOLATION: ${fullPath}`);
                    foundViolation = true;
                }
            }
        }
    }
    
    scan(process.cwd());

    if (foundViolation) {
        process.exit(451);
    }

    // 4. THE SIGNAL (This triggers the next job)
    if (process.env.GITHUB_OUTPUT) {
        fs.appendFileSync(process.env.GITHUB_OUTPUT, `status=ready\n`);
        console.log("✅ Signal sent: READY");
    }
}

run();
