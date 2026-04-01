const fs = require('fs');
const path = require('path');

// 1. Find the config (checks root first)
const configPath = path.join(process.cwd(), 'ci.config.json');

if (!fs.existsSync(configPath)) {
    console.log("❌ Error: ci.config.json missing!");
    process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

// 2. Strict Boolean Check (No "false" strings allowed!)
if (config.ci !== true) {
    console.log(`⏭️  CI is DISABLED (Value: ${config.ci}). Goodbye!`);
    process.exit(0);
}

console.log("🚀 CI ENABLED: Hunting for forbidden flags...");

// 3. Recursive Scanner (The "Entire Repo" bit)
let foundViolation = false;

function scan(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
            // Skip heavy folders to stay fast
            if (!['node_modules', '.git'].includes(entry.name)) scan(fullPath);
        } else if (entry.name.endsWith('.sh')) {
            const content = fs.readFileSync(fullPath, 'utf8');
            if (content.includes("EXIT_RUNTIME") || content.includes("--exit-runtime")) {
                console.log(`❌ VIOLATION: ${fullPath}`);
                foundViolation = true;
            }
        }
    }
}

scan(process.cwd());

if (foundViolation) process.exit(451);
console.log("✔ Repository is clean.");
