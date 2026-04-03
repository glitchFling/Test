const fs = require("fs");
const path = require("path");

function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
  }
}

function parseCommitConfig(config) {
  if (!Array.isArray(config.commit) || config.commit.length < 2) {
    throw new Error(
      'ci.config.json "commit" must be an array like ["on", "main"].'
    );
  }

  const [toggleRaw, branchRaw] = config.commit;
  const toggle = String(toggleRaw).toLowerCase();
  const branch = String(branchRaw || "").trim();

  if (!["on", "off"].includes(toggle)) {
    throw new Error('ci.config.json commit toggle must be "on" or "off".');
  }

  if (!branch) {
    throw new Error("ci.config.json commit branch must be non-empty.");
  }

  return { toggle, branch };
}

function scanForViolations(dir) {
  let foundViolation = false;
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!["node_modules", ".git"].includes(entry.name)) {
        foundViolation = scanForViolations(fullPath) || foundViolation;
      }
      continue;
    }

    if (!entry.name.endsWith(".sh")) continue;

    const content = fs.readFileSync(fullPath, "utf8");
    if (content.includes("EXIT_RUNTIME") || content.includes("--exit-runtime")) {
      console.error(`VIOLATION: ${fullPath}`);
      foundViolation = true;
    }
  }

  return foundViolation;
}

function resolveRefName() {
  return (
    process.env.GITHUB_HEAD_REF ||
    process.env.GITHUB_REF_NAME ||
    ""
  ).trim();
}

function run() {
  const configPath = path.join(process.cwd(), "ci.config.json");
  if (!fs.existsSync(configPath)) {
    console.error("Error: ci.config.json not found.");
    process.exit(1);
  }

  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  const { toggle, branch } = parseCommitConfig(config);
  const currentRef = resolveRefName();

  setOutput("status", "skipped");
  setOutput("commit_enabled", toggle);
  setOutput("commit_branch", branch);
  setOutput("current_branch", currentRef);

  if (config.ci !== true) {
    console.log(`CI disabled. Value: ${config.ci}`);
    return;
  }

  if (toggle !== "on") {
    console.log(`Commit gate disabled. commit[0]=${toggle}`);
    return;
  }

  if (currentRef !== branch) {
    console.log(`Branch gate blocked. current=${currentRef} expected=${branch}`);
    return;
  }

  console.log(`CI enabled on branch ${currentRef}. Scanning repository...`);

  if (scanForViolations(process.cwd())) {
    process.exit(451);
  }

  setOutput("status", "ready");
  console.log("Signal sent: READY");
}

run();
