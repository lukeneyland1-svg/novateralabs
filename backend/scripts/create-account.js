const readline = require("readline");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const db = require("../db");

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function question(prompt, hide) {
  return new Promise((resolve) => {
    if (!hide) { rl.question(prompt, resolve); return; }
    process.stdout.write(prompt);
    let input = "";
    const onData = (char) => {
      char = char.toString();
      if (char === "\n" || char === "\r") {
        process.stdin.removeListener("data", onData);
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdout.write("\n");
        resolve(input);
        return;
      }
      if (char === "") process.exit();
      if (char === "") { input = input.slice(0, -1); return; }
      input += char;
    };
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", onData);
  });
}

(async () => {
  const username = await question("New username: ", false);
  const password = await question("New password: ", true);
  rl.close();

  const existing = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
  if (existing) {
    console.log("That username is already taken.");
    process.exit(1);
  }

  const hash = bcrypt.hashSync(password, 10);
  const apiKey = crypto.randomBytes(24).toString("hex");
  db.prepare("INSERT INTO users (username, password_hash, is_owner, api_key) VALUES (?, ?, 0, ?)").run(username, hash, apiKey);
  console.log(`Account "${username}" created.`);
  console.log(`API key (for connecting a server via the agent script): ${apiKey}`);
  process.exit(0);
})();
