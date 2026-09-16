const readline = require("readline");
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
      if (char === "\u0003") process.exit();
      if (char === "\u007f") { input = input.slice(0, -1); return; }
      input += char;
    };
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", onData);
  });
}

(async () => {
  const username = await question("Username to update: ", false);
  const password = await question("New password: ", true);

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user) {
    console.log("No such user found.");
    process.exit(1);
  }

  const hash = bcrypt.hashSync(password, 10);
  db.prepare("UPDATE users SET password_hash = ? WHERE username = ?").run(hash, username);
  console.log("Password updated successfully.");
  process.exit(0);
})();
