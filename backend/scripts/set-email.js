const readline = require("readline");
const db = require("../db");

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function question(prompt) {
  return new Promise((resolve) => rl.question(prompt, resolve));
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

(async () => {
  const username = await question("Username to update: ");
  const email = await question("Email address (used for password resets): ");
  rl.close();

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user) {
    console.log("No such user found.");
    process.exit(1);
  }
  if (!isValidEmail(email)) {
    console.log("That doesn't look like a valid email address.");
    process.exit(1);
  }

  db.prepare("UPDATE users SET email = ? WHERE username = ?").run(email, username);
  console.log("Email updated successfully.");
  process.exit(0);
})();
