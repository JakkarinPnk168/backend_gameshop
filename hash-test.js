// hash-test.js
import bcrypt from "bcrypt"; // ถ้าใช้ ES Module (มี "type": "module" ใน package.json)
// หรือใช้ require ถ้าเป็น CommonJS
// const bcrypt = require("bcrypt");

const password = "12345678";

bcrypt.hash(password, 10).then(hash => {
  console.log("✅ Password:", password);
  console.log("🔒 Hash:", hash);
});
