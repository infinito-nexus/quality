import "./altcha/altcha.min.js";

globalThis.$altcha.algorithms.set(
  "PBKDF2/SHA-256",
  () => new Worker(new URL("./altcha/pbkdf2.js", import.meta.url)),
);
