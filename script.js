(() => {
  "use strict";

  /* ============ DOM refs ============ */
  const pwdInput        = document.getElementById("pwd-input");
  const toggleVisBtn     = document.getElementById("toggle-visibility");
  const eyeOpen          = document.getElementById("eye-open");
  const eyeClosed        = document.getElementById("eye-closed");
  const reuseWarning     = document.getElementById("reuse-warning");

  const gaugeFill        = document.getElementById("gauge-fill");
  const scoreNumber      = document.getElementById("score-number");
  const ratingLabel      = document.getElementById("rating-label");
  const strengthFill     = document.getElementById("strength-fill");
  const crackTimeEl      = document.getElementById("crack-time");

  const statLength       = document.getElementById("stat-length");
  const statEntropy      = document.getElementById("stat-entropy");
  const statPool         = document.getElementById("stat-pool");

  const crackRowsEl      = document.getElementById("crack-rows");
  const suggestionsList  = document.getElementById("suggestions-list");
  const suggestionsBlock = document.getElementById("suggestions-block");

  const genLength        = document.getElementById("gen-length");
  const genLengthValue   = document.getElementById("gen-length-value");
  const genUpper         = document.getElementById("gen-upper");
  const genLower         = document.getElementById("gen-lower");
  const genNumber        = document.getElementById("gen-number");
  const genSpecial       = document.getElementById("gen-special");
  const genAmbiguous     = document.getElementById("gen-ambiguous");
  const generateBtn      = document.getElementById("generate-btn");
  const genOutput        = document.getElementById("gen-output");
  const copyBtn          = document.getElementById("copy-btn");
  const copyNote         = document.getElementById("copy-note");
  const useBtn           = document.getElementById("use-btn");

  const clearHistoryBtn  = document.getElementById("clear-history");
  const historyCountEl   = document.getElementById("history-count");

  const GAUGE_CIRC = 2 * Math.PI * 68; // matches r=68 in svg

  /* ============ Common password list (sample of frequently breached passwords) ============ */
  const COMMON_PASSWORDS = new Set([
    "123456","password","123456789","12345678","12345","qwerty","abc123",
    "password1","111111","123123","letmein","welcome","admin","iloveyou",
    "monkey","football","dragon","master","login","princess","qwerty123",
    "solo","passw0rd","starwars","freedom","whatever","trustno1","000000",
    "1234567","1234567890","superman","batman","shadow","michael","mustang",
    "baseball","access","flower","loveme","jordan","harley","ranger",
    "daniel","tigger","sunshine","chocolate","robert","matthew","jennifer",
    "hunter","jessica","charlie","andrew","michelle","corvette","bailey",
    "liverpool","amanda","1q2w3e4r","zaq12wsx","asdfgh","qazwsx","123321",
    "666666","121212","7777777","1qaz2wsx","abcd1234","p@ssw0rd","changeme"
  ]);

  const KEYBOARD_ROWS = ["qwertyuiop","asdfghjkl","zxcvbnm","1234567890"];

  /* ============ Char sets ============ */
  const SET_LOWER = "abcdefghijklmnopqrstuvwxyz";
  const SET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const SET_NUMBER = "0123456789";
  const SET_SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`";
  const AMBIGUOUS = "l1IO0";

  /* ============ Helpers ============ */
  function hasLower(s){ return /[a-z]/.test(s); }
  function hasUpper(s){ return /[A-Z]/.test(s); }
  function hasNumber(s){ return /[0-9]/.test(s); }
  function hasSpecial(s){ return /[^A-Za-z0-9]/.test(s); }

  function poolSize(s){
    let pool = 0;
    if (hasLower(s)) pool += 26;
    if (hasUpper(s)) pool += 26;
    if (hasNumber(s)) pool += 10;
    if (hasSpecial(s)) pool += 32;
    return pool;
  }

  function calcEntropy(s){
    const pool = poolSize(s);
    if (!s.length || pool === 0) return 0;
    return +(s.length * Math.log2(pool)).toFixed(1);
  }

  function hasRepeatedRun(s){
    return /(.)\1{2,}/.test(s); // same char 3+ times in a row
  }

  function hasSequentialPattern(s){
    const lower = s.toLowerCase();
    for (const row of KEYBOARD_ROWS) {
      const rowRev = row.split("").reverse().join("");
      for (let i = 0; i <= lower.length - 3; i++) {
        const chunk = lower.slice(i, i + 3);
        if (row.includes(chunk) || rowRev.includes(chunk)) return true;
      }
    }
    return false;
  }

  function isCommonPassword(s){
    return COMMON_PASSWORDS.has(s.toLowerCase());
  }

  function formatDuration(seconds){
    if (!isFinite(seconds) || seconds < 0) return "instant";
    if (seconds < 1) return "less than a second";
    const units = [
      ["century", 3153600000],
      ["year", 31536000],
      ["day", 86400],
      ["hour", 3600],
      ["minute", 60],
      ["second", 1]
    ];
    for (const [name, unitSeconds] of units) {
      if (seconds >= unitSeconds) {
        const value = seconds / unitSeconds;
        if (value > 1000 && name === "century") return "billions of years";
        const rounded = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
        return `${rounded.toLocaleString()} ${name}${rounded === 1 ? "" : "s"}`;
      }
    }
    return "less than a second";
  }

  const ATTACK_SCENARIOS = [
    { label: "Online, throttled (100 guesses/sec)", rate: 1e2 },
    { label: "Offline, slow hash (10k guesses/sec)", rate: 1e4 },
    { label: "Offline, GPU fast hash (10B guesses/sec)", rate: 1e10 }
  ];

  function crackSeconds(entropy, rate){
    const guesses = Math.pow(2, entropy) / 2; // average case
    return guesses / rate;
  }

  async function sha256(text){
    const enc = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest("SHA-256", enc);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  /* ============ Local history (fingerprints only, never raw passwords) ============ */
  const HISTORY_KEY = "vaultline_pwd_fingerprints";

  function getHistory(){
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    } catch { return []; }
  }
  function saveHistory(list){
    localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(-200)));
  }
  function updateHistoryCount(){
    historyCountEl.textContent = getHistory().length;
  }

  async function checkAndRecordHistory(password){
    if (!password) { reuseWarning.classList.add("hidden"); return; }
    const fp = await sha256(password);
    const history = getHistory();
    if (history.includes(fp)) {
      reuseWarning.classList.remove("hidden");
    } else {
      reuseWarning.classList.add("hidden");
      history.push(fp);
      saveHistory(history);
      updateHistoryCount();
    }
  }

  /* ============ Scoring ============ */
  function scorePassword(s){
    if (!s) return 0;

    let score = 0;

    // length contribution, up to 30
    score += Math.min(30, s.length * 2.2);

    // variety contribution, 10 each
    if (hasLower(s)) score += 10;
    if (hasUpper(s)) score += 10;
    if (hasNumber(s)) score += 10;
    if (hasSpecial(s)) score += 10;

    // entropy bonus, up to 20
    const entropy = calcEntropy(s);
    score += Math.min(20, entropy / 4);

    // penalties
    if (isCommonPassword(s)) score -= 55;
    if (hasRepeatedRun(s)) score -= 12;
    if (hasSequentialPattern(s)) score -= 12;
    if (s.length < 8) score -= 15;

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  function ratingFromScore(score){
    if (score < 40) return { label: "Weak", color: "var(--danger)" };
    if (score < 70) return { label: "Medium", color: "var(--warning)" };
    return { label: "Strong", color: "var(--success)" };
  }

  function buildSuggestions(s){
    const tips = [];
    if (!s) {
      return ["Start typing a password to see a live security readout."];
    }
    if (s.length < 12) tips.push("Use at least 12 characters — every extra character multiplies the guessing time.");
    if (!hasUpper(s)) tips.push("Add an uppercase letter (A–Z).");
    if (!hasLower(s)) tips.push("Add a lowercase letter (a–z).");
    if (!hasNumber(s)) tips.push("Add a number (0–9).");
    if (!hasSpecial(s)) tips.push("Add a special character (e.g. ! @ # $ %).");
    if (isCommonPassword(s)) tips.push("This exact password appears in known breach lists — avoid it entirely.");
    if (hasRepeatedRun(s)) tips.push("Avoid repeating the same character three or more times in a row.");
    if (hasSequentialPattern(s)) tips.push("Avoid sequential runs like \"1234\", \"abcd\", or \"qwerty\".");
    if (tips.length === 0) tips.push("Solid password. Consider a unique passphrase per account and a password manager to store it.");
    return tips;
  }

  /* ============ Render ============ */
  function setCheck(el, condition, strongFailColor){
    el.classList.remove("pass", "fail-strong");
    if (condition) {
      el.classList.add("pass");
    } else if (strongFailColor) {
      el.classList.add("fail-strong");
    }
  }

  async function analyze(){
    const s = pwdInput.value;
    const score = scorePassword(s);
    const rating = ratingFromScore(score);
    const entropy = calcEntropy(s);
    const pool = poolSize(s);

    // gauge
    const offset = GAUGE_CIRC - (score / 100) * GAUGE_CIRC;
    gaugeFill.style.strokeDashoffset = s ? offset : GAUGE_CIRC;
    gaugeFill.style.stroke = rating.color;
    scoreNumber.textContent = s ? score : 0;

    ratingLabel.textContent = s ? rating.label : "—";
    ratingLabel.style.color = s ? rating.color : "var(--text-muted)";
    strengthFill.style.width = s ? `${score}%` : "0%";
    strengthFill.style.background = rating.color;

    // stats
    statLength.textContent = s.length;
    statEntropy.textContent = `${entropy} bits`;
    statPool.textContent = pool;

    // checks
    setCheck(document.getElementById("check-length"), s.length >= 12);
    setCheck(document.getElementById("check-upper"), hasUpper(s));
    setCheck(document.getElementById("check-lower"), hasLower(s));
    setCheck(document.getElementById("check-number"), hasNumber(s));
    setCheck(document.getElementById("check-special"), hasSpecial(s));
    setCheck(document.getElementById("check-common"), s.length > 0 && !isCommonPassword(s), true);
    setCheck(document.getElementById("check-repeat"), s.length > 0 && !hasRepeatedRun(s), true);
    setCheck(document.getElementById("check-sequence"), s.length > 0 && !hasSequentialPattern(s), true);

    // main crack time (fast GPU scenario, matches label under rating)
    const fastSeconds = s ? crackSeconds(entropy, 1e10) : 0;
    crackTimeEl.textContent = s
      ? `Estimated crack time (fast GPU): ${formatDuration(fastSeconds)}`
      : "Estimated crack time (fast GPU): —";

    // crack-time table
    crackRowsEl.innerHTML = "";
    ATTACK_SCENARIOS.forEach(scenario => {
      const row = document.createElement("div");
      row.className = "crack-row";
      const seconds = s ? crackSeconds(entropy, scenario.rate) : 0;
      row.innerHTML = `<span>${scenario.label}</span><span>${s ? formatDuration(seconds) : "—"}</span>`;
      crackRowsEl.appendChild(row);
    });

    // suggestions
    const tips = buildSuggestions(s);
    suggestionsList.innerHTML = "";
    tips.forEach(tip => {
      const li = document.createElement("li");
      li.textContent = tip;
      suggestionsList.appendChild(li);
    });
    suggestionsBlock.classList.toggle("ok", s.length > 0 && score >= 70);

    // history / reuse check
    await checkAndRecordHistory(s);
  }

  /* ============ Visibility toggle ============ */
  toggleVisBtn.addEventListener("click", () => {
    const isPassword = pwdInput.type === "password";
    pwdInput.type = isPassword ? "text" : "password";
    eyeOpen.style.display = isPassword ? "none" : "block";
    eyeClosed.style.display = isPassword ? "block" : "none";
    toggleVisBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
  });

  pwdInput.addEventListener("input", () => { analyze(); });

  /* ============ Generator ============ */
  genLength.addEventListener("input", () => {
    genLengthValue.textContent = genLength.value;
  });

  function buildCharPool(){
    let pool = "";
    if (genUpper.checked) pool += SET_UPPER;
    if (genLower.checked) pool += SET_LOWER;
    if (genNumber.checked) pool += SET_NUMBER;
    if (genSpecial.checked) pool += SET_SPECIAL;
    if (genAmbiguous.checked) {
      pool = pool.split("").filter(c => !AMBIGUOUS.includes(c)).join("");
    }
    return pool;
  }

  function secureRandomInt(max){
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    return arr[0] % max;
  }

  function generatePassword(){
    const pool = buildCharPool();
    const length = parseInt(genLength.value, 10);
    if (!pool) {
      genOutput.value = "";
      genOutput.placeholder = "Select at least one character type";
      return;
    }
    // ensure at least one of each selected type is present
    const mustInclude = [];
    if (genUpper.checked) mustInclude.push(SET_UPPER);
    if (genLower.checked) mustInclude.push(SET_LOWER);
    if (genNumber.checked) mustInclude.push(SET_NUMBER);
    if (genSpecial.checked) mustInclude.push(SET_SPECIAL);

    let result = [];
    mustInclude.forEach(set => {
      const filtered = genAmbiguous.checked ? set.split("").filter(c => !AMBIGUOUS.includes(c)).join("") : set;
      if (filtered.length) result.push(filtered[secureRandomInt(filtered.length)]);
    });
    while (result.length < length) {
      result.push(pool[secureRandomInt(pool.length)]);
    }
    // shuffle (Fisher-Yates) using secure randomness
    for (let i = result.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [result[i], result[j]] = [result[j], result[i]];
    }
    result = result.slice(0, length);
    genOutput.value = result.join("");
  }

  generateBtn.addEventListener("click", generatePassword);

  copyBtn.addEventListener("click", async () => {
    if (!genOutput.value) return;
    try {
      await navigator.clipboard.writeText(genOutput.value);
      copyNote.classList.remove("hidden");
      setTimeout(() => copyNote.classList.add("hidden"), 1800);
    } catch {
      genOutput.select();
      document.execCommand("copy");
    }
  });

  useBtn.addEventListener("click", () => {
    if (!genOutput.value) return;
    pwdInput.value = genOutput.value;
    pwdInput.type = "text";
    eyeOpen.style.display = "none";
    eyeClosed.style.display = "block";
    analyze();
    pwdInput.scrollIntoView({ behavior: "smooth", block: "center" });
    pwdInput.focus();
  });

  clearHistoryBtn.addEventListener("click", () => {
    localStorage.removeItem(HISTORY_KEY);
    updateHistoryCount();
    reuseWarning.classList.add("hidden");
  });

  /* ============ Init ============ */
  updateHistoryCount();
  generatePassword();
  analyze();
})();
