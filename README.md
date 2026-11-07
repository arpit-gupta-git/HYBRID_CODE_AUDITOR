# 🛡️ Hybrid AST + AI Code Vulnerability & Hallucination Auditor

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Security](https://img.shields.io/badge/SAST-AST%20%2B%20DataFlow-red)
![AI](https://img.shields.io/badge/Local%20AI-GraphCodeBERT%20%7C%20Qwen2.5--Coder-green)
![Cost](https://img.shields.io/badge/API%20Cost-%240%20(100%25%20Offline)-brightgreen)

An offline, zero-cost **Static Application Security Testing (SAST)** and automated code-repair engine. It detects security vulnerabilities (**MITRE CWEs**) and **AI API hallucinations** in Python code using deterministic compiler parsing (`ast` + `NetworkX`), deep-learning classification (`GraphCodeBERT`), and local LLM patching (`Qwen2.5-Coder`).

---

## 📌 1. Problem Statement & Motivation

1. **Insecure AI-Generated Code:** AI coding assistants frequently generate functional but vulnerable code (such as f-string SQL queries, hardcoded API keys, or `os.system()` calls).
2. **AI Package & Method Hallucinations:** LLMs predict tokens probabilistically and regularly invent non-existent libraries (e.g., `import py_crypto_shield`) or fake methods inside real libraries (e.g., `math.is_even()`).
3. **Privacy & Cost Barriers of Cloud Scanners:** Enterprise SAST tools cost hundreds of dollars per month and require uploading proprietary source code to external cloud servers.
4. **Why Regex Fails:** Simple text search (`grep`/Regex) cannot distinguish between a dangerous function call (`eval(user_input)`) and a harmless comment (`# Never use eval()`) or string literal.

### 💡 Proposed Solution
A **100% local, privacy-preserving hybrid pipeline** that parses code into an **Abstract Syntax Tree (AST)**, tracks tainted variables across lines (`Def-Use` chains), verifies imports against the live Python runtime (`importlib` + `inspect`), scores complex logic with `GraphCodeBERT`, and generates compiler-verified security patches using a local LLM via Ollama.

---

## 🏗️ 2. System Architecture

```text
                       [ Raw Python Source Code (.py) ]
                                      │
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ STAGE 1: Deterministic AST & Runtime Introspection Engine                 │
│ • Parses code via `ast.parse()` into structural nodes (`Call`, `Assign`)  │
│ • Detects CWE-89, CWE-78, CWE-94, CWE-798, CWE-502 with 0 false positives │
│ • Verifies imports & methods dynamically via `importlib` & `hasattr()`    │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ STAGE 2: Data-Flow Graph (DFG) & Taint Propagation Tracker                │
│ • Tracks untrusted data (`unsafe_variables` / `NetworkX` Def-Use chains)  │
│ • Catches multi-line vulnerabilities (2-step SQLi & CWE-22 Path Traversal)│
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ STAGE 3: Neural Vulnerability Scoring                                     │
│ • Runs local `microsoft/graphcodebert-base` inference on flagged blocks   │
│ • Computes semantic vulnerability confidence score                        │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ STAGE 4: Local LLM Auto-Patcher & Compiler Verification Gate              │
│ • Rewrites vulnerable code locally via Ollama (`qwen2.5-coder:3b`)        │
│ • Re-parses patched code via `ast.parse()` & re-scans to ensure 0 bugs    │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 3. Targeted CWEs & Hallucination Rules (Detailed Reference)

> **What is a CWE?** **CWE (Common Weakness Enumeration)** is a universal, community-developed dictionary of software and hardware security weaknesses maintained by the MITRE Corporation.

| ID | Vulnerability Name | Severity | AST Node & Taint Trigger | Standard Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **CWE-89** | SQL Injection | 🔴 CRITICAL | `ast.Call` (`execute`) + `JoinedStr` / `BinOp` / Tainted `Name` | Parameterized tuple queries (`%s` or `?`) |
| **CWE-78** | OS Command Injection | 🟠 HIGH | `ast.Call` (`os.system`, `os.popen`, `subprocess` w/ `shell=True`) | `subprocess.run([...], shell=False)` |
| **CWE-94** | Code Injection | 🟠 HIGH | `ast.Call` (`eval`, `exec`) on dynamic input | `ast.literal_eval()` or safe JSON parsing |
| **CWE-798** | Hardcoded Credentials | 🟡 MEDIUM | `ast.Assign` (`password`/`api_key`/`secret`/`salt`) + `ast.Constant` | Environment variables (`os.environ.get()`) |
| **CWE-22** | Path Traversal | 🟠 HIGH | Tainted input flowing into `open()` or `send_file()` | `os.path.basename()` + directory allowlist |
| **CWE-502** | Unsafe Deserialization | 🟠 HIGH | `ast.Call` (`pickle.loads`, `pickle.load`, `yaml.load`) | `json.loads()` or `yaml.safe_load()` |
| **AI-HALLUC** | AI API Hallucination | 🟠 HIGH | `ast.Import` / `ast.ImportFrom` / `ast.Attribute` failing `hasattr()` | Replace with verified standard library API |

---

## 🔍 4. Deep-Dive: CWE Explanations, AST Logic & Code Examples

### 1️⃣ CWE-89: SQL Injection (1-Line & Multi-Line Taint Tracking)
* **Why It Is Dangerous:** When user input is glued directly into an SQL string using f-strings or `+`, an attacker can input `admin' --` or `' OR '1'='1` to break out of quotes, bypass password checks, or delete database tables.
* **How Our AST Engine Catches It:**
  * **Direct (1-Line):** Checks `ast.Call` where `func.attr == "execute"` and flags if `node.args[0]` is an `ast.JoinedStr` (f-string) or `ast.BinOp` (`+` / `%`).
  * **Tainted (2-Line):** Records any variable assigned an f-string or `BinOp` inside an `unsafe_variables` set during `ast.Assign`, and flags `execute(var)` if `var` is in `unsafe_variables`.
* **Code Example:**
  ```python
  # ❌ VULNERABLE (Caught by AST + Taint Set)
  bad_query = f"SELECT * FROM users WHERE user = '{username}'"
  db.execute(bad_query)

  # ✅ SECURE PATCH (Parameterized Query)
  db.execute("SELECT * FROM users WHERE user = %s", (username,))
  ```

### 2️⃣ CWE-78 & CWE-94: OS Command & Dynamic Code Injection
* **Why It Is Dangerous:** Passing strings to `eval()`, `exec()`, or `os.system()` lets attackers chain shell commands (e.g., `127.0.0.1 && del /F /Q *`) or execute arbitrary Python bytecode on the host server.
* **How Our AST Engine Catches It:** Inspects `ast.Call` nodes. Extracts standalone names via `node.func.id` (`eval`, `exec`) and dotted methods via `node.func.attr` (`os.system`), ignoring comments and string literals completely.
* **Code Example:**
  ```python
  # ❌ VULNERABLE
  user_dict = eval(request_body)
  os.system("ping " + user_ip)

  # ✅ SECURE PATCH
  import ast, subprocess
  user_dict = ast.literal_eval(request_body)
  subprocess.run(["ping", user_ip], check=True, shell=False)
  ```

### 3️⃣ CWE-798: Use of Hard-Coded Credentials & Secrets
* **Why It Is Dangerous:** Developers and AI assistants often hardcode placeholder passwords, API keys, or cryptographic salts directly in code. Once pushed to GitHub, automated bots scrape and exploit those keys within seconds.
* **How Our AST Engine Catches It:** Inspects `ast.Assign` nodes. Checks if any left-hand target (`target.id`) matches sensitive keywords (`password`, `secret`, `api_key`, `token`, `salt`) **AND** verifies if the right-hand side (`node.value`) is a hardcoded string literal (`ast.Constant`). Safely ignores dynamic calls like `os.environ.get()`.
* **Code Example:**
  ```python
  # ❌ VULNERABLE (node.value is ast.Constant -> Flagged!)
  secret_password = "admin123"

  # ✅ SECURE PATCH (node.value is ast.Call -> Ignored by scanner!)
  import os
  secret_password = os.environ.get("DB_PASSWORD")
  ```

### 4️⃣ CWE-22: Path Traversal
* **Why It Is Dangerous:** Concatenating untrusted filenames into `open()` allows attackers to pass `../../etc/passwd` or `..\Windows\win.ini` to escape the upload folder and read private system files.
* **How Our AST Engine Catches It:** Tracks tainted filename variables flowing into `open()` calls without prior sanitization through `os.path.basename()`.
* **Code Example:**
  ```python
  # ❌ VULNERABLE
  with open("/uploads/" + user_file, "r") as f:
      data = f.read()

  # ✅ SECURE PATCH
  import os
  safe_file = os.path.basename(user_file)
  with open(os.path.join("/uploads", safe_file), "r") as f:
      data = f.read()
  ```

### 5️⃣ CWE-502: Deserialization of Untrusted Data
* **Why It Is Dangerous:** Python's `pickle.loads()` executes arbitrary code hidden inside maliciously crafted byte streams during object reconstruction.
* **How Our AST Engine Catches It:** Flags `ast.Call` nodes invoking `loads` or `load` on `pickle` or unsafe `yaml`.
* **Code Example:**
  ```python
  # ❌ VULNERABLE
  import pickle
  data = pickle.loads(untrusted_bytes)

  # ✅ SECURE PATCH
  import json
  data = json.loads(untrusted_bytes.decode("utf-8"))
  ```

### 6️⃣ AI-HALLUC: AI Library & Function Hallucinations
* **Why It Is Dangerous:** AI models frequently invent non-existent packages or fake helper methods (like `math.is_even()`), breaking builds or introducing subtle logic failures.
* **How Our AST Engine Catches It:**
  * Inspects `ast.Import` (`import X`) and `ast.ImportFrom` (`from X import Y`).
  * Dynamically attempts `importlib.import_module(X)` to verify package existence.
  * Inspects `ast.Attribute` calls (`X.method()`) and `ImportFrom` aliases using `hasattr(module, method)` and `inspect.signature()` to confirm the function and parameters actually exist.
* **Code Example:**
  ```python
  # ❌ AI HALLUCINATION (Caught by importlib + hasattr)
  import super_ai_crypto          # -> Hallucinated Library!
  import math
  result = math.is_even(4)        # -> Hallucinated Function inside real library!

  # ✅ VALID PYTHON
  result = (4 % 2 == 0)
  ```

---

## 🧠 5. Core AST Cheat Sheet ("The 4-Box Mental Model")

| AST Node Class | Python Syntax Represented | Key Attributes Inspected in Our Code |
| :--- | :--- | :--- |
| **`ast.Name`** | Simple variable word (`x`, `secret_password`) | `node.id` (always holds the string name of the variable) |
| **`ast.Assign`** | Assignment (`left = right`) | `node.targets` (left side list), `node.value` (right side `Constant`, `JoinedStr`, or `Call`) |
| **`ast.Call`** | Function call (`func(arg1)`) | `node.func.id` (no dot: `eval`), `node.func.attr` (with dot: `db.execute`), `node.args` (arguments) |
| **`ast.Import` / `ImportFrom`** | `import X` / `from X import Y` | `node.module` (parent library), `node.names` (list of `alias.name` items) |

---

## 🌍 6. Real-World Applications & DevSecOps Placement

* **IDE Pre-Commit Guardrail:** Runs locally via Git pre-commit hooks to block commits containing hardcoded API keys or SQL injections before code leaves the developer's laptop.
* **CI/CD Pull Request Gate:** Automates security reviews in GitHub Actions / GitLab pipelines at zero licensing cost.
* **Air-Gapped Enterprise Auditing:** Enables banking, healthcare, and defense teams to audit AI-assisted code offline without leaking source code to external LLM APIs.

---

## 🛠️ 7. Tech Stack & Hardware Requirements

* **Language & Built-ins:** Python 3.10+, `ast`, `importlib`, `inspect`
* **Graph & Taint Engine:** `NetworkX`
* **Deep Learning Classifier:** Hugging Face `transformers`, `torch` (`microsoft/graphcodebert-base`)
* **Local LLM Patching:** Ollama (`qwen2.5-coder:3b`)
* **UI Dashboard:** Streamlit
* **Target Hardware:** Runs 100% locally on consumer laptops (e.g., Intel Core i5 HX + NVIDIA RTX 3050 4GB/6GB VRAM, 16GB RAM).

---

## 📈 8. Implementation Roadmap

- [x] **Week 1:** Core Deterministic AST Scanner (`week1_scanner.py` — `CWE-89`, `CWE-78`, `CWE-94`, `CWE-798`, 2-Line Taint Set)
- [ ] **Week 2:** Runtime Introspection & AI Hallucination Detector (`importlib`, `hasattr`, `ast.Import`, `ast.ImportFrom`)
- [ ] **Week 3:** `NetworkX` Data-Flow Graph (DFG) & Multi-Hop Taint Analysis (`CWE-22`)
- [ ] **Week 4:** Local `GraphCodeBERT` Scoring & `Qwen2.5-Coder` Automated Patching + AST Verification Gate
- [ ] **Week 5–6:** Interactive Streamlit Dashboard, Benchmark Evaluation & Final Report

---

## ⚡ 9. Quick Start

```bash
# 1. Clone the repository
git clone [https://github.com/YOUR-USERNAME/HYBRID-CODE-AUDITOR.git](https://github.com/YOUR-USERNAME/HYBRID-CODE-AUDITOR.git)
cd HYBRID-CODE-AUDITOR

# 2. Run the Week 1 Core AST Scanner self-test
python week1_scanner.py
```
