import ast

def run_week1_scan(source_code):
    dangerous_functions = ["eval", "exec", "system", "loads"]
    secret_keywords = ["password", "secret", "api_key", "token", "salt"]
    unsafe_variables = set()
    findings = []  # Stores all structured bug reports

    tree = ast.parse(source_code)

    for node in ast.walk(tree):
        # --- BOX 2: Variable Assignments ---
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    
                    # Rule 2: Hardcoded Secrets (CWE-798)
                    is_sensitive = any(word in var_name for word in secret_keywords)
                    is_string = isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                    
                    if is_sensitive and is_string:
                        findings.append({
                            "line": node.lineno,
                            "cwe": "CWE-798",
                            "type": "Hardcoded Secret",
                            "message": f"Hardcoded secret assigned to '{target.id}'"
                        })

                    # Taint Memory: Track variables holding f-strings or +
                    if isinstance(node.value, (ast.JoinedStr, ast.BinOp)):
                        unsafe_variables.add(target.id)

        # --- BOX 3: Function Calls ---
        elif isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            # Rule 1: Dangerous Sinks (CWE-78 / CWE-94)
            if func_name in dangerous_functions:
                findings.append({
                    "line": node.lineno,
                    "cwe": "CWE-94/78",
                    "type": "Dangerous Sink",
                    "message": f"Dangerous function '{func_name}()' used"
                })

            # Rule 3: SQL Injection (CWE-89)
            if func_name == "execute" and len(node.args) > 0:
                first_arg = node.args[0]
                is_direct_fstring = isinstance(first_arg, (ast.JoinedStr, ast.BinOp))
                is_tainted_var = isinstance(first_arg, ast.Name) and first_arg.id in unsafe_variables
                
                if is_direct_fstring or is_tainted_var:
                    findings.append({
                        "line": node.lineno,
                        "cwe": "CWE-89",
                        "type": "SQL Injection",
                        "message": "Unsafe dynamic SQL query inside execute()"
                    })

    return findings
# test case : a simple one ------
if __name__ == "__main__":
    sample_code = """
import os
secret_password = "admin123"
safe_password = os.environ.get("MY_PASS")
eval(secret_password)
os.system("dir")
db.execute(f"SELECT * FROM users WHERE user = '{secret_password}'")
bad_query = f"DELETE FROM users WHERE user = '{secret_password}'"
db.execute(bad_query)
"""
    results = run_week1_scan(sample_code)
    for bug in results:
        print(f"[Line {bug['line']}] [{bug['cwe']}] {bug['type']}: {bug['message']}")
