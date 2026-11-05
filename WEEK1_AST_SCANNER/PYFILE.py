import ast

sample_code = """
import os 
# Comment: Never use eval() in production!
print("Testing if eval() triggers a false alarm")
secret_password = "admin123"
safe_password = os.environ.get("MY_PASS")
eval(secret_password)
os.system("dir")
db.execute(f"SELECT * FROM users WHERE user = '{secret_password}'")
db.execute("SELECT * FROM users WHERE user = %s", (secret_password,))
"""

dangerous_functions = ["eval", "exec", "system", "loads"]
secret_keywords = ["password", "secret", "api_key", "token", "salt"]

tree = ast.parse(sample_code)

for node in ast.walk(tree):
    # --- RULE 1 & RULE 3: Check Function Calls ---
    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # Rule 1: Dangerous Execution Sinks (Day 3)
        if func_name in dangerous_functions:
            print("WARNING! DANGEROUS FUNCTION", func_name.title(), "FOUND on line", node.lineno)

        # Rule 3: SQL Injection inside .execute() calls (Day 5)
        if func_name == "execute" and len(node.args) > 0:
            first_arg = node.args[0]
            if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                print("WARNING! SQL INJECTION RISK in execute() on line", node.lineno)

    # --- RULE 2: Check Variable Assignments for Hardcoded Secrets (Day 4) ---
    elif isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                is_sensitive_name = any(word in var_name for word in secret_keywords)
                is_hardcoded_string = isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                
                if is_sensitive_name and is_hardcoded_string:
                    print("WARNING! HARDCODED SECRET in variable", target.id, "on line", node.lineno)
