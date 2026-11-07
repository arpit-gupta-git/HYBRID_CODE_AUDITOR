import ast
import importlib

sample_code = """
import math
import super_ai_crypto
"""

# Dictionary to store verified real modules: {"math": <module 'math'>}
loaded_modules = {}

tree = ast.parse(sample_code)

for node in ast.walk(tree):
    # --- BOX 4: Check Import Statements ---
    if isinstance(node, ast.Import):
        for alias in node.names:
            mod_name = alias.name
            try:
                # Try loading the library dynamically
                real_mod = importlib.import_module(mod_name)
                loaded_modules[mod_name] = real_mod
                print(f"[Line {node.lineno}] VERIFIED: '{mod_name}' is a real library.")
            except ImportError:
                print(f"[Line {node.lineno}] WARNING! AI HALLUCINATION: Library '{mod_name}' does not exist!")

print("Saved real modules in memory:", list(loaded_modules.keys()))
