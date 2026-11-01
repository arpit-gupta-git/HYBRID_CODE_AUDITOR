import ast
sample_code = """
# Comment: Never use eval() in production!
print("Testing if eval() triggers a false alarm")
secret_password = "admin123"
eval(secret_password)
"""
dangerous_func = ["eval","exec"]
tree = ast.parse(sample_code)
for node in ast.walk(tree):
    if isinstance(node,ast.Call) and node.func.id in dangerous_func:
        # Print what function is being called and on what line!
        print("Found function call:", node.func.id, "on line", node.lineno)