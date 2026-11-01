import ast

sample_code = """
secret_password = "admin123"
eval(secret_password)
print("hello")
for i in range(10):
    print(12)
"""

tree = ast.parse(sample_code)
print(ast.dump(tree, indent=4))