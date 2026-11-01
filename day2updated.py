import ast
sample_code = """
import os 
# Comment: Never use eval() in production!
print("Testing if eval() triggers a false alarm")
secret_password = "admin123"
eval(secret_password)
os.system("dir")
"""
dangerous_functions = ["eval","exec","system","loads"]
tree = ast.parse(sample_code)
for node in ast.walk(tree):
    if isinstance(node,ast.Call):
        func_name = ""
        if isinstance(node.func,ast.Name) :
            func_name = node.func.id
        elif isinstance(node.func,ast.Attribute):
            func_name = node.func.attr
        if func_name in dangerous_functions:
            print("WARNING ! ", "DANGEROUS FUNCTION",func_name.title() , "FOUND on line ", node.lineno)