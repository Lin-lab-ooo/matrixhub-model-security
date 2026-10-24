"""Read only a SHA-bound source and execute selected finite token definitions.
No whole-scanner import, torch/pickle import, serialization or payload parsing.
"""
import ast,hashlib,re,types
from pathlib import Path
NAMES={'LEGACY_SLOTS_MAX','LEGACY_INT_MAX','LEGACY_WIDTHS','LEGACY_FLOATS','LEGACY_GLOBALS','LegacyTorchError','legacy_require','LegacyGlobal','LegacyMap','LegacyList','LegacyStorage','LegacyTensor','LegacyMachine'}
def load_tokens(path,wanted,name):
    raw=Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=wanted:raise ValueError('source-sha')
    nodes=[]
    for node in ast.parse(raw).body:
        if isinstance(node,(ast.ClassDef,ast.FunctionDef)) and node.name in NAMES:nodes.append(node)
        elif isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id in NAMES for t in node.targets):nodes.append(node)
    module=types.ModuleType(name);module.re=re
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),module.__dict__)
    return module
