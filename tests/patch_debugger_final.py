with open("../frontend/src/components/Services/RegexDebugger.tsx", "r") as f:
    code = f.read()

code = code.replace("action: d.action,", "")
code = code.replace('action: Action.BLOCK, replaceWith: "",', '')
with open("../frontend/src/components/Services/RegexDebugger.tsx", "w") as f:
    f.write(code)
