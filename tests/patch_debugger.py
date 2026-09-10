import re

with open("../frontend/src/components/Services/RegexDebugger.tsx", "r") as f:
    code = f.read()

# Remove action and replaceWith from type Draft
code = re.sub(r'\s*action: string,\s*replaceWith: string,', '', code)
# Remove from initial props
code = re.sub(r'action\?: string, replaceWith\?: string ', '', code)

# Remove from default creation
code = re.sub(r'\s*action: p\.action \?\? Action\.BLOCK,\s*replaceWith: p\.replaceWith \?\? "",', '', code)

# Remove from dependencies map
code = re.sub(r'd\.action, d\.replaceWith', '', code)

# Remove from API payload
code = re.sub(r'\s*action: d\.action,\s*replace_with: encode\(d\.action === Action\.REWRITE \? d\.replaceWith : ""\),', '', code)

# Remove SegmentedControl and TextInput for rewrite
block = r'\s*const rewriting = draft\.action === Action\.REWRITE.*?onChange=\{\(value\) => update\(draft\.key, \{ replaceWith: value \}\)\} />\s*</Box>\s*:\s*null\}\s*</Group>'
code = re.sub(block, '</Group>', code, flags=re.DOTALL)

# Remove from add pattern button
code = re.sub(r'action: Action\.BLOCK, replaceWith: "", ', '', code)

with open("../frontend/src/components/Services/RegexDebugger.tsx", "w") as f:
    f.write(code)
