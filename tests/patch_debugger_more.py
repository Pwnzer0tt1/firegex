import re

with open("../frontend/src/components/Services/RegexDebugger.tsx", "r") as f:
    code = f.read()

# Remove rewriting / segmented control for action completely
code = re.sub(r'\s*const rewriting = draft\.action === Action\.REWRITE.*?<SegmentedControl size="xs" value=\{draft\.action\}.*?</Group>', '</Group>', code, flags=re.DOTALL)
# Remove from Action import
code = re.sub(r'Action,\s*', '', code)

with open("../frontend/src/components/Services/RegexDebugger.tsx", "w") as f:
    f.write(code)

with open("../frontend/src/components/Services/FilterCard.tsx", "r") as f:
    code = f.read()

code = re.sub(r'Action,\s*', '', code)
block = r'\s*\{rx\.action === Action\.REWRITE \?.*?<Space w="xs" />\s*:\s*null\}'
code = re.sub(block, '', code, flags=re.DOTALL)

with open("../frontend/src/components/Services/FilterCard.tsx", "w") as f:
    f.write(code)

with open("../frontend/src/components/Services/utils.ts", "r") as f:
    code = f.read()

code = re.sub(r'/\*\*\s*What a matching pattern does.*?\s*REWRITE = "rewrite",\s*\}', '', code, flags=re.DOTALL)
code = re.sub(r'\s*action: Action,\s*replace_with: string \| null,', '', code)

with open("../frontend/src/components/Services/utils.ts", "w") as f:
    f.write(code)

with open("../frontend/src/components/Services/AddRegexModal.tsx", "r") as f:
    code = f.read()

code = re.sub(r'Action,\s*', '', code)
with open("../frontend/src/components/Services/AddRegexModal.tsx", "w") as f:
    f.write(code)

