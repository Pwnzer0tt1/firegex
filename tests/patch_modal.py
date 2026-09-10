import re

with open("../frontend/src/components/Services/AddRegexModal.tsx", "r") as f:
    code = f.read()

# Remove 'action: Action.BLOCK as string,' and 'replace_with: "",'
code = re.sub(r'\s*action:.*?,\s*replace_with:.*?,', '', code, flags=re.DOTALL)
# Remove 'action: edit.action,' and 'replace_with: decode(edit.replace_with ?? ""),
code = re.sub(r'\s*action: edit\.action,\s*replace_with: decode\(edit\.replace_with \?\? ""\),', '', code, flags=re.DOTALL)

# Remove action and replace_with from body
code = re.sub(r'\s*action: values\.action,\s*//.*?\s*replace_with: rewriting \? encode\(values\.replace_with\) : null,', '', code, flags=re.DOTALL)

# Remove rewriting / canRewrite
code = re.sub(r'\s*const rewriting = form\.values\.action === Action\.REWRITE\s*const canRewrite = transport !== Transport\.NFQUEUE\s*', '', code)

# Remove SegmentedControl for action and {rewriting ? ... : null} and {canRewrite ? null : ...}
block_to_remove = r'<Text size="sm" fw=\{500\}>What to do where it matches</Text>.*?<Space h="md" />'
code = re.sub(block_to_remove, '', code, flags=re.DOTALL)

# Remove action and replaceWith from initial debugger
code = re.sub(r'\s*action: form\.values\.action,\s*replaceWith: form\.values\.replace_with,', '', code)

with open("../frontend/src/components/Services/AddRegexModal.tsx", "w") as f:
    f.write(code)
