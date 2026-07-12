
def _get_version():
    v = "{{VERSION_PLACEHOLDER}}" if "{" not in "{{VERSION_PLACEHOLDER}}" else "0.0.0"
    if v == "0.0.0":
        import os
        env_v = os.getenv("FIREGEX_VERSION")
        if env_v:
            return env_v
        try:
            import re

            def parse_version(ver):
                ver = ver.lstrip("v")
                parts = re.split(r'[^0-9]+', ver)
                return tuple(int(p) if p.isdigit() else 0 for p in parts if p)

            def find_git_dir(start_path):
                current = start_path
                while current and current != "/" and current != "":
                    gd = os.path.join(current, ".git")
                    if os.path.isdir(gd):
                        return gd
                    parent = os.path.dirname(current)
                    if parent == current:
                        break
                    current = parent
                return None

            git_dir = find_git_dir(os.path.abspath(os.path.dirname(__file__)))
            if not git_dir:
                return v
                
            branch = None
            with open(os.path.join(git_dir, "HEAD"), "r") as f:
                head = f.read().strip()
                if head.startswith("ref: refs/heads/"):
                    branch = head.split("ref: refs/heads/")[1]
                    
            if branch != "main":
                return v
                
            tags = []
            try:
                with open(os.path.join(git_dir, "packed-refs"), "r") as f:
                    for line in f:
                        if " refs/tags/" in line:
                            tags.append(line.strip().split(" refs/tags/")[1])
            except Exception:
                pass
                
            tags_dir = os.path.join(git_dir, "refs", "tags")
            try:
                for root, _, files in os.walk(tags_dir):
                    for file in files:
                        tags.append(os.path.relpath(os.path.join(root, file), tags_dir).replace(os.path.sep, "/"))
            except Exception:
                pass
                
            version_tags = [t for t in set(tags) if any(c.isdigit() for c in t)]
            if version_tags:
                return max(version_tags, key=parse_version)
        except Exception:
            pass
    return v

__version__ = _get_version()

#Exported functions
__all__ = []
