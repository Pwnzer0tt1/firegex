import { MarkdownDocs } from "../MarkdownDocs";
// Single source of truth for this documentation: docs/nfproxy.md is rendered
// here as-is, and is also linked from fgex-lib/README.md (the pip package's
// own README), so the UI and the markdown files can never drift apart.
import docsMarkdown from "../../../../docs/nfproxy.md?raw";

export const NFProxyDocs = () => <MarkdownDocs content={docsMarkdown} sourcePath="docs/nfproxy.md" />;
