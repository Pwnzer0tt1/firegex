import { MarkdownDocs } from "../MarkdownDocs";
import docsMarkdown from "../../../../docs/firewall.md?raw";

export const FirewallDocs = () => <MarkdownDocs content={docsMarkdown} sourcePath="docs/firewall.md" />;
