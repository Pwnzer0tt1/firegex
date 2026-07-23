import { MarkdownDocs } from "./MarkdownDocs";
import docsMarkdown from "../../../docs/tls.md?raw";

export const TLSDocs = () => <MarkdownDocs content={docsMarkdown} sourcePath="docs/tls.md" />;
