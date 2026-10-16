import { MarkdownDocs } from "../MarkdownDocs";
import docsMarkdown from "../../../../docs/services.md?raw";

export const ServicesDocs = () => <MarkdownDocs content={docsMarkdown} sourcePath="docs/services.md" />;
