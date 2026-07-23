import { CodeHighlight } from "@mantine/code-highlight";
import { Typography } from "@mantine/core";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

function toHighlightLanguage(lang: string | undefined): string {
    return lang === "python" ? "python" : "";
}

const GITHUB_BLOB_BASE = "https://github.com/Pwnzer0tt1/firegex/blob/main/";

// Cross-references between doc files (e.g. "nfregex.md", "../fgex-lib/README.md")
// are relative to the file's position in the repo, which only resolves correctly
// on GitHub - inside the app they'd resolve against the current page's URL instead.
// Repoint any relative link at the equivalent file on GitHub, given where the
// currently-rendered markdown source lives in the repo.
function resolveHref(href: string, sourcePath: string): string {
    if (/^([a-z][a-z0-9+.-]*:)?\/\//i.test(href) || href.startsWith("mailto:") || href.startsWith("#")) {
        return href;
    }
    return new URL(href, GITHUB_BLOB_BASE + sourcePath).href;
}

function buildMarkdownComponents(sourcePath: string): Components {
    return {
        // CodeHighlight already renders its own <pre>, so unwrap the one react-markdown adds
        pre: ({ children }) => <>{children}</>,
        code: ({ className, children, ...props }) => {
            const match = /language-(\w+)/.exec(className ?? "");
            if (match) {
                return (
                    <CodeHighlight
                        code={String(children).replace(/\n$/, "")}
                        language={toHighlightLanguage(match[1])}
                        my="sm"
                    />
                );
            }
            return (
                <code className={className} {...props}>
                    {children}
                </code>
            );
        },
        a: ({ href, children, ...props }) => (
            <a href={href ? resolveHref(href, sourcePath) : href} target="_blank" rel="noreferrer" {...props}>
                {children}
            </a>
        ),
    };
}

// Renders a markdown documentation source (imported elsewhere via `?raw`) with
// Firegex's Mantine styling, so every module's docs page shares one renderer
// and one on-disk source of truth instead of duplicating hand-written JSX.
// `sourcePath` is the file's repo-relative path (e.g. "docs/nfproxy.md"), used
// to resolve relative cross-references to other doc files.
export const MarkdownDocs = ({ content, sourcePath }: { content: string; sourcePath: string }) => {
    return (
        <Typography>
            <ReactMarkdown remarkPlugins={[remarkGfm]} components={buildMarkdownComponents(sourcePath)}>
                {content}
            </ReactMarkdown>
        </Typography>
    );
};
