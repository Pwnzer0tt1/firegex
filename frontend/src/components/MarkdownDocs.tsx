import { CodeHighlight } from "@mantine/code-highlight";
import { Typography } from "@mantine/core";
import { isValidElement, type ReactNode } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

function toHighlightLanguage(lang: string | undefined): string {
    const normalized = lang?.toLowerCase();
    if (normalized === "python" || normalized === "py") return "python";
    if (normalized === "bash" || normalized === "sh" || normalized === "shell") return "bash";
    if (normalized === "json") return "json";
    return "";
}

function flattenText(node: ReactNode): string {
    if (node == null || typeof node === "boolean") return "";
    if (typeof node === "string" || typeof node === "number") return String(node);
    if (Array.isArray(node)) return node.map(flattenText).join("");
    if (isValidElement<{ children?: ReactNode }>(node)) return flattenText(node.props.children);
    return "";
}

function slugifyHeading(children: ReactNode): string {
    return flattenText(children)
        .toLowerCase()
        .trim()
        .replace(/[^\w\s-]/g, "")
        .replace(/ /g, "-");
}

const GITHUB_BLOB_BASE = "https://github.com/Pwnzer0tt1/firegex/blob/main/";

// Cross-references between doc files (e.g. "pyfilter.md", "../fgex-lib/README.md")
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
            const raw = String(children);
            const isBlock = Boolean(match) || raw.includes("\n");
            if (isBlock) {
                return (
                    <CodeHighlight
                        code={raw.replace(/\n$/, "")}
                        language={toHighlightLanguage(match?.[1])}
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
        h1: ({ children, ...props }) => <h1 id={slugifyHeading(children)} {...props}>{children}</h1>,
        h2: ({ children, ...props }) => <h2 id={slugifyHeading(children)} {...props}>{children}</h2>,
        h3: ({ children, ...props }) => <h3 id={slugifyHeading(children)} {...props}>{children}</h3>,
        h4: ({ children, ...props }) => <h4 id={slugifyHeading(children)} {...props}>{children}</h4>,
        a: ({ href, children, onClick, ...props }) => {
            if (href?.startsWith("#")) {
                return (
                    <a
                        href={href}
                        onClick={e => {
                            onClick?.(e);
                            e.preventDefault();
                            const targetId = decodeURIComponent(href.slice(1));
                            document.getElementById(targetId)?.scrollIntoView({ behavior: "smooth" });
                        }}
                        {...props}
                    >
                        {children}
                    </a>
                );
            }
            return (
                <a href={href ? resolveHref(href, sourcePath) : href} target="_blank" rel="noreferrer" onClick={onClick} {...props}>
                    {children}
                </a>
            );
        },
    };
}

// Renders a markdown documentation source (imported elsewhere via `?raw`) with
// Firegex's Mantine styling, so every module's docs page shares one renderer
// and one on-disk source of truth instead of duplicating hand-written JSX.
// `sourcePath` is the file's repo-relative path (e.g. "docs/pyfilter.md"), used
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
