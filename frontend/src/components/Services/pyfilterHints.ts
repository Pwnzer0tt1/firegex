import type { Monaco } from '@monaco-editor/react';
import { ApiModel, PyFilterApi } from './utils';

/**
 * Teaching the editor what the filter library offers.
 *
 * Everything here is driven by the description the backend introspects out of the
 * library — the models, their members, which of those can be written to. Nothing about
 * the API is spelled out in this file, because a second description of it would be
 * wrong the first time a model gained a property, and autocompletion that lies is worse
 * than none for exactly the reason a regex tester that disagrees with the engine is.
 *
 * What *is* here is the small amount of reading needed to know which model a name
 * refers to: filters annotate their parameters, and that annotation is what the library
 * itself keys off, so it is enough to look at the enclosing `def`.
 */

/** Monaco's completion kinds, resolved lazily so this module does not import the editor. */
type Kinds = { Class: number, Property: number, Method: number, Constant: number, Snippet: number }

const SNIPPETS = [
    {
        label: "pyfilter",
        detail: "a filter over raw payloads",
        insert: [
            "@pyfilter",
            "def ${1:block_something}(packet: RawPacket):",
            "\t\"\"\"${2:What this refuses, and why.}\"\"\"",
            "\tif b\"${3:needle}\" in packet.data:",
            "\t\treturn REJECT",
            "\treturn ACCEPT",
        ].join("\n"),
        doc: "A filter called for every chunk, in both directions.",
    },
    {
        label: "pyfilter-http",
        detail: "a filter over parsed HTTP requests",
        insert: [
            "@pyfilter",
            "def ${1:block_something}(request: HttpRequest):",
            "\t\"\"\"${2:What this refuses, and why.}\"\"\"",
            "\tif \"${3:../}\" in (request.url or \"\"):",
            "\t\treturn REJECT",
            "\treturn ACCEPT",
        ].join("\n"),
        doc: "Asking for an HttpRequest is what makes this file an HTTP filter.",
    },
    {
        label: "pyfilter-rewrite",
        detail: "a filter that rewrites the payload",
        insert: [
            "@pyfilter",
            "def ${1:redact}(packet: RawPacket):",
            "\tif b\"${2:secret}\" not in packet.data:",
            "\t\treturn ACCEPT",
            "\tpacket.data = packet.data.replace(b\"${2:secret}\", b\"${3:[redacted]}\")",
            "\treturn UNSTABLE_MANGLE",
        ].join("\n"),
        doc: "`data` is the only thing a filter can change. Exact on the proxy layer.",
    },
    {
        label: "imports",
        detail: "the usual imports",
        insert: "from firegex.pyfilters import pyfilter, ACCEPT, REJECT\nfrom firegex.pyfilters.models import ${1:RawPacket}\n",
        doc: "Verdicts come from firegex.pyfilters; models from firegex.pyfilters.models.",
    },
]

/** The model a parameter of the enclosing `def` was annotated with, if any. */
function annotationsInScope(lines: string[], upTo: number): Map<string, string> {
    const found = new Map<string, string>()
    for (let i = upTo; i >= 0; i--) {
        const def = lines[i].match(/^\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)/)
        if (!def) continue
        for (const param of def[1].split(",")) {
            const annotated = param.match(/^\s*(\w+)\s*:\s*(\w+)/)
            if (annotated) found.set(annotated[1], annotated[2])
        }
        break // the nearest enclosing def is the one whose parameters are in scope
    }
    return found
}

const memberDoc = (model: string, m: { name: string, doc: string, writable: boolean }) => ({
    value: [
        `\`${model}.${m.name}\`${m.writable ? " — **writable**" : ""}`,
        "",
        m.doc || "_No description._",
        ...(m.writable
            ? ["", "Assign to it and return `UNSTABLE_MANGLE` to forward the new bytes."]
            : []),
    ].join("\n"),
})

const modelDoc = (model: ApiModel) => ({
    value: [
        `\`${model.name}\``,
        "",
        model.doc || "_No description._",
        "",
        model.protocols.length > 1
            ? "_Available whatever the traffic is._"
            : `_Asking for this makes the file a **${model.protocols[0]}** filter._`,
    ].join("\n"),
})

/**
 * Register completion and hover for one editor, and give back a disposer.
 *
 * Registered per editor instance rather than globally so that closing the modal takes
 * the providers with it — Monaco keeps language registrations for the lifetime of the
 * page, and a second registration would offer everything twice.
 */
export function registerPyfilterHints(monaco: Monaco, api: PyFilterApi): () => void {
    const kinds = monaco.languages.CompletionItemKind as unknown as Kinds
    const byName = new Map(api.models.map(m => [m.name, m]))

    const completion = monaco.languages.registerCompletionItemProvider("python", {
        triggerCharacters: ["."],
        provideCompletionItems: (model: any, position: any) => {
            const line: string = model.getLineContent(position.lineNumber)
            const before = line.slice(0, position.column - 1)
            const word = model.getWordUntilPosition(position)
            const range = {
                startLineNumber: position.lineNumber, endLineNumber: position.lineNumber,
                startColumn: word.startColumn, endColumn: word.endColumn,
            }

            // `something.` — offer that model's members, when we know what it is.
            const member = before.match(/(\w+)\s*\.\s*\w*$/)
            if (member) {
                const lines: string[] = model.getValue().split("\n")
                const annotated = annotationsInScope(lines, position.lineNumber - 1)
                const found = byName.get(annotated.get(member[1]) ?? member[1])
                if (!found) return { suggestions: [] }
                return {
                    suggestions: found.members.map(m => ({
                        label: m.signature ?? m.name,
                        kind: m.signature ? kinds.Method : kinds.Property,
                        insertText: m.signature ? `${m.name}()` : m.name,
                        detail: m.writable ? "writable" : "read-only",
                        documentation: memberDoc(found.name, m),
                        range,
                    })),
                }
            }

            return {
                suggestions: [
                    ...api.models.map(m => ({
                        label: m.name, kind: kinds.Class, insertText: m.name,
                        detail: m.protocols.join(" · "),
                        documentation: modelDoc(m), range,
                    })),
                    ...api.verdicts.map(v => ({
                        label: v.name, kind: kinds.Constant, insertText: v.name,
                        detail: "verdict", documentation: { value: v.doc }, range,
                    })),
                    ...api.settings.map(v => ({
                        label: v.name, kind: kinds.Constant, insertText: v.name,
                        detail: "module-level setting",
                        documentation: {
                            value: [v.doc, ...(v.values.length ? ["", ...v.values.map(x => `- \`${x}\``)] : [])].join("\n"),
                        },
                        range,
                    })),
                    ...SNIPPETS.map(s => ({
                        label: s.label, kind: kinds.Snippet, insertText: s.insert,
                        insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
                        detail: s.detail, documentation: { value: s.doc }, range,
                    })),
                ],
            }
        },
    })

    const hover = monaco.languages.registerHoverProvider("python", {
        provideHover: (model: any, position: any) => {
            const word = model.getWordAtPosition(position)
            if (!word) return null
            const range = {
                startLineNumber: position.lineNumber, endLineNumber: position.lineNumber,
                startColumn: word.startColumn, endColumn: word.endColumn,
            }

            const found = byName.get(word.word)
            if (found) return { range, contents: [modelDoc(found)] }

            const verdict = [...api.verdicts, ...api.settings].find(v => v.name === word.word)
            if (verdict) return { range, contents: [{ value: `\`${verdict.name}\`\n\n${verdict.doc}` }] }

            // A member: resolved through the annotation of whatever it was reached from.
            const line: string = model.getLineContent(position.lineNumber)
            const owner = line.slice(0, word.startColumn - 1).match(/(\w+)\s*\.\s*$/)
            if (owner) {
                const lines: string[] = model.getValue().split("\n")
                const annotated = annotationsInScope(lines, position.lineNumber - 1)
                const cls = byName.get(annotated.get(owner[1]) ?? owner[1])
                const m = cls?.members.find(x => x.name === word.word)
                if (cls && m) return { range, contents: [memberDoc(cls.name, m)] }
            }
            return null
        },
    })

    return () => { completion.dispose(); hover.dispose() }
}
