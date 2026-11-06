// Package version holds fixed application and internal format identifiers.
package version

// Application changes only with explicit user approval. Keeping it a constant
// prevents release tags or linker flags from overriding the reported version.
const Application = "1.0.0"

// Protocol and Script are internal identifiers; menus do not display them.
const Protocol = "v1"
const Script = "v1"
