package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Tool-description / schema pinning.
//
// MCP "rug pulls" (MCPoison, CVE-2025-54136) and "full-schema poisoning"
// (CyberArk) mutate a tool's *definition* after the user approved the server —
// the description, parameter names, defaults, enums, examples, even error
// templates carry injectable instructions the model reads before any call.
// sir's binary-drift gate pins the server's *executable*; this pins its
// advertised *tool definitions*.
//
// Two honest constraints, mirrored from HashCommand:
//   - sir only sees tool definitions if it actively reads `tools/list` from the
//     server (the agent's hooks never deliver them). Capture therefore happens
//     at `sir mcp approve` / `sir mcp scan`, not on every tool call.
//   - the digest is over EVERY field of EVERY tool (full-schema), because the
//     injection surface is the whole object, not just `description`.

// CanonicalToolsDigest returns a stable SHA256 hex digest over the tool
// definitions in an MCP `tools/list` response, plus the sorted tool names it
// covered (for human-readable drift reporting).
//
// raw may be either the full JSON-RPC result object (`{"tools":[...]}`) or a
// bare tools array (`[...]`). The digest is:
//   - order-independent: tools are sorted by name before hashing, because a
//     server may return them in any order across runs;
//   - full-field: every key of every tool object is included (encoding/json
//     marshals map keys in sorted order, so the canonical form is deterministic);
//   - numerically exact: numbers are preserved verbatim (json.Number) so a
//     large default/enum value cannot silently re-canonicalize.
//
// Returns ("", nil, nil) for an empty input — the honest "nothing to pin"
// case, matching HashCommand's empty-hash semantics. A malformed tools/list is
// an error (a server that cannot produce a parseable tool list is not a thing
// we can safely pin, and the caller should surface that).
func CanonicalToolsDigest(raw []byte) (digest string, toolNames []string, err error) {
	// No input at all (server unreachable / not yet probed) is "nothing to pin".
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", nil, nil
	}

	tools, err := extractTools(raw)
	if err != nil {
		return "", nil, err
	}
	if len(tools) == 0 {
		// A server that successfully advertised ZERO tools is a real, pinnable
		// baseline — distinct from "could not probe". Return a stable sentinel
		// digest so a later drift from "no tools" to "a new (poisoned) tool" is
		// detected as drift rather than mistaken for a first-time capture.
		sum := sha256.Sum256([]byte("mcp.tools.empty.v1"))
		return hex.EncodeToString(sum[:]), nil, nil
	}

	// Sort tools by their "name" field so server-side ordering never moves the
	// digest. Tools without a string name sort last by their canonical bytes,
	// keeping the sort total and deterministic.
	type namedTool struct {
		name      string
		canonical []byte
	}
	canon := make([]namedTool, 0, len(tools))
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		c, err := marshalCanonical(t)
		if err != nil {
			return "", nil, err
		}
		name := toolName(t)
		canon = append(canon, namedTool{name: name, canonical: c})
		if name != "" {
			names = append(names, name)
		}
	}
	sort.Slice(canon, func(i, j int) bool {
		if canon[i].name != canon[j].name {
			return canon[i].name < canon[j].name
		}
		return bytes.Compare(canon[i].canonical, canon[j].canonical) < 0
	})
	sort.Strings(names)

	h := sha256.New()
	for _, c := range canon {
		h.Write(c.canonical)
		h.Write([]byte{0}) // record separator so adjacent tools can't blur together
	}
	return hex.EncodeToString(h.Sum(nil)), names, nil
}

// extractTools accepts either {"tools":[...]} (the tools/list result) or a bare
// [...] array, and returns the tool objects as raw decoded values.
func extractTools(raw []byte) ([]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var top interface{}
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("parse tools/list: %w", err)
	}
	switch v := top.(type) {
	case []interface{}:
		return v, nil
	case map[string]interface{}:
		// Either the JSON-RPC envelope {"result":{"tools":[...]}} or the bare
		// result {"tools":[...]}. Unwrap "result" first if present.
		if res, ok := v["result"].(map[string]interface{}); ok {
			v = res
		}
		if t, ok := v["tools"].([]interface{}); ok {
			return t, nil
		}
		return nil, fmt.Errorf("tools/list has no \"tools\" array")
	default:
		return nil, fmt.Errorf("tools/list is neither an array nor an object")
	}
}

// marshalCanonical produces deterministic bytes for one decoded tool value.
// encoding/json sorts map keys, and UseNumber kept numbers exact, so the same
// logical tool always marshals to the same bytes regardless of source field
// order or whitespace.
func marshalCanonical(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func toolName(t interface{}) string {
	m, ok := t.(map[string]interface{})
	if !ok {
		return ""
	}
	name, _ := m["name"].(string)
	return name
}
