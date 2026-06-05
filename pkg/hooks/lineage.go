package hooks

import (
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/somoore/sir/pkg/core"
	internalpostflight "github.com/somoore/sir/pkg/hooks/internal/postflight"
	"github.com/somoore/sir/pkg/session"
)

func secretReadLineageLabel() session.LineageLabel {
	return session.LineageLabel{Sensitivity: "secret", Trust: "trusted", Provenance: "user"}
}

func secretOutputLineageLabel() session.LineageLabel {
	return session.LineageLabel{Sensitivity: "secret", Trust: "trusted", Provenance: "agent"}
}

func taintedMCPLineageLabel() session.LineageLabel {
	return session.LineageLabel{Sensitivity: "internal", Trust: "untrusted", Provenance: "mcp_tool"}
}

func credentialMCPLineageLabel() session.LineageLabel {
	return session.LineageLabel{Sensitivity: "secret", Trust: "untrusted", Provenance: "mcp_tool"}
}

func recordSensitiveReadEvidence(state *session.State, sourceRef string) {
	state.RecordLineageEvidence("sensitive_read", sourceRef, "high", []session.LineageLabel{secretReadLineageLabel()})
}

func seedSensitivePathLineage(projectRoot string, state *session.State, target string) {
	if state == nil || strings.TrimSpace(target) == "" {
		return
	}
	state.AttachLineageLabelsToPath(ResolveTarget(projectRoot, target), []session.LineageLabel{secretReadLineageLabel()})
}

func recordCredentialOutputEvidence(state *session.State, sourceRef string, matches []CredentialMatch) {
	state.RecordLineageEvidence("credential_output", sourceRef, highestCredentialConfidence(matches), []session.LineageLabel{secretOutputLineageLabel()})
}

func recordMCPCredentialEvidence(state *session.State, sourceRef string, matches []CredentialMatch) {
	state.RecordLineageEvidence("mcp_credential_output", sourceRef, highestCredentialConfidence(matches), []session.LineageLabel{credentialMCPLineageLabel()})
}

func recordMCPInjectionEvidence(state *session.State, sourceRef, severity string) {
	confidence := "medium"
	if strings.EqualFold(severity, "HIGH") {
		confidence = "high"
	}
	state.RecordLineageEvidence("tainted_mcp", sourceRef, confidence, []session.LineageLabel{taintedMCPLineageLabel()})
}

func attachLineageToWriteTarget(projectRoot string, state *session.State, payload *PostHookPayload) {
	target := internalpostflight.ExtractTarget(payload)
	if target == "" {
		return
	}
	state.AttachActiveEvidenceToPath(ResolveTarget(projectRoot, target))
}

func highestCredentialConfidence(matches []CredentialMatch) string {
	confidence := "medium"
	for _, match := range matches {
		if strings.EqualFold(match.Confidence, "high") {
			return "high"
		}
	}
	return confidence
}

func lineageSourceRef(payload *PostHookPayload, fallback string) string {
	return internalpostflight.SourceRef(payload, fallback)
}

func coreLabelsFromLineage(labels []session.LineageLabel) []core.Label {
	out := make([]core.Label, 0, len(labels))
	for _, label := range labels {
		out = append(out, core.Label{
			Sensitivity: label.Sensitivity,
			Trust:       label.Trust,
			Provenance:  label.Provenance,
		})
	}
	return out
}

func derivedLabelsForIntent(projectRoot string, payload *HookPayload, intent Intent, state *session.State) []core.Label {
	switch intent.Verb {
	case "stage_write":
		return coreLabelsFromLineage(state.DerivedLabelsForPath(ResolveTarget(projectRoot, intent.Target)))
	case "commit":
		return coreLabelsFromLineage(state.DerivedLabelsForPaths(gitStagedPaths(projectRoot)))
	case "push_origin", "push_remote":
		paths := gitOutgoingPaths(projectRoot, pushRemoteName(intent))
		// Forge-publish CLIs (gh/glab/hub/tea) carry the published payload as a
		// command-line file argument (`--body-file leak.txt`, `-F body=@file`,
		// `file://…`) rather than as files in the outgoing commits, so we must
		// scan the command tokens to label them. Native `git push`, by contrast,
		// only carries git-ref arguments on the command line (remote names,
		// branches, refspecs) — never file paths — so scanning its tokens would
		// only manufacture false positives when a derived file's basename happens
		// to collide with a ref token (e.g. a tainted `cmd/main` vs branch `main`).
		// Restrict the token scan to forge publishes to keep plain pushes quiet.
		if payload != nil && payload.ToolName == "Bash" && intent.IsForgePublish {
			paths = appendUniquePaths(paths, derivedPathsMentionedInCommand(projectRoot, state, intent.Target))
		}
		return coreLabelsFromLineage(state.DerivedLabelsForPaths(paths))
	case "net_allowlisted", "net_external", "dns_lookup":
		if payload != nil && payload.ToolName == "Bash" {
			return coreLabelsFromLineage(state.DerivedLabelsForPaths(derivedPathsMentionedInCommand(projectRoot, state, intent.Target)))
		}
	}
	return nil
}

func appendUniquePaths(paths []string, extra []string) []string {
	if len(extra) == 0 {
		return paths
	}
	seen := make(map[string]struct{}, len(paths)+len(extra))
	out := make([]string, 0, len(paths)+len(extra))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	for _, path := range extra {
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func gitStagedPaths(projectRoot string) []string {
	return gitPathList(projectRoot, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
}

func gitOutgoingPaths(projectRoot, remoteName string) []string {
	if paths := gitPathList(projectRoot, "diff", "--name-only", "@{upstream}..HEAD"); len(paths) > 0 {
		return paths
	}
	if paths := gitPathsForRemote(projectRoot, remoteName); len(paths) > 0 {
		return paths
	}
	return gitStagedPaths(projectRoot)
}

func pushRemoteName(intent Intent) string {
	if intent.RemoteName != "" {
		return intent.RemoteName
	}
	if intent.Verb == "push_origin" {
		return "origin"
	}
	return ""
}

func gitPathList(projectRoot string, args ...string) []string {
	cmd := exec.Command("git", append([]string{"-C", projectRoot}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		paths = append(paths, ResolveTarget(projectRoot, line))
	}
	return paths
}

func gitPathsForRevList(projectRoot string, args ...string) []string {
	commits := gitLineList(projectRoot, append([]string{"rev-list"}, args...)...)
	if len(commits) == 0 {
		return nil
	}
	paths := make([]string, 0)
	for _, commit := range commits {
		for _, path := range gitPathList(projectRoot, "diff-tree", "--no-commit-id", "--name-only", "-r", commit) {
			if !slices.Contains(paths, path) {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func gitPathsForRemote(projectRoot, remoteName string) []string {
	if remoteName == "" {
		return gitPathsForRevList(projectRoot, "--reverse", "HEAD", "--not", "--remotes")
	}
	if paths := gitPathsForRevList(projectRoot, "--reverse", "HEAD", "--not", "--remotes="+remoteName); len(paths) > 0 {
		return paths
	}
	return nil
}

func gitLineList(projectRoot string, args ...string) []string {
	cmd := exec.Command("git", append([]string{"-C", projectRoot}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	values := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		values = append(values, line)
	}
	return values
}

func derivedPathsMentionedInCommand(projectRoot string, state *session.State, command string) []string {
	if command == "" {
		return nil
	}
	derivedPaths := state.DerivedPaths()
	if len(derivedPaths) == 0 {
		return nil
	}
	tokens := strings.Fields(command)
	matched := make([]string, 0, len(tokens))
	for _, token := range tokens {
		for _, cleaned := range lineagePathCandidatesFromToken(token) {
			resolved := ResolveTarget(projectRoot, cleaned)
			for _, path := range derivedPaths {
				if resolved == path || cleaned == filepath.Base(path) {
					matched = append(matched, path)
					break
				}
			}
		}
	}
	return matched
}

func lineagePathCandidatesFromToken(token string) []string {
	cleaned := strings.Trim(token, "\"'`@,;:()[]{}<>|&")
	if cleaned == "" {
		return nil
	}
	candidates := []string{cleaned}
	if idx := strings.IndexByte(cleaned, '='); idx >= 0 && idx+1 < len(cleaned) {
		candidates = append(candidates, strings.TrimPrefix(cleaned[idx+1:], "@"))
	}
	if strings.HasPrefix(cleaned, "@") && len(cleaned) > 1 {
		candidates = append(candidates, strings.TrimPrefix(cleaned, "@"))
	}
	if strings.HasPrefix(cleaned, "file://") && len(cleaned) > len("file://") {
		candidates = append(candidates, strings.TrimPrefix(cleaned, "file://"))
	}
	return candidates
}
