package hooks

import (
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

func TestForgePublishCommandsMapToPushRemote(t *testing.T) {
	l := lease.DefaultLease()
	cases := []struct {
		name       string
		cmd        string
		wantRemote string
	}{
		{"gh pr create", "gh pr create --title test --body body", "github-cli"},
		{"gh pr comment body file", "gh -R owner/repo pr comment 42 --body-file leak.txt", "github-cli"},
		{"gh gist create", "gh gist create leak.txt", "github-cli"},
		{"gh release upload", "gh release upload v1.0 artifact.zip", "github-cli"},
		{"gh repo create source push", "gh repo create owner/new --source . --push", "github-cli"},
		{"gh api write", "gh api repos/owner/repo/issues -X POST --input issue.json", "github-cli"},
		{"glab mr create", "glab mr create --title test", "gitlab-cli"},
		{"glab issue note", "glab -R group/project issue note 12 -m hi", "gitlab-cli"},
		{"glab api write", "glab api projects/1/releases --method POST", "gitlab-cli"},
		{"hub pull request", "hub pull-request -m test", "github-hub"},
		{"tea pull create", "tea pulls create --repo owner/repo", "gitea-cli"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapShellCommand(tc.cmd, l)
			if got.Verb != policy.VerbPushRemote {
				t.Fatalf("verb = %q, want push_remote", got.Verb)
			}
			if got.RemoteName != tc.wantRemote {
				t.Fatalf("RemoteName = %q, want %q", got.RemoteName, tc.wantRemote)
			}
			if !got.IsForgePublish {
				t.Fatal("IsForgePublish = false, want true")
			}
		})
	}
}

func TestForgeReadOnlyCommandsStayDryRun(t *testing.T) {
	l := lease.DefaultLease()
	cases := []string{
		"gh pr view 42",
		"gh issue list",
		"gh api repos/owner/repo",
		"glab mr view 42",
		"glab issue list",
		"hub issue show 42",
		"tea issues list",
	}

	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			got := mapShellCommand(cmd, l)
			if got.Verb != policy.VerbExecuteDryRun {
				t.Fatalf("verb = %q, want execute_dry_run", got.Verb)
			}
			if got.IsForgePublish {
				t.Fatal("IsForgePublish = true, want false")
			}
		})
	}
}

func TestForgePublishCompoundPropagatesMarker(t *testing.T) {
	l := lease.DefaultLease()
	got := mapShellCommand("echo ok && gh pr create --title test --body body", l)
	if got.Verb != policy.VerbPushRemote {
		t.Fatalf("verb = %q, want push_remote", got.Verb)
	}
	if got.RemoteName != "github-cli" {
		t.Fatalf("RemoteName = %q, want github-cli", got.RemoteName)
	}
	if !got.IsForgePublish {
		t.Fatal("IsForgePublish = false, want true")
	}
}

func TestForgePublishDoesNotReuseGitRemoteAutoApproval(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)
	input := map[string]interface{}{"command": "gh pr create --title test --body body"}
	payload := &HookPayload{ToolName: "Bash", ToolInput: input, CWD: projectRoot}

	first, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluate first publish: %v", err)
	}
	if first.Decision != policy.VerdictAsk {
		t.Fatalf("first publish = %q, want ask", first.Decision)
	}
	if _, err := ExportPostEvaluatePayload(&PostHookPayload{ToolName: "Bash", ToolInput: input, CWD: projectRoot}, l, state, projectRoot); err != nil {
		t.Fatalf("post evaluate publish: %v", err)
	}

	second, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluate second publish: %v", err)
	}
	if second.Decision != policy.VerdictAsk {
		t.Fatalf("second publish after approval = %q, want ask (forge publish must not reuse git remote auto-approval)", second.Decision)
	}
}

func TestUntrustedThisTurnBlocksForgePublish(t *testing.T) {
	forceLocalPolicyFallback(t)
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)
	state.MarkUntrustedContentThisTurn()
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "gh pr create --title test --body body"},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluate forge publish: %v", err)
	}
	if resp.Decision != policy.VerdictDeny {
		t.Fatalf("untrusted-this-turn forge publish = %q, want deny (reason=%s)", resp.Decision, resp.Reason)
	}
}
