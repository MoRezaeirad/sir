package main

import (
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
	"github.com/somoore/sir/pkg/telemetry"
)

// cmdClearSession clears developer-recoverable runtime restriction state.
// Pressure-valve command for developers who want to restore operability without
// starting a new Claude session.
func cmdClearSession(projectRoot string) {
	existing, err := session.Load(projectRoot)
	if err != nil && !os.IsNotExist(err) {
		fatal("no active session found: %v", err)
	}

	cleared := false
	if existing != nil && existing.HasTransientRestrictions() {
		if err := session.Update(projectRoot, func(state *session.State) error {
			state.ClearTransientRestrictions()
			return nil
		}); err != nil {
			fatal("clear session: %v", err)
		}
		cleared = true
	}

	shadowCleared, shadowErr := clearRuntimeShadowTransientRestrictions(projectRoot)
	if shadowErr != nil {
		if cleared {
			fmt.Fprintf(os.Stderr, "warning: could not clear active sir run shadow state: %v\n", shadowErr)
		} else {
			fatal("clear runtime shadow session: %v", shadowErr)
		}
	}
	cleared = cleared || shadowCleared

	if !cleared {
		fmt.Println("Session does not carry transient runtime restrictions. Nothing to clear.")
		return
	}

	entry := &ledger.Entry{
		ToolName: "sir-cli",
		Verb:     "session_cleared",
		Target:   "transient_restrictions",
		Decision: "allow",
		Reason:   "developer cleared transient runtime restrictions via sir unlock",
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not log to ledger: %v\n", err)
	}

	fmt.Println(hooks.FormatSessionCleared())
}

func clearRuntimeShadowTransientRestrictions(projectRoot string) (bool, error) {
	inspection, err := inspectRuntimeContainment(projectRoot)
	if err != nil || inspection == nil || inspection.Info == nil || inspection.Info.ShadowStateHome == "" {
		return false, err
	}
	switch inspection.Health {
	case session.RuntimeContainmentActive, session.RuntimeContainmentDegraded, session.RuntimeContainmentLegacy:
	default:
		return false, nil
	}

	shadowState, err := session.LoadFromHome(inspection.Info.ShadowStateHome, projectRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !shadowState.HasTransientRestrictions() {
		return false, nil
	}

	if err := session.UpdateFromHome(inspection.Info.ShadowStateHome, projectRoot, func(state *session.State) error {
		state.ClearTransientRestrictions()
		return nil
	}); err != nil {
		return false, err
	}
	return true, nil
}

func cmdUninstall(projectRoot string) {
	explicit := parseInstallAgentFlag(os.Args[2:])

	var agents []agent.Agent
	if explicit != "" {
		ag := agent.ForID(agent.AgentID(explicit))
		if ag == nil {
			fatal("unknown agent: %s (supported: %s)", explicit, supportedAgentIDs())
		}
		agents = []agent.Agent{ag}
	} else {
		agents = agent.All()
	}

	scope := "all agents"
	if explicit != "" {
		scope = explicit
	}
	anyRemoved := false
	for _, ag := range agents {
		removed, err := uninstallForAgent(ag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: uninstall %s hooks: %v\n", ag.Name(), err)
			continue
		}
		if removed {
			anyRemoved = true
		}
	}

	if anyRemoved {
		recordUninstall(projectRoot, scope)
	}

	if !anyRemoved {
		fmt.Println("No sir hooks found in any known agent config.")
	}
	fmt.Println("sir hooks removed. State and ledger are preserved at ~/.sir/ for forensic review.")
	fmt.Println("To remove everything (binaries + all state), run the uninstaller:")
	fmt.Println("  curl -fsSL https://raw.githubusercontent.com/somoore/sir/main/uninstall.sh | bash")
	fmt.Println("  (or: rm -rf ~/.sir ~/.local/bin/sir ~/.local/bin/mister-core)")
}

// recordUninstall makes hook removal observable: it appends a ledger marker to
// the current project (preserved for forensic review) and emits an OTLP event,
// so uninstall — a bypass of sir's protection — is visible to `sir friction`
// and to a fleet SIEM rather than silently disappearing with the hooks.
func recordUninstall(projectRoot, scope string) {
	entry := &ledger.Entry{
		ToolName: "sir-cli",
		Verb:     "sir_uninstall",
		Target:   scope,
		Decision: "alert",
		Severity: "MEDIUM",
		Reason:   fmt.Sprintf("sir hooks removed (%s)", scope),
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not log uninstall to ledger: %v\n", err)
	}
	sessionID := "uninstall"
	if st, err := session.Load(projectRoot); err == nil {
		sessionID = st.SessionID
	}
	ex := telemetry.NewExporter(projectRoot, sessionID, "", "")
	ex.Emit(telemetry.LogEvent{
		Timestamp: entry.Timestamp,
		SessionID: sessionID,
		Verb:      "sir_uninstall",
		Verdict:   "alert",
		Severity:  "MEDIUM",
		Reason:    entry.Reason,
	})
	ex.Shutdown()
}
