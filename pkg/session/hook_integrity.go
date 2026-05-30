package session

// maxDeniedToolUses bounds the denied-tool-use ring so the set cannot grow
// without limit over a long session.
const maxDeniedToolUses = 256

// RecordDeniedToolUse remembers that sir denied the given tool_use_id at
// PreToolUse, so a later PostToolUse for the same id can be recognized as the
// executor ignoring the deny. No-op for an empty id or a duplicate.
func (s *State) RecordDeniedToolUse(toolUseID string) {
	if toolUseID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.DeniedToolUses {
		if id == toolUseID {
			return
		}
	}
	s.DeniedToolUses = append(s.DeniedToolUses, toolUseID)
	if len(s.DeniedToolUses) > maxDeniedToolUses {
		s.DeniedToolUses = s.DeniedToolUses[len(s.DeniedToolUses)-maxDeniedToolUses:]
	}
}

// WasToolUseDenied reports whether the given tool_use_id was denied at
// PreToolUse this session.
func (s *State) WasToolUseDenied(toolUseID string) bool {
	if toolUseID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, id := range s.DeniedToolUses {
		if id == toolUseID {
			return true
		}
	}
	return false
}
