package agent

import "github.com/ayanasarkar/vapt-agent/internal/adapters"

// validateModuleRequest refuses a blank or malformed Metasploit module when a validation is requested.
func validateModuleRequest(module string) error { return adapters.ValidModule(module) }
