package versioning

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

// QualifiedName represents a function reference that may include a version or alias.
// Format: "functionName", "functionName:version", "functionName:alias"
type QualifiedName struct {
	FunctionName string
	Qualifier    string // version number or alias name, empty for $LATEST
}

// ParseQualifiedName parses a function reference string.
// Supported formats:
//   - "myFunction" -> function with $LATEST
//   - "myFunction:1" -> function with version 1
//   - "myFunction:prod" -> function with alias "prod"
//   - "myFunction:$LATEST" -> function with latest published code
func ParseQualifiedName(ref string) QualifiedName {
	parts := strings.SplitN(ref, ":", 2)
	qn := QualifiedName{
		FunctionName: parts[0],
	}
	if len(parts) > 1 {
		qn.Qualifier = parts[1]
	}
	return qn
}

// String returns the string representation of the qualified name.
func (q QualifiedName) String() string {
	if q.Qualifier == "" {
		return q.FunctionName
	}
	return fmt.Sprintf("%s:%s", q.FunctionName, q.Qualifier)
}

// IsVersion returns true if the qualifier is a version number.
func (q QualifiedName) IsVersion() bool {
	if q.Qualifier == "" {
		return false
	}
	_, err := strconv.Atoi(q.Qualifier)
	return err == nil
}

// IsAlias returns true if the qualifier is an alias name.
func (q QualifiedName) IsAlias() bool {
	if q.Qualifier == "" || q.Qualifier == "$LATEST" {
		return false
	}
	_, err := strconv.Atoi(q.Qualifier)
	return err != nil
}

// IsLatest returns true if the qualifier is $LATEST or empty.
func (q QualifiedName) IsLatest() bool {
	return q.Qualifier == "" || q.Qualifier == "$LATEST"
}

// Version returns the version number if the qualifier is a version.
func (q QualifiedName) Version() (int, bool) {
	v, err := strconv.Atoi(q.Qualifier)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ResolvedInvocation contains the resolved function and version for an invocation.
type ResolvedInvocation struct {
	FunctionName string
	Version      int
	Alias        string // empty if invoked directly by version
	IsLatest     bool   // true if using $LATEST
}

// Resolver resolves function references to specific versions.
type Resolver struct {
	manager *Manager
}

// NewResolver creates a new resolver.
func NewResolver(manager *Manager) *Resolver {
	return &Resolver{
		manager: manager,
	}
}

// Resolve resolves a function reference to a specific version.
func (r *Resolver) Resolve(ref string) (*ResolvedInvocation, error) {
	qn := ParseQualifiedName(ref)

	// Check if function exists
	config, err := r.manager.GetFunction(qn.FunctionName)
	if err != nil {
		// Function not registered in versioning system - return as-is for backward compatibility
		return &ResolvedInvocation{
			FunctionName: qn.FunctionName,
			Version:      0,
			IsLatest:     true,
		}, nil
	}

	// Handle $LATEST
	if qn.IsLatest() {
		return &ResolvedInvocation{
			FunctionName: qn.FunctionName,
			Version:      config.LatestVersion,
			IsLatest:     true,
		}, nil
	}

	// Handle version number
	if version, ok := qn.Version(); ok {
		// Verify version exists
		if _, err := r.manager.GetVersion(qn.FunctionName, version); err != nil {
			return nil, err
		}
		return &ResolvedInvocation{
			FunctionName: qn.FunctionName,
			Version:      version,
			IsLatest:     false,
		}, nil
	}

	// Handle alias
	alias, err := r.manager.GetAlias(qn.FunctionName, qn.Qualifier)
	if err != nil {
		return nil, err
	}

	// Handle routing config for traffic splitting
	version := alias.FunctionVersion
	if alias.RoutingConfig != nil && len(alias.RoutingConfig.AdditionalVersionWeights) > 0 {
		version = r.selectVersionWithRouting(alias)
	}

	return &ResolvedInvocation{
		FunctionName: qn.FunctionName,
		Version:      version,
		Alias:        qn.Qualifier,
		IsLatest:     false,
	}, nil
}

// selectVersionWithRouting selects a version based on routing config weights.
func (r *Resolver) selectVersionWithRouting(alias *Alias) int {
	// Calculate total weight for additional versions
	var additionalWeight float64
	for _, weight := range alias.RoutingConfig.AdditionalVersionWeights {
		additionalWeight += weight
	}

	// Clamp to valid range
	if additionalWeight > 1.0 {
		additionalWeight = 1.0
	}

	// Generate random number
	roll := rand.Float64()

	// Check additional versions first
	var cumulative float64
	for version, weight := range alias.RoutingConfig.AdditionalVersionWeights {
		cumulative += weight
		if roll < cumulative {
			return version
		}
	}

	// Default to primary version
	return alias.FunctionVersion
}

// GetVersionConfig returns the configuration for a specific resolved invocation.
func (r *Resolver) GetVersionConfig(resolved *ResolvedInvocation) (*Version, error) {
	if resolved.Version == 0 {
		return nil, nil // No version tracking for this function
	}
	return r.manager.GetVersion(resolved.FunctionName, resolved.Version)
}
