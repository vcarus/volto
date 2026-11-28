//go:build tools

// This file is never compiled: the `tools` build tag is set by nothing. It
// exists so that `go mod tidy`, which reads every file whatever its tags, sees
// an import of sing-box and keeps the requirement direct.
//
// The `tool` directive in go.mod alone keeps the requirement too, but marks it
// `// indirect`, and Dependabot's gomod updater does not update a requirement
// it reaches only through a `tool` directive (dependabot-core issue 12050, open
// on 2026-11-29). A direct requirement is one it updates.
package singbox

import _ "github.com/sagernet/sing-box/cmd/sing-box"
