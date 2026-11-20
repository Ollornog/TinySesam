// Caddy with the caddy-jwt plugin, for deploy/forward-auth/Caddyfile.gate (ADR-9) and deploy/quickstart/.
//
// This is the documented way to build Caddy with plugins without xcaddy: a main package that imports
// Caddy's command, its standard modules and the plugins. go.mod pins the versions and go.sum their hashes,
// so Dependabot (`gomod`) bumps Caddy and caddy-jwt like any other dependency, and the build fails on a
// module whose content differs from the recorded hash.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/ggicci/caddy-jwt"
)

func main() {
	caddycmd.Main()
}
