// Go tools of the vulnerability gate and the CI of the Go gate client (clients/go, workflow client-go): govulncheck and
// staticcheck. Kept out of the library's own go.mod so that no application that imports the client inherits their
// requirements. Pinned by go.sum, bumped by Dependabot (entry gomod /.github/audit). Never imported: the module path
// only names it.
module tinysesam.invalid/audit-tools

go 1.26.0

tool (
	golang.org/x/vuln/cmd/govulncheck
	honnef.co/go/tools/cmd/staticcheck
)

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/telemetry v0.0.0-20261116191925-e77a43154acb // indirect
	golang.org/x/tools v0.53.0 // indirect
	golang.org/x/vuln v1.10.0 // indirect
	honnef.co/go/tools v0.8.2 // indirect
)
