package tinysesam

// AdminAccounts is the administration data of an application (spec section 8b): the accounts a person may administer
// inside the application's area, as TinySesam's /.tinysesam/admin/accounts.json answers it on the application's host.
// Accounts is never nil; Links is always set. Every string is text, never markup; every href is safe or nil. An
// address is a convenience, not a right: the action page checks the person's rights again.
type AdminAccounts struct {
	App      *string        `json:"app"`
	Links    AdminLinks     `json:"links"`
	Accounts []AdminAccount `json:"accounts"`
}

// AdminLinks leads to the panel (nil without its pages).
type AdminLinks struct {
	Panel *string `json:"panel"`
}

// AdminAccount is one account the person may administer. ID is the claim ts_id and the header Remote-Id; Source is nil
// when missing or no list; Roles and Permissions (for this application) are never nil; TOTP is nil with TOTP off.
type AdminAccount struct {
	ID          *string      `json:"id"`
	Username    *string      `json:"username"`
	DisplayName *string      `json:"display_name"`
	Source      []string     `json:"source"`
	Roles       []string     `json:"roles"`
	Disabled    *bool        `json:"disabled"`
	TOTP        *bool        `json:"totp"`
	Permissions []string     `json:"permissions"`
	Actions     AdminActions `json:"actions"`
}

// AdminActions are the administration action pages of spec section 8c for one account; nil where the person may not
// act on it now (or not a safe link).
type AdminActions struct {
	TOTPReset     *string `json:"admin_totp_reset"`
	Lock          *string `json:"admin_lock"`
	Unlock        *string `json:"admin_unlock"`
	Roles         *string `json:"admin_roles"`
	KeyRevoke     *string `json:"admin_key_revoke"`
	ProgramRevoke *string `json:"admin_program_revoke"`
	SessionEnd    *string `json:"admin_session_end"`
	SigninLink    *string `json:"admin_signin_link"`
}

// ParseAdminAccounts normalizes the body of a 200 answer of /.tinysesam/admin/accounts.json (spec section 8b) — read
// same-origin in the browser for a person whose account overview names it (Account.Admin). Anything that is no JSON
// object reads as nothing to show; a member of the wrong type reads as missing, an unsafe href as nil, unknown members
// are dropped.
func ParseAdminAccounts(body []byte) AdminAccounts {
	out := AdminAccounts{Accounts: []AdminAccount{}}
	v, err := decodeStrictJSON(body)
	if err != nil {
		return out
	}
	data, _ := v.(map[string]any)
	out.App = text(data["app"])
	out.Links.Panel = href(group(data["links"])["panel"])
	for _, a := range objects(data["accounts"]) {
		act := group(a["actions"])
		out.Accounts = append(out.Accounts, AdminAccount{ID: text(a["id"]), Username: text(a["username"]),
			DisplayName: text(a["display_name"]), Source: texts(a["source"]), Roles: textList(a["roles"]),
			Disabled: flag(a["disabled"]), TOTP: flag(a["totp"]), Permissions: textList(a["permissions"]),
			Actions: AdminActions{TOTPReset: href(act["admin_totp_reset"]), Lock: href(act["admin_lock"]),
				Unlock: href(act["admin_unlock"]), Roles: href(act["admin_roles"]),
				KeyRevoke: href(act["admin_key_revoke"]), ProgramRevoke: href(act["admin_program_revoke"]),
				SessionEnd: href(act["admin_session_end"]), SigninLink: href(act["admin_signin_link"])}})
	}
	return out
}

// textList keeps the string entries of a list, in order; anything that is no list is an empty list.
func textList(v any) []string {
	if out := texts(v); out != nil {
		return out
	}
	return []string{}
}
