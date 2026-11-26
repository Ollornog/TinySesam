"""The German version of the configuration findings (`_DE`, selected with `config.lang == "de"`).

Split from `config_check.py` (T-112); `config_check` re-exports what other modules and the tests take from it
(its `__all__`), so they keep `config_check.<name>`.
"""
from __future__ import annotations

#: The one name of this module, read by `_config_check_base._t`.
__all__ = ["_DE"]

# --- German version of the findings (selected with `config.lang == "de"`) ---------------
#
# Key = the English template exactly as it stands in the `_t(config, …)` call, value = the German
# template with the same named placeholders. A key that is missing here falls back to English.
# `tests/` can check completeness: every first argument of a `_t(` call (AST) and every value of
# REQUIRES_MAILER / REQUIRES_BASE_URL / BASE_URL_RECOMMENDED must be a key of `_DE`, and every
# key must be used (`config_check._DE`).
_DE: dict[str, str] = {
    ("totp_app_hint: a mapping language → text (at most {langs} languages such as \"en\", \"de\"), each text 1 to "
     "{max} characters of plain text without control characters or line breaks"):
        ("totp_app_hint: eine Zuordnung Sprache → Text (höchstens {langs} Sprachen wie \"en\", \"de\"), jeder Text 1 "
         "bis {max} Zeichen reiner Text ohne Steuerzeichen und Zeilenumbrüche"),
    "recovery_codes_enabled={v!r} — True or False":
        "recovery_codes_enabled={v!r} — True oder False",
    ("recovery_codes_enabled=False and no application may reset an access (apps[…].provisioning with the scope "
     "users:reset): whoever loses their authenticator app is locked out until the application's own code removes "
     "the TOTP (totp_disable, grant_mfa_enrollment, create_signin_link) — the admin panel cannot."):
        ("recovery_codes_enabled=False und keine Anwendung darf einen Zugang zurücksetzen (apps[…].provisioning mit "
         "dem Scope users:reset): Wer die Authenticator-App verliert, bleibt ausgesperrt, bis der Code der Anwendung "
         "das TOTP entfernt (totp_disable, grant_mfa_enrollment, create_signin_link) — das Admin-Panel kann es nicht."),
    ("apps[{app!r}].provisioning.welcome_url={v!r} — a path (/…) or an http(s) address on the host of base_url or "
     "in trusted_redirect_hosts, printable ASCII without user part, at most {max} characters"):
        ("apps[{app!r}].provisioning.welcome_url={v!r} — ein Pfad (/…) oder eine http(s)-Adresse auf dem Host von "
         "base_url oder in trusted_redirect_hosts, druckbares ASCII ohne Benutzerangabe, höchstens {max} Zeichen"),
    ("{field}: the role {role!r} is empty, holds a comma or a control character, or has surrounding spaces — "
     "Remote-Groups would read it as another role or as several"):
        ("{field}: Die Rolle {role!r} ist leer, enthält ein Komma oder ein Steuerzeichen oder hat Leerzeichen am Rand — "
         "Remote-Groups läse sie als andere Rolle oder als mehrere"),
    ("apps: the id 'tinysesam' is reserved for TinySesam's own approval types — name the application "
     "differently"):
        ("apps: Die Kennung 'tinysesam' ist für TinySesams eigene Freigabe-Typen reserviert — die Anwendung "
         "anders benennen"),
    ("apps[{app!r}].approvals needs approvals_enabled=True"):
        ("apps[{app!r}].approvals braucht approvals_enabled=True"),
    ("apps[{app!r}].approvals.return_urls: at most {max} absolute https addresses (http only to "
     "127.0.0.1, ::1 or localhost) without query, fragment or user info — compared exactly"):
        ("apps[{app!r}].approvals.return_urls: höchstens {max} absolute https-Adressen (http nur zu "
         "127.0.0.1, ::1 oder localhost) ohne Query, Fragment und Benutzerangabe — sie werden exakt verglichen"),
    ("apps[{app!r}].approvals.types: a mapping type name → definition, at most {max}"):
        ("apps[{app!r}].approvals.types: eine Zuordnung Typname → Definition, höchstens {max}"),
    ("apps[{app!r}].approvals.types: {type!r} — ASCII, at least three segments separated by dots, the "
     "first one the application's id ({app}.<thing>.<action>), at most 100 characters"):
        ("apps[{app!r}].approvals.types: {type!r} — ASCII, mindestens drei durch Punkte getrennte Teile, der "
         "erste die Kennung der Anwendung ({app}.<ding>.<aktion>), höchstens 100 Zeichen"),
    ("apps[{app!r}].approvals.types[{type!r}].fields: a mapping field name → schema, at most {max} fields"):
        ("apps[{app!r}].approvals.types[{type!r}].fields: eine Zuordnung Feldname → Schema, höchstens {max} "
         "Felder"),
    ("apps[{app!r}].approvals.types[{type!r}].fields: {field!r} — lower-case letters, digits and _ , "
     "starting with a letter, at most 32 characters, never \"type\""):
        ("apps[{app!r}].approvals.types[{type!r}].fields: {field!r} — Kleinbuchstaben, Ziffern und _ , "
         "beginnend mit einem Buchstaben, höchstens 32 Zeichen, nie \"type\""),
    ("apps[{app!r}].approvals.types[{type!r}].fields[{field!r}].max: the longest value, 1 to {max} "
     "characters"):
        ("apps[{app!r}].approvals.types[{type!r}].fields[{field!r}].max: der längste Wert, 1 bis {max} Zeichen"),
    ("apps[{app!r}].approvals.types[{type!r}].fields[{field!r}].pattern: a regular expression of at most "
     "{max} characters (it must match the whole value)"):
        ("apps[{app!r}].approvals.types[{type!r}].fields[{field!r}].pattern: ein regulärer Ausdruck mit "
         "höchstens {max} Zeichen (er muss den ganzen Wert treffen)"),
    ("apps[{app!r}].approvals.types[{type!r}].fields[{field!r}]: min and max are integers within ±(2^53 − "
     "1), min not above max"):
        ("apps[{app!r}].approvals.types[{type!r}].fields[{field!r}]: min und max sind ganze Zahlen innerhalb "
         "±(2^53 − 1), min nicht über max"),
    ("apps[{app!r}].approvals.types[{type!r}].fields[{field!r}]: {{\"type\": \"string\", \"max\": …, \"pattern\": "
     "…}}, {{\"type\": \"integer\", \"min\": …, \"max\": …}} or {{\"type\": \"boolean\"}}"):
        ("apps[{app!r}].approvals.types[{type!r}].fields[{field!r}]: {{\"type\": \"string\", \"max\": …, \"pattern\": "
         "…}}, {{\"type\": \"integer\", \"min\": …, \"max\": …}} oder {{\"type\": \"boolean\"}}"),
    ("apps[{app!r}].approvals.types[{type!r}].irreversible: true or false"):
        ("apps[{app!r}].approvals.types[{type!r}].irreversible: true oder false"),
    ("apps[{app!r}].approvals.types[{type!r}].summary[{lang!r}]: only {{field}} placeholders (no format, "
     "no attribute; a literal brace is written {{{{ or }}}})"):
        ("apps[{app!r}].approvals.types[{type!r}].summary[{lang!r}]: nur Platzhalter {{feld}} (kein Format, "
         "kein Attribut; eine Klammer selbst schreibt man {{{{ oder }}}})"),
    ("apps[{app!r}].approvals.types[{type!r}].summary[{lang!r}]: the placeholder {{{name}}} is no field "
     "of the type"):
        ("apps[{app!r}].approvals.types[{type!r}].summary[{lang!r}]: Der Platzhalter {{{name}}} ist kein Feld "
         "des Typs"),
    ("apps[{app!r}].approvals.types[{type!r}].title[{lang!r}]: the title is fixed text — no placeholder"):
        ("apps[{app!r}].approvals.types[{type!r}].title[{lang!r}]: Der Titel ist fester Text — kein "
         "Platzhalter"),
    ("apps[{app!r}].approvals.types[{type!r}].{member}: a mapping language → text with at least \"en\" "
     "({{\"en\": …, \"de\": …}})"):
        ("apps[{app!r}].approvals.types[{type!r}].{member}: eine Zuordnung Sprache → Text mit mindestens \"en\" "
         "({{\"en\": …, \"de\": …}})"),
    ("apps[{app!r}].approvals.types[{type!r}].{member}[{lang!r}]: a text of at most {max} characters "
     "without control characters"):
        ("apps[{app!r}].approvals.types[{type!r}].{member}[{lang!r}]: ein Text mit höchstens {max} Zeichen "
         "ohne Steuerzeichen"),
    ("apps[{app!r}].approvals.types[{type!r}]: allowed members are {keys}; \"fields\", \"title\" and "
     "\"summary\" are required"):
        ("apps[{app!r}].approvals.types[{type!r}]: erlaubte Einträge sind {keys}; \"fields\", \"title\" und "
         "\"summary\" sind Pflicht"),
    ("apps[{app!r}].approvals.types_file {path!r} cannot be read as a JSON object type name → definition "
     "({why})"):
        ("apps[{app!r}].approvals.types_file {path!r} lässt sich nicht als JSON-Objekt Typname → Definition "
         "lesen ({why})"),
    ("apps[{app!r}].approvals.types_from={v!r} — the id of another application whose approvals block has "
     "types or types_file"):
        ("apps[{app!r}].approvals.types_from={v!r} — die Kennung einer anderen Anwendung, deren "
         "approvals-Block types oder types_file hat"),
    ("apps[{app!r}].approvals: exactly one of types, types_file and types_from"):
        ("apps[{app!r}].approvals: genau eines von types, types_file und types_from"),
    ("apps[{app!r}].approvals: {v!r} — allowed members are {keys}"):
        ("apps[{app!r}].approvals: {v!r} — erlaubte Einträge sind {keys}"),
    ("approvals_enabled=True with apikey_enabled=False: an approval is requested with an API key of the "
     "account — without keys nobody can ask."):
        ("approvals_enabled=True mit apikey_enabled=False: Eine Freigabe wird mit einem API-Key des Kontos "
         "angefragt — ohne Keys kann niemand anfragen."),
    ("approvals_enabled=True with csrf_enabled=False: the approval page needs the CSRF protection — "
     "otherwise a foreign page could confirm an action in the name of the signed-in person."):
        ("approvals_enabled=True mit csrf_enabled=False: Die Freigabe-Seite braucht den CSRF-Schutz — sonst "
         "könnte eine fremde Seite im Namen der angemeldeten Person eine Aktion bestätigen."),
    ("approvals_enabled=True without base_url: the link handed to the requester is built from base_url "
     "— never from the Host header of a request."):
        ("approvals_enabled=True ohne base_url: Der Link für den Anfrager wird aus base_url gebaut — nie "
         "aus dem Host-Header einer Anfrage."),
    ("oauth_service_key_days=0: a service key never expires — a copied key file stays usable until someone "
     "revokes the service. With a lifetime the reference client rotates the key on its own."):
        ("oauth_service_key_days=0: Ein Dienst-Schlüssel läuft nie ab — eine kopierte Schlüsseldatei bleibt "
         "nutzbar, bis jemand den Dienst widerruft. Mit Laufzeit wechselt der Referenz-Client den Schlüssel selbst."),
    ("oauth_pairing_consent_enabled=True without oauth_enabled=True: the pairing code arms one consent of the "
     "OAuth server — switch it on (with base_url, forward_auth_enabled and oauth_resources)."):
        ("oauth_pairing_consent_enabled=True ohne oauth_enabled=True: Der Kopplungscode schaltet eine Zustimmung des "
         "OAuth-Servers frei — ihn einschalten (mit base_url, forward_auth_enabled und oauth_resources)."),
    ("oauth_service_clients=True without oauth_enabled=True: services get their tokens from the OAuth "
     "server — switch it on (with base_url, forward_auth_enabled and oauth_resources)."):
        ("oauth_service_clients=True ohne oauth_enabled=True: Dienste bekommen ihre Tokens vom OAuth-Server — "
         "ihn einschalten (mit base_url, forward_auth_enabled und oauth_resources)."),
    ("oauth_enabled=True without forward_auth_enabled=True: the access token is checked in "
     "/auth/forward — without it no application accepts the tokens."):
        ("oauth_enabled=True ohne forward_auth_enabled=True: Das Access-Token wird in /auth/forward "
         "geprüft — ohne die Route nimmt keine Anwendung die Tokens an."),
    ("oauth_enabled=True without base_url: base_url is the issuer of the tokens (RFC 8414) and the "
     "address of the sign-in — it must be fixed, never taken from a request."):
        ("oauth_enabled=True ohne base_url: base_url ist der Aussteller der Tokens (RFC 8414) und die "
         "Adresse der Anmeldung — sie muss feststehen und darf nie aus einer Anfrage kommen."),
    ("oauth_enabled=True with csrf_enabled=False: the consent page needs the CSRF protection — "
     "otherwise a foreign page could allow a device in the name of the signed-in person."):
        ("oauth_enabled=True mit csrf_enabled=False: Die Zustimmungsseite braucht den CSRF-Schutz — "
         "sonst könnte eine fremde Seite im Namen der angemeldeten Person ein Gerät erlauben."),
    ("oauth_enabled=True, but oauth_resources is empty: tokens are issued only for a known "
     "resource (e.g. [\"https://app.example.com/mcp\"]) — without one every request is refused."):
        ("oauth_enabled=True, aber oauth_resources ist leer: Tokens gibt es nur für eine bekannte "
         "Ressource (z. B. [\"https://app.example.com/mcp\"]) — ohne sie wird jede Anfrage abgelehnt."),
    ("oauth_resources: {value!r} is no absolute http(s) URL without query and fragment."):
        ("oauth_resources: {value!r} ist keine absolute http(s)-Adresse ohne Query und Fragment."),
    ("oauth_resources: {value!r} uses http — tokens would travel in clear text. Use https "
     "(a certificate with an IP SAN works without a domain)."):
        ("oauth_resources: {value!r} nutzt http — Tokens gingen im Klartext. https verwenden "
         "(ein Zertifikat mit IP-SAN geht auch ohne Domain)."),
    ("oauth_resources: {value!r} lies on the address of TinySesam itself — a resource is an "
     "application behind forward auth, not the authorization server."):
        ("oauth_resources: {value!r} liegt auf der Adresse von TinySesam selbst — eine Ressource ist eine "
         "Anwendung hinter Forward-Auth, nicht der Autorisierungsserver."),
    ("oauth_refresh_max_days=0: a connected device stays connected as long as it is used, without "
     "an absolute maximum. ASVS 5.0 V10.4.8 (level 2) asks for one; the default is 180 days."):
        ("oauth_refresh_max_days=0: Ein verbundenes Gerät bleibt verbunden, solange es genutzt wird, "
         "ohne absolutes Höchstalter. ASVS 5.0 V10.4.8 (Stufe 2) verlangt eines; die Vorgabe ist 180 Tage."),
    ("{field}={path!r} is readable or writable by group or others (mode {mode}). It holds key material: "
     "chmod 600, owned by the service's user."):
        ("{field}={path!r} ist für Gruppe oder andere lesbar oder schreibbar (Modus {mode}). Darin liegt "
         "Schlüsselmaterial: chmod 600, Eigentümer der Benutzer des Dienstes."),
    ("{field}={path!r} lies in the database's directory — a backup or copy of that directory carries the key "
     "together with the data it protects. Keep it elsewhere (docs/OPERATIONS.md \"Keys\")."):
        ("{field}={path!r} liegt im Verzeichnis der Datenbank — eine Sicherung oder Kopie dieses Verzeichnisses "
         "trägt den Schlüssel mit den Daten, die er schützt. Woanders ablegen (docs/OPERATIONS.md \"Keys\")."),
    ("gate_token_enabled=True, the vault key is {path!r} next to the database, and the gate key is kept in the "
     "database encrypted with it: whoever can read the data directory can mint gate tokens for every account. "
     "Put TINYSESAM_SECRETS_KEY or secrets_key_file elsewhere, or give the gate key a place of its own "
     "(TINYSESAM_GATE_KEY, gate_key_file)."):
        ("gate_token_enabled=True, der Tresor-Schlüssel ist {path!r} neben der Datenbank, und der Gate-Schlüssel "
         "liegt damit verschlüsselt in der Datenbank: Wer das Datenverzeichnis lesen kann, kann für jedes Konto "
         "Gate-Tokens prägen. TINYSESAM_SECRETS_KEY oder secrets_key_file woanders ablegen, oder dem "
         "Gate-Schlüssel einen eigenen Ort geben (TINYSESAM_GATE_KEY, gate_key_file)."),
    ("demo_mode=True together with {real}: the demo creates an admin account with a known "
     "password. Next to a real login path or in front of foreign applications that is a "
     "back door, not a demonstration."):
        ("demo_mode=True zusammen mit {real}: Die Demo legt ein Admin-Konto mit bekanntem "
         "Passwort an. Neben einem echten Anmeldeweg oder vor fremden Anwendungen ist das eine "
         "Hintertür, keine Vorführung."),
    ("cookie_domain={domain!r} does not cover the host of base_url ({host}). The browser "
     "discards a cookie for a foreign domain — nobody would stay signed in."):
        ("cookie_domain={domain!r} umfasst den Host von base_url ({host}) nicht. Der Browser "
         "verwirft ein Cookie für eine fremde Domain — niemand bliebe angemeldet."),
    ("{field}={value!r} must begin with '/' — otherwise it is no path, and routes as well "
     "as links point nowhere."):
        ("{field}={value!r} muss mit '/' beginnen — sonst ist es kein Pfad, und Routen wie "
         "Links zeigen ins Leere."),
    ("session_ttl_transient_hours={short} is longer than session_ttl_hours={long}: without "
     "\"Stay signed in\" one would stay signed in longer than with it."):
        ("session_ttl_transient_hours={short} ist länger als session_ttl_hours={long}: Ohne "
         "„Angemeldet bleiben\" bliebe man länger angemeldet als mit."),
    ("signup_invite_only=True without allow_signup=True has no effect — registration is off "
     "anyway."):
        ("signup_invite_only=True ohne allow_signup=True ist wirkungslos — die Registrierung "
         "ist ohnehin aus."),
    ("Open registration without signup_verify_email: a taken address answers with 409, a "
     "free one signs in immediately — every visitor thus learns which addresses have an "
     "account here (ASVS 6.3.8). With signup_verify_email=True both answer the same."):
        ("Offene Registrierung ohne signup_verify_email: Eine vergebene Adresse antwortet mit "
         "409, eine freie meldet sofort an — jeder Besucher erfährt so, welche Adressen hier "
         "ein Konto haben (ASVS 6.3.8). Mit signup_verify_email=True antworten beide gleich."),
    ("signup_verify_email=True, but signup_require_email=False: whoever gives no address at "
     "registration is active immediately without any confirmation. Either "
     "signup_require_email=True or do without the confirmation."):
        ("signup_verify_email=True, aber signup_require_email=False: Wer bei der Registrierung "
         "keine Adresse angibt, ist ohne jede Bestätigung sofort aktiv. Entweder "
         "signup_require_email=True oder auf die Bestätigung verzichten."),
    ("gate_token_enabled=True, but no protected host: neither trusted_redirect_hosts nor "
     "oidc_clients nor base_url. A gate token arises only for these hosts — so for none, "
     "and the proxy keeps asking on every request."):
        ("gate_token_enabled=True, aber kein geschützter Host: weder trusted_redirect_hosts "
         "noch oidc_clients noch base_url. Ein Gate-Token entsteht nur für diese Hosts — so für "
         "keinen, und der Proxy fragt weiter bei jeder Anfrage."),
    ("gate_token_ttl_sec={ttl}: for this long, neither a sign-out in another application "
     "nor a block nor an approval withdrawn at the provider takes effect at the proxy. Up "
     "to 300 s the difference to a check per request is hardly noticeable; above 15 minutes "
     "it is a revocation delay that one should want deliberately."):
        ("gate_token_ttl_sec={ttl}: So lange wirkt am Proxy weder ein Abmelden in einer anderen "
         "Anwendung noch eine Sperre oder eine beim Provider entzogene Freigabe. Bis 300 s ist "
         "der Unterschied zur Prüfung je Anfrage kaum zu spüren; über 15 Minuten ist es ein "
         "Widerrufsverzug, den man bewusst wollen sollte."),
    ("gate_cookie_name={name!r} must have the form __Host-tinysesam_<name>: __Host- binds "
     "the cookie to the host of the application (the browser accepts it only without a "
     "Domain attribute), and tinysesam_ makes sure the proxy templates remove it in front "
     "of the application."):
        ("gate_cookie_name={name!r} muss die Form __Host-tinysesam_<name> haben: __Host- bindet "
         "das Cookie an den Host der Anwendung (der Browser nimmt es nur ohne Domain-Angabe "
         "an), und tinysesam_ sorgt dafür, dass die Proxy-Vorlagen es vor der Anwendung "
         "entfernen."),
    ("gate_token_enabled=True without forward_auth_enabled=True: the gate token arises in "
     "the response of /auth/forward — without the route there is none, and the proxy would "
     "fall back on every request to a check that does not exist."):
        ("gate_token_enabled=True ohne forward_auth_enabled=True: Das Gate-Token entsteht in "
         "der Antwort von /auth/forward — ohne die Route gibt es keins, und der Proxy fiele bei "
         "jeder Anfrage auf eine Prüfung zurück, die nicht existiert."),
    ("gate_link_enabled=True without base_url: the app hosts send to the address of the "
     "gateway for the sign-in — that is in base_url."):
        ("gate_link_enabled=True ohne base_url: Die App-Hosts schicken zur Anmeldung an die "
         "Adresse des Gateways — die steht in base_url."),
    ("gate_link_enabled=True together with cookie_domain: the code exchange is meant to NOT "
     "have the session cookie on the parent domain — otherwise it reaches every app below "
     "it. Leave cookie_domain empty."):
        ("gate_link_enabled=True zusammen mit cookie_domain: Der Code-Austausch soll das "
         "Sitzungs-Cookie gerade NICHT auf der Elterndomain haben — sonst erreicht es jede App "
         "darunter. cookie_domain leer lassen."),
    ("gate_link_enabled=True without gate_token_enabled=True: the code exchange gives the "
     "app host a connection with which it gets gate tokens — without a gate token it has no "
     "purpose."):
        ("gate_link_enabled=True ohne gate_token_enabled=True: Der Code-Austausch gibt dem "
         "App-Host eine Verbindung, mit der er Gate-Token bekommt — ohne Gate-Token hat sie "
         "keinen Zweck."),
    ("{where}='direct' leads straight to the identity provider — that only works if OIDC is "
     "the only login method (enabled: {enabled}). Otherwise the other methods would have no "
     "way onto the login page."):
        ("{where}='direct' leitet direkt zum Identity Provider — das geht nur, wenn OIDC die "
         "einzige Anmeldemethode ist (eingeschaltet: {enabled}). Sonst gäbe es für die übrigen "
         "Methoden keinen Weg auf die Login-Seite."),
    ("forward_login='direct' and sign-out (\"all\"/\"ask\"), but oidc_rp_logout=False: the "
     "session at the provider remains, and the next page request signs in again without any "
     "action. Set oidc_rp_logout=True (oidc_gateway() does that)."):
        ("forward_login='direct' und Abmelden („all“/„ask“), aber oidc_rp_logout=False: Die "
         "Sitzung beim Provider bleibt, und der nächste Seitenaufruf meldet ohne Zutun wieder "
         "an. oidc_rp_logout=True setzen (oidc_gateway() tut das)."),
    ("forward_apps is set, but forward_auth_enabled is False — only forward auth reads the "
     "per-application settings."):
        ("forward_apps ist gesetzt, forward_auth_enabled aber False — die Einstellungen je "
         "Anwendung liest nur die Forward-Auth."),
    ("{f}: {h!r} — a target of the app frame is a path (\"/spaces\", on this host) or an https "
     "address on exactly this host, without quotation marks, angle brackets, backslash and spaces"):
        ("{f}: {h!r} — ein Ziel des App-Rahmens ist ein Pfad (\"/spaces\", auf diesem Host) oder eine "
         "https-Adresse auf genau diesem Host, ohne Anführungszeichen, spitze Klammern, Backslash und Leerzeichen"),
    ("{where} has an app frame (home/links) but no name — the frame shows the application's name and "
     "nothing else on the left. Set {where}['name']."):
        ("{where} hat einen App-Rahmen (home/links), aber keinen name — der Rahmen zeigt links den Namen der "
         "Anwendung und sonst nichts. {where}['name'] setzen."),
    ("{where}['home']={value!r}: a path (\"/\", on this host) or an https address on exactly this host, "
     "without quotation marks, angle brackets, backslash and spaces."):
        ("{where}['home']={value!r}: ein Pfad (\"/\", auf diesem Host) oder eine https-Adresse auf genau diesem "
         "Host, ohne Anführungszeichen, spitze Klammern, Backslash und Leerzeichen."),
    "{where}['links']={value!r}: a list of (title, target) pairs like topbar_links.":
        "{where}['links']={value!r}: eine Liste von Paaren (Titel, Ziel) wie topbar_links.",
    "{where}['links'] has {n} entries — more than {limit} no longer fit next to the name on a desktop.":
        "{where}['links'] hat {n} Einträge — mehr als {limit} passen am Desktop nicht mehr neben den Namen.",
    ("{where} has an app frame (home/links), but topbar_enabled=False — the frame is a form of the top bar "
     "and is not shown."):
        ("{where} hat einen App-Rahmen (home/links), aber topbar_enabled=False — der Rahmen ist eine Form der "
         "Kopfleiste und wird nicht gezeigt."),
    ("forward_frame_default={value!r} names no forward_apps entry with an app frame (home or links) — "
     "the default frame would be empty."):
        ("forward_frame_default={value!r} nennt keinen Eintrag in forward_apps mit App-Rahmen (home oder links) "
         "— der Standard-Rahmen wäre leer."),
    ("admin_delegates[{owner!r}] manages {roles}, which apps[{app!r}].provisioning.roles grants as "
     "well — the admin panel and the application then manage the same accounts. Keep delegates "
     "for applications without an account API."):
        ("admin_delegates[{owner!r}] verwaltet {roles}, das auch apps[{app!r}].provisioning.roles vergibt — "
         "dann verwalten Admin-Panel und Anwendung dieselben Konten. Delegierte nur für Anwendungen ohne "
         "Konten-API einsetzen."),
    ("{where} is not in trusted_redirect_hosts — there is no redirect back for this host, the "
     "setting never takes effect."):
        ("{where} steht nicht in trusted_redirect_hosts — für diesen Host gibt es keine "
         "Rückleitung, die Einstellung greift nie."),
    "{where}['logout']={value!r}: allowed are {allowed}.":
        "{where}['logout']={value!r}: erlaubt sind {allowed}.",
    "{where}['login']={value!r}: allowed are {allowed}.":
        "{where}['login']={value!r}: erlaubt sind {allowed}.",
    "{where}['app_passwords']={value!r}: expected True or False.":
        "{where}['app_passwords']={value!r}: erwartet True oder False.",
    "{where} does not know {keys} (allowed: {allowed}).":
        "{where} kennt {keys} nicht (erlaubt: {allowed}).",
    "{where} must be a dict.":
        "{where} muss ein Dict sein.",
    "forward_apps must be a dict: {{\"app.example.com\": {{\"name\": …, \"login\": …}}}}.":
        ("forward_apps muss ein Dict sein: {{\"app.example.com\": {{\"name\": …, \"login\": "
         "…}}}}."),
    "forward_logout={mode!r}: allowed are {allowed}.":
        "forward_logout={mode!r}: erlaubt sind {allowed}.",
    "forward_login={mode!r}: allowed are {allowed}.":
        "forward_login={mode!r}: erlaubt sind {allowed}.",
    ("Group rule via the claim 'groups' (oidc_allowed_groups or oidc_group_role_map), but "
     "the scope 'groups' is not requested: {affected}. PocketID and other providers send "
     "the claim only with this scope — then oidc_allowed_groups rejects EVERYONE, and "
     "oidc_group_role_map assigns no role. Add 'groups' to oidc_scopes (gateway: "
     "TINYSESAM_OIDC_SCOPES; per application `scopes` in the oidc_clients entry). If the "
     "provider delivers the claim without a scope of its own (mapper, e.g. with Keycloak), "
     "this warning is moot."):
        ("Gruppenregel über den Claim 'groups' (oidc_allowed_groups bzw. oidc_group_role_map), "
         "aber der Scope 'groups' wird nicht angefordert: {affected}. PocketID und andere "
         "Provider schicken den Claim nur mit diesem Scope — dann weist oidc_allowed_groups "
         "JEDEN ab, und oidc_group_role_map vergibt keine Rolle. 'groups' in oidc_scopes "
         "aufnehmen (Gateway: TINYSESAM_OIDC_SCOPES; je Anwendung `scopes` im Eintrag von "
         "oidc_clients). Liefert der Provider den Claim ohne eigenen Scope (Mapper, etwa bei "
         "Keycloak), ist diese Warnung gegenstandslos."),
    ("Forward auth with open self-registration: every visitor creates an account and "
     "thereby gets through every protected application that does not require ?roles= at the "
     "proxy. signup_invite_only=True, allow_signup=False or require roles at the proxy."):
        ("Forward-Auth mit offener Selbst-Registrierung: Jeder Besucher legt sich ein Konto an "
         "und kommt damit durch jede geschützte Anwendung, die am Proxy kein ?roles= verlangt. "
         "signup_invite_only=True, allow_signup=False oder Rollen am Proxy verlangen."),
    ("Forward auth with an open gate: {items}. Every account at the provider is created at "
     "the first login and then gets through EVERY protected application that does not "
     "require ?roles= at the proxy. Limit the circle: set *_allowed_groups (for the gateway "
     "TINYSESAM_ALLOWED_GROUPS), require ?roles= at the proxy, or regulate the approval per "
     "application at the provider (oidc_clients)."):
        ("Forward-Auth mit offenem Tor: {items}. Jedes Konto beim Anbieter wird beim ersten "
         "Login angelegt und kommt danach durch JEDE geschützte Anwendung, die am Proxy kein "
         "?roles= verlangt. Den Kreis begrenzen: *_allowed_groups setzen (beim Gateway "
         "TINYSESAM_ALLOWED_GROUPS), am Proxy ?roles= verlangen, oder die Freigabe je Anwendung "
         "beim Provider regeln (oidc_clients)."),
    ("stepup_strict=True without stepup_methods has no effect: the barrier applies only to "
     "named methods. Probably e.g. stepup_methods=['totp'] was meant."):
        ("stepup_strict=True ohne stepup_methods ist wirkungslos: Die Schranke gilt nur für "
         "genannte Verfahren. Gemeint war vermutlich z.B. stepup_methods=['totp']."),
    ("stepup_methods requires {names}, but {switches}. This wish can never be fulfilled — "
     "without stepup_strict the confirmation silently falls back to another method, with "
     "stepup_strict the area stays closed."):
        ("stepup_methods verlangt {names}, aber {switches}. Dieser Wunsch kann nie erfüllt "
         "werden — ohne stepup_strict fällt die Bestätigung still auf ein anderes Verfahren "
         "zurück, mit stepup_strict bleibt der Bereich zu."),
    ("stepup_methods names {names} — those are not step-up methods. Allowed are {allowed}. "
     "An unknown name is not skipped but rejected: skipped, the confirmation would fall "
     "back to the password."):
        ("stepup_methods nennt {names} — das sind keine Step-up-Verfahren. Erlaubt sind "
         "{allowed}. Ein unbekannter Name wird nicht übersprungen, sondern abgewiesen: "
         "Übersprungen fiele die Bestätigung auf das Passwort zurück."),
    ("passkey_enabled=True with the developer values rp_id={rp!r}, origin={origin!r}. "
     "Outside your own machine every passkey fails with them — in production set both to "
     "the public address (and base_url as well)."):
        ("passkey_enabled=True mit den Entwicklerwerten rp_id={rp!r}, origin={origin!r}. "
         "Ausserhalb der eigenen Maschine scheitert damit jeder Passkey — produktiv beide auf "
         "die öffentliche Adresse setzen (und base_url dazu)."),
    ("origin={shown!r} differs from base_url ({base}). The login page runs under base_url, "
     "and the browser reports exactly this origin — with the value here every passkey "
     "fails. Usually the development default is still in place here."):
        ("origin={shown!r} weicht von base_url ab ({base}). Die Anmeldeseite läuft unter "
         "base_url, und der Browser meldet genau diesen Origin — mit dem Wert hier scheitert "
         "jeder Passkey. Meist steht hier noch die Vorgabe für die Entwicklung."),
    ("rp_id={rp!r} does not match origin={origin!r}: the rp_id must be the host of the "
     "origin or a domain above it. Every browser rejects the passkey ceremony that way."):
        ("rp_id={rp!r} passt nicht zu origin={origin!r}: Die rp_id muss der Host des Origins "
         "sein oder eine Domain darüber. So lehnt jeder Browser die Passkey-Zeremonie ab."),
    ("rp_id={rp!r} must be a hostname without scheme and port, e.g. \"auth.example.com\" or "
     "the domain above it (\"example.com\")."):
        ("rp_id={rp!r} muss ein Hostname ohne Schema und Port sein, z.B. \"auth.example.com\" "
         "oder die Domain darüber (\"example.com\")."),
    ("origin={origin!r} is not an origin. Required is exactly scheme, host and optionally "
     "port (\"https://auth.example.com\"), without a path and without a trailing slash — "
     "the browser compares character by character."):
        ("origin={origin!r} ist kein Origin. Verlangt ist genau Schema, Host und ggf. Port "
         "(\"https://auth.example.com\"), ohne Pfad und ohne Schrägstrich am Ende — der Browser "
         "vergleicht Zeichen für Zeichen."),
    ("origin is an empty list — at least one origin like \"https://auth.example.com\" must "
     "be there, otherwise every passkey fails."):
        ("origin ist eine leere Liste — mindestens ein Origin wie \"https://auth.example.com\" "
         "muss dastehen, sonst scheitert jeder Passkey."),
    ("trusted_proxies contains entries that are not an IP network: {bad}. Expected are "
     "addresses or networks like '203.0.113.5' or '198.51.100.0/24' — no hostnames. An "
     "invalid entry must not be read along: it would otherwise decide whether the proxy "
     "counts as trustworthy."):
        ("trusted_proxies enthält Einträge, die kein IP-Netz sind: {bad}. Erwartet werden "
         "Adressen oder Netze wie '203.0.113.5' oder '198.51.100.0/24' — keine Hostnamen. Ein "
         "ungültiger Eintrag darf nicht mitgelesen werden: Er entschiede sonst, ob der Proxy "
         "als vertrauenswürdig gilt."),
    ("{field}={value} is outside {lo}…{hi}. The most common reason is a mixed-up unit (the "
     "field name states it)."):
        ("{field}={value} liegt ausserhalb von {lo}…{hi}. Häufigster Grund ist eine "
         "verwechselte Einheit (der Feldname nennt sie)."),
    "{field}={value!r} is not an integer.":
        "{field}={value!r} ist keine ganze Zahl.",
    ("The configuration check names the field {field!r}, which does not exist in "
     "TinySesamConfig — a bug in TinySesam itself."):
        ("Die Konfigurationsprüfung nennt das Feld {field!r}, das es in TinySesamConfig nicht "
         "gibt — ein Fehler in TinySesam selbst."),
    ("{field}=True ({what}), but smtp_host is empty. Without a mailer no mail goes out and "
     "the method ends silently. Either set smtp_host or call auth.set_mailer(...) at "
     "runtime — then this message is moot."):
        ("{field}=True ({what}), aber smtp_host ist leer. Ohne Mailer geht keine Mail hinaus "
         "und das Verfahren endet still. Entweder smtp_host setzen oder zur Laufzeit "
         "auth.set_mailer(...) aufrufen — dann ist diese Meldung gegenstandslos."),
    ("smtp_host={host!r} is an IP address. The certificate of the mail server is checked "
     "against the hostname; if it does not carry the IP as a Subject Alternative Name, "
     "every send fails. Remedy: enter the name the certificate is issued for (with a CA of "
     "your own additionally smtp_ca_file)."):
        ("smtp_host={host!r} ist eine IP-Adresse. Das Zertifikat des Mailservers wird gegen den "
         "Hostnamen geprüft; trägt es die IP nicht als Subject Alternative Name, scheitert "
         "jeder Versand. Abhilfe: den Namen eintragen, auf den das Zertifikat ausgestellt ist "
         "(bei eigener CA zusätzlich smtp_ca_file)."),
    ("base_url={base!r} is an IP address. HTTPS on it needs a CA of your own that every "
     "device trusts once (Secure cookies and OAuth clients require HTTPS), and passkeys do "
     "not work on an IP address at all (WebAuthn accepts only domain names). Recommended: "
     "a domain — a publicly trusted certificate via DNS-01 works even for names that "
     "resolve only inside your network. "
     "If it has to be the IP: docs/HOME-NETWORK.md."):
        ("base_url={base!r} ist eine IP-Adresse. HTTPS darauf braucht eine eigene CA, der jedes "
         "Gerät einmal vertraut (Secure-Cookies und OAuth-Clients verlangen HTTPS), und Passkeys "
         "funktionieren auf einer IP-Adresse gar nicht (WebAuthn nimmt nur Domainnamen). "
         "Empfohlen: eine Domain — ein öffentlich vertrauenswürdiges Zertifikat per DNS-01 klappt "
         "auch für Namen, die nur im eigenen Netz auflösen. Muss es die IP sein: docs/HOME-NETWORK.md."),
    ("smtp_ca_file={ca!r} does not exist. The TLS check of the mail server then fails on "
     "every mail — sign-in links, resets and confirmations would never go out, and only in "
     "operation."):
        ("smtp_ca_file={ca!r} gibt es nicht. Die TLS-Prüfung des Mailservers scheitert dann bei "
         "jeder Mail — Anmelde-Links, Resets und Bestätigungen gingen nie hinaus, und das erst "
         "im Betrieb."),
    ("ldap_tls_ca_file={ca!r} does not exist. The connection to the directory then fails at "
     "every sign-in — and only in operation."):
        ("ldap_tls_ca_file={ca!r} gibt es nicht. Die Verbindung zum Verzeichnis scheitert dann "
         "bei jeder Anmeldung — und zwar erst im Betrieb."),
    ("ldap_tls_verify=False: the certificate of the directory is not checked. Encrypted "
     "then only means: not readable by someone who does not sit in between. Whoever "
     "redirects the traffic presents a certificate of their own and gets both passwords. "
     "With a CA of your own, it belongs in ldap_tls_ca_file."):
        ("ldap_tls_verify=False: Das Zertifikat des Verzeichnisses wird nicht geprüft. "
         "Verschlüsselt heisst dann nur: nicht mitlesbar von jemandem, der nicht "
         "dazwischensitzt. Wer den Verkehr umlenkt, hält ein eigenes Zertifikat hin und bekommt "
         "beide Passwörter. Bei eigener CA gehört sie in ldap_tls_ca_file."),
    ("ldap_allow_plaintext=True: the LDAP traffic is unencrypted. The password of the "
     "service account and every user password can thus be read by anyone sitting on the "
     "path. Only justifiable if this path does not leave the machine."):
        ("ldap_allow_plaintext=True: Der LDAP-Verkehr ist unverschlüsselt. Das Passwort des "
         "Dienstkontos und jedes Benutzerpasswort sind damit für jeden mitlesbar, der auf dem "
         "Weg sitzt. Nur vertretbar, wenn dieser Weg die Maschine nicht verlässt."),
    ("ldap_url={url!r} speaks plain text and ldap_start_tls is False. Then the password of "
     "the service account AND every user password travel unencrypted over the network — at "
     "every sign-in. Remedy: ldaps:// in the URL (port 636) or ldap_start_tls=True (port "
     "389). If the directory is on the same host and the traffic never leaves it, "
     "ldap_allow_plaintext=True says so explicitly."):
        ("ldap_url={url!r} spricht im Klartext und ldap_start_tls ist False. Dann gehen das "
         "Passwort des Dienstkontos UND jedes Benutzerpasswort unverschlüsselt über das Netz — "
         "bei jeder Anmeldung. Abhilfe: ldaps:// in der URL (Port 636) oder ldap_start_tls=True "
         "(Port 389). Ist das Verzeichnis auf demselben Host und der Verkehr verlässt ihn nie, "
         "sagt ldap_allow_plaintext=True das ausdrücklich."),
    ("passkey_user_verification='preferred': a passkey without user verification signs in "
     "on its own and then proves only possession of the key — an unlocked computer or a "
     "plugged-in stick is enough. That is a deliberate decision for a stock of old "
     "authenticators; for a new one the value belongs at 'required'."):
        ("passkey_user_verification='preferred': Ein Passkey ohne Nutzerprüfung meldet allein "
         "an und belegt dann nur den Besitz des Schlüssels — ein entsperrter Rechner oder ein "
         "eingesteckter Stick genügt. Das ist eine bewusste Entscheidung für einen Bestand "
         "alter Authentikatoren; für einen neuen gehört der Wert auf 'required'."),
    ("signin_link_max_ttl_min={most} is below magiclink_ttl_min={default}: a sign-in link issued without "
     "its own validity takes magiclink_ttl_min and would always be refused. Raise the bound or lower "
     "magiclink_ttl_min."):
        ("signin_link_max_ttl_min={most} liegt unter magiclink_ttl_min={default}: Ein Anmeldelink ohne eigene "
         "Gültigkeit bekommt magiclink_ttl_min und würde immer abgewiesen. Die Grenze anheben oder "
         "magiclink_ttl_min senken."),
    ("signin_link_max_ttl_min={most} is below invite_ttl_min={default}: an invitation issued without its "
     "own validity takes invite_ttl_min and would always be refused. Raise the bound or lower "
     "invite_ttl_min."):
        ("signin_link_max_ttl_min={most} liegt unter invite_ttl_min={default}: Eine Einladung ohne eigene "
         "Gültigkeit bekommt invite_ttl_min und würde immer abgewiesen. Die Grenze anheben oder "
         "invite_ttl_min senken."),
    ("totp_window={window!r} does not exist. Allowed are 'previous' (default: the current and the "
     "previous 30-second step), 'current' (only the running step) and 'previous_and_next' (also the "
     "next step, the behaviour up to 0.25.x)."):
        ("totp_window={window!r} gibt es nicht. Erlaubt sind 'previous' (Vorgabe: der laufende und der "
         "vorige 30-Sekunden-Schritt), 'current' (nur der laufende Schritt) und 'previous_and_next' "
         "(auch der nächste Schritt, das Verhalten bis 0.25.x)."),
    ("passkey_user_verification={uv!r} does not exist. Allowed are 'required' (default: the "
     "authenticator must verify the person) and 'preferred' (it is asked to). A passkey "
     "signs in on its own — without verification it only proves possession of the key."):
        ("passkey_user_verification={uv!r} gibt es nicht. Erlaubt sind 'required' (Vorgabe: der "
         "Authenticator muss den Menschen prüfen) und 'preferred' (er wird gebeten). Ein "
         "Passkey meldet allein an — ohne Prüfung belegt er nur den Besitz des Schlüssels."),
    ("csrf_enabled=False together with cookie_samesite='none': the browser then sends the "
     "session cookie along with every form of a foreign site, and no token holds against it "
     "— every state-changing route can be triggered via CSRF. Either csrf_enabled=True "
     "(needed as soon as SameSite=None is used) or cookie_samesite='lax'."):
        ("csrf_enabled=False zusammen mit cookie_samesite='none': Dann schickt der Browser das "
         "Sitzungs-Cookie bei jedem Formular einer fremden Seite mit, und kein Token hält "
         "dagegen — jede zustandsändernde Route ist per CSRF auslösbar. Entweder "
         "csrf_enabled=True (nötig, sobald SameSite=None gebraucht wird) oder "
         "cookie_samesite='lax'."),
    ("mfa_enrollment='grace', but mfa_enrollment_grace_days is 0 or less. 'grace' then "
     "behaves like 'strict', only less conspicuously — either set a period or write "
     "mfa_enrollment='strict' right away."):
        ("mfa_enrollment='grace', aber mfa_enrollment_grace_days ist 0 oder kleiner. Damit "
         "verhält sich 'grace' wie 'strict', nur unauffälliger — entweder eine Frist setzen "
         "oder gleich mfa_enrollment='strict' schreiben."),
    ("mfa_enrollment={kind!r} does not exist. Allowed are {allowed}: 'first_login' (default, "
     "allowed until the first complete login), 'grace' (allowed mfa_enrollment_grace_days "
     "after account creation), 'strict' (never — the setup then comes from the operator)."):
        ("mfa_enrollment={kind!r} gibt es nicht. Erlaubt sind {allowed}: 'first_login' (Vorgabe, "
         "erlaubt bis zum ersten vollständigen Login), 'grace' (erlaubt "
         "mfa_enrollment_grace_days ab Kontoanlage), 'strict' (nie — die Einrichtung kommt dann "
         "vom Betreiber)."),
    ("oidc_clients is set, but forward_auth_enabled is False. The approval per application "
     "is checked in /auth/forward — without forward auth it arises at login, but is "
     "afterwards queried by nothing."):
        ("oidc_clients ist gesetzt, forward_auth_enabled aber False. Die Freigabe je Anwendung "
         "wird in /auth/forward geprüft — ohne Forward-Auth entsteht sie beim Login, wird "
         "danach aber von nichts abgefragt."),
    ("{where} is not in trusted_redirect_hosts. The login URL for this application is then "
     "built on base_url instead of on the requested host — without cookie_domain the "
     "session cookie is host-only, and the sign-in goes round in circles."):
        ("{where} ist nicht in trusted_redirect_hosts. Die Login-URL für diese Anwendung wird dann "
         "auf base_url gebaut statt auf den angefragten Host — ohne cookie_domain gilt das "
         "Sitzungs-Cookie host-only, und die Anmeldung dreht sich im Kreis."),
    ("{where} names an issuer of its own. Several providers in one installation are not "
     "intended: discovery document, JWKS and the mapping issuer+sub→account hang on the one "
     "oidc_issuer. A second provider needs a second instance."):
        ("{where} nennt einen eigenen issuer. Mehrere Provider in einer Installation sind nicht "
         "vorgesehen: Discovery-Dokument, JWKS und die Zuordnung issuer+sub→Konto hängen am "
         "einen oidc_issuer. Für einen zweiten Provider braucht es eine zweite Instanz."),
    ("{where} has no client_secret. The exchange of the authorization code then fails at the "
     "provider, and only after the sign-in — that is, at the point where nobody suspects a "
     "configuration gap any more."):
        ("{where} hat kein client_secret. Der Tausch des Autorisierungs-Codes scheitert dann beim "
         "Provider, und zwar erst nach der Anmeldung — also an der Stelle, an der niemand mehr "
         "eine Konfigurationslücke vermutet."),
    ("{where} has no client_id. Without it there is no client at the provider for this "
     "application — and thus no approval of its own."):
        ("{where} hat keine client_id. Ohne sie gibt es für diese Anwendung keinen Client beim "
         "Provider — und damit auch keine eigene Freigabe."),
    ("oidc_revalidate_minutes={n} means: re-check at the provider every {hours} hours. The "
     "field counts minutes — was the period meant in seconds (one hour = 60, not 3600)? If "
     "the long period is intended, it stays at this warning."):
        ("oidc_revalidate_minutes={n} heisst: Nachprüfung beim Provider alle {hours} Stunden. "
         "Das Feld zählt Minuten — war die Frist in Sekunden gemeint (eine Stunde = 60, nicht "
         "3600)? Ist die lange Frist gewollt, bleibt es bei dieser Warnung."),
    ("oidc_revalidate_minutes={n}, but oidc_clients is empty. The re-check concerns the "
     "approval per application — without several clients there is none, and the value stays "
     "without effect. Probably session_ttl_hours (lifetime of the session) or "
     "stepup_max_age_sec (freshness for sensitive routes) was meant."):
        ("oidc_revalidate_minutes={n}, aber oidc_clients ist leer. Die Nachprüfung betrifft die "
         "Freigabe je Anwendung — ohne mehrere Clients gibt es keine, und der Wert bleibt "
         "folgenlos. Gemeint war vermutlich session_ttl_hours (Lebensdauer der Sitzung) oder "
         "stepup_max_age_sec (Frische für heikle Routen)."),
    ("oidc_clients names {hosts}, but oidc_enabled is False. The host→client mapping would "
     "have no effect: there would be no OIDC path through which an approval could arise."):
        ("oidc_clients nennt {hosts}, aber oidc_enabled ist False. Die Zuordnung Host→Client "
         "wäre wirkungslos: Es gäbe keinen OIDC-Weg, über den eine Freigabe entstehen könnte."),
    ("{fields} begins with the prefix of base_url ({prefix}). These fields are app paths "
     "without the prefix — TinySesam puts it in front itself since 0.21, otherwise "
     "{prefix}{prefix}/… results. Remove the prefix from the value."):
        ("{fields} beginnt mit dem Präfix der base_url ({prefix}). Diese Felder sind Pfade der "
         "App ohne Präfix — TinySesam setzt ihn seit 0.21 selbst davor, sonst entsteht "
         "{prefix}{prefix}/…. Den Präfix aus dem Wert nehmen."),
    ("federation_name_binding_days={days}: for {sources}, an unbound account is bound "
     "indefinitely via its name. A dormant account (someone has left) then falls to the "
     "next person who gets the same name in the directory — together with roles and admin "
     "right. Better: bind the existing accounts once "
     "(auth.federation_bind_existing(source), first as a dry run) and keep the default (30)."):
        ("federation_name_binding_days={days}: {sources} binden ein ungebundenes Konto "
         "unbegrenzt über seinen Namen. Ein ruhendes Konto (jemand ist ausgeschieden) fällt "
         "dann an die nächste Person, die im Verzeichnis denselben Namen bekommt — samt Rollen "
         "und Admin-Recht. Besser: den Bestand einmal binden "
         "(auth.federation_bind_existing(source), erst als Trockenlauf) und die Vorgabe (30) "
         "lassen."),
    ("ldap_user_filter searches via {attr}, but ldap_email_trusted=False: whoever signs in "
     "with their {attr} value gets a substitute name (ldap-…) instead of this value as the "
     "account name and is never matched to an existing account by name; without a stable "
     "identifier (ldap_attr_id) the sign-in is rejected."):
        ("ldap_user_filter sucht über {attr}, aber ldap_email_trusted=False: Wer sich mit "
         "seinem {attr}-Wert anmeldet, bekommt einen Ersatznamen (ldap-…) statt dieses Werts "
         "als Kontonamen und wird nie über den Namen einem vorhandenen Konto zugeordnet; ohne "
         "stabile Kennung (ldap_attr_id) wird die Anmeldung abgewiesen."),
    ("admin_identifiers names the address(es) {addrs}, and {sources} counts as a trusted "
     "source (*_email_trusted=True or a proof attribute *_attr_email_verified): whoever "
     "holds one of these addresses as proven there becomes first admin at the first login. "
     "That is only right if nobody can change their address (or the proof attribute) in "
     "this source themselves (no self-service for the mail attribute, no IdP with "
     "self-registration) — otherwise turn both off and use /auth/claim-admin."):
        ("admin_identifiers nennt die Adresse(n) {addrs}, und {sources} gilt als vertraute "
         "Quelle (*_email_trusted=True oder ein Beleg-Attribut *_attr_email_verified): Wer dort "
         "eine dieser Adressen belegt trägt, wird beim ersten Login Erst-Admin. Das ist nur "
         "richtig, wenn niemand seine Adresse (bzw. das Beleg-Attribut) in dieser Quelle selbst "
         "ändern kann (kein Self-Service für das mail-Attribut, kein IdP mit "
         "Selbstregistrierung) — sonst beides aus und /auth/claim-admin."),
    ("admin_identifiers names the address(es) {addrs}, and accounts are created at the "
     "first login by {sources} itself, without the operator trusting the addresses of this "
     "source (*_email_trusted=False, no *_attr_email_verified). Through these paths the "
     "address NEVER becomes the first admin — the address is not used there at all. The "
     "proven way is the one-time token: sign in, then /auth/claim-admin (see "
     "admin_claim_ttl_min); after that the first admin assigns the rights themselves."):
        ("admin_identifiers nennt die Adresse(n) {addrs}, und {sources} legt Konten beim ersten "
         "Login selbst an, ohne dass der Betreiber den Adressen dieser Quelle traut "
         "(*_email_trusted=False, kein *_attr_email_verified). Über diese Wege wird die Adresse "
         "NIE zum Erst-Admin — die Adresse wird dort gar nicht verwendet. Der belegte Weg ist "
         "das Einmal-Token: anmelden, dann /auth/claim-admin (s. admin_claim_ttl_min); danach "
         "vergibt der Erst-Admin die Rechte selbst."),
    ("admin_claim_token_file is set, but the token path is off (admin_claim_ttl_min=0 or "
     "admin_enabled=False) — the file is never written. The first admin then only comes "
     "about via admin_identifiers or an own call of auth.ensure_admin(…) — the CLI cannot "
     "create accounts."):
        ("admin_claim_token_file ist gesetzt, aber der Token-Weg ist aus (admin_claim_ttl_min=0 "
         "oder admin_enabled=False) — die Datei wird nie geschrieben. Der Erst-Admin kommt dann "
         "nur über admin_identifiers oder einen eigenen Aufruf von auth.ensure_admin(…) "
         "zustande — das CLI kann keine Konten anlegen."),
    ("admin_claim_token_file and security_log point to the same file. The first-admin "
     "one-time token would then end up again in the log that fail2ban reads, logrotate "
     "archives and a log shipper takes along — whoever reads it becomes admin. Use a file "
     "of its own for the token (e.g. /run/<service>/admin-claim.token) or leave the field "
     "empty, then the value goes to stderr."):
        ("admin_claim_token_file und security_log zeigen auf dieselbe Datei. Damit stünde das "
         "Erst-Admin-Einmal-Token wieder in dem Log, das fail2ban liest, logrotate archiviert "
         "und ein Log-Versand mitnimmt — wer es liest, wird Admin. Für den Token eine eigene "
         "Datei nehmen (z.B. /run/<dienst>/admin-claim.token) oder das Feld leer lassen, dann "
         "geht der Wert auf stderr."),
    ("base_url is empty, but this function builds absolute addresses: {functions}. Without "
     "a checked base the redirect stays relative — that holds as long as app and login page "
     "live under the same host. For SSO across several hosts set base_url (and "
     "cookie_domain)."):
        ("base_url ist leer, aber diese Funktion baut absolute Adressen: {functions}. Ohne "
         "geprüfte Basis bleibt die Umleitung relativ — das trägt, solange App und Login-Seite "
         "unter demselben Host liegen. Für SSO über mehrere Hosts base_url (und cookie_domain) "
         "setzen."),
    ("base_url is empty, but these functions hand an absolute address to third parties: "
     "{functions}. The only source left would be the Host header of the respective request "
     "— and that is set by the requester (with a mail to a foreign mailbox, therefore the "
     "attacker). Remedy: set base_url to the public address of this app, e.g. "
     "base_url=\"https://auth.example.com\" (locally base_url=\"http://127.0.0.1:8000\"). "
     "Mounted under a subpath, the prefix belongs in it (\"https://example.com/sso\"). "
     "trusted_redirect_hosts is NOT a substitute for this: if more than one host is listed "
     "there, the requester decides via the Host header which of them ends up in the link."):
        ("base_url ist leer, aber diese Funktionen geben eine absolute Adresse in fremde Hand: "
         "{functions}. Als Quelle bliebe der Host-Header der jeweiligen Anfrage — den setzt der "
         "Anfragende (bei einer Mail an ein fremdes Postfach also der Angreifer). Abhilfe: "
         "base_url auf die öffentliche Adresse dieser App setzen, z.B. "
         "base_url=\"https://auth.example.com\" (lokal base_url=\"http://127.0.0.1:8000\"). "
         "Unter einem Unterpfad montiert gehört das Präfix mit hinein "
         "(\"https://example.com/sso\"). trusted_redirect_hosts ist dafür KEIN Ersatz: Steht "
         "dort mehr als ein Host, bestimmt der Anfragende per Host-Header, welcher davon in den "
         "Link kommt."),
    ("base_url={base!r} is not a usable base address (expected e.g. "
     "\"https://auth.example.com\", with a subpath \"https://example.com/sso\"). Required "
     "are scheme http/https and a host; not allowed are user info in the host, a query (?) "
     "or fragment (#), an invalid port and a path with \"..\" or \"//\". Every link built "
     "from it would be broken — without an error, without a log line, only at the recipient."):
        ("base_url={base!r} ist keine brauchbare Basis-Adresse (erwartet z.B. "
         "\"https://auth.example.com\", mit Unterpfad \"https://example.com/sso\"). Verlangt "
         "sind Schema http/https und ein Host; nicht erlaubt sind Benutzerangabe im Host, "
         "Abfrage (?) oder Fragment (#), ein unzulässiger Port und ein Pfad mit \"..\" oder "
         "\"//\". Jeder daraus gebaute Link wäre kaputt — ohne Fehler, ohne Logzeile, erst beim "
         "Empfänger."),
    ("base_url={base!r} is used as {canon!r} — the address is not in the form in which it "
     "appears in links. Please enter exactly the second value, so that configuration and "
     "reality say the same."):
        ("base_url={base!r} wird als {canon!r} verwendet — die Adresse ist nicht in der Form, "
         "in der sie in Links steht. Bitte genau den zweiten Wert eintragen, damit "
         "Konfiguration und Wirklichkeit dasselbe sagen."),
    ("allow_signup=True next to ldap_enabled=True: whoever registers with the name or the "
     "address of a person from the directory before that person has signed in locks them "
     "out under this identifier (an identifier belongs to exactly one account). Turn "
     "registration off and create accounts in the admin panel or with auth.create_user(...)."):
        ("allow_signup=True neben ldap_enabled=True: Wer sich mit dem Namen oder der Adresse "
         "einer Person aus dem Verzeichnis registriert, bevor sie sich angemeldet hat, sperrt "
         "sie unter dieser Kennung aus (eine Kennung gehört genau einem Konto). Registrierung "
         "ausschalten und Konten im Admin-Panel bzw. mit auth.create_user(...) anlegen."),
    ("allow_signup=True with password_enabled=False creates accounts that can never sign in "
     "— registration assigns a password, and password login is off."):
        ("allow_signup=True mit password_enabled=False legt Konten an, die sich nie anmelden "
         "können — die Registrierung vergibt ein Passwort, und der Passwort-Login ist aus."),
    ("password_reset_enabled=True, but magiclink_enabled=False. The routes are mounted, but "
     "the link \"Forgot password?\" does not appear on the login page — the feature is on "
     "and reachable for nobody."):
        ("password_reset_enabled=True, aber magiclink_enabled=False. Die Routen sind montiert, "
         "der Link „Passwort vergessen?\" erscheint auf der Login-Seite aber nicht — die "
         "Funktion ist an und für niemanden erreichbar."),
    ("login_chain={chain} with login_chain_strict=False names 'pin' behind another factor, "
     "and pin_login=True offers the PIN as a first factor at the same time: whoever starts "
     "with it guesses it without the password, and a self-service reset clears these failed "
     "attempts from the series (account_max_consecutive_failures). If the PIN is meant to "
     "be only a follow-up factor: pin_login=False — the PIN step after the first factor "
     "stays reachable."):
        ("login_chain={chain} mit login_chain_strict=False nennt 'pin' hinter einem anderen "
         "Faktor, und pin_login=True bietet die PIN zugleich als Erstfaktor an: Wer mit ihr "
         "beginnt, rät sie ohne das Passwort, und ein Selbstbedienungs-Reset räumt diese "
         "Fehlversuche aus der Serie (account_max_consecutive_failures). Soll die PIN nur "
         "Folgefaktor sein: pin_login=False — der PIN-Schritt nach dem ersten Faktor bleibt "
         "erreichbar."),
    "login_chain requires 'totp', but totp_enabled=False — unsatisfiable.":
        "login_chain verlangt 'totp', aber totp_enabled=False — unerfüllbar.",
    ("login_chain requires {steps}, but {switches} — the chain is unsatisfiable, nobody "
     "gets past this step."):
        ("login_chain verlangt {steps}, aber {switches} — die Kette ist unerfüllbar, niemand "
         "kommt über diesen Schritt hinaus."),
    ("login_chain has empty steps or alternatives: {steps}. A step names one factor or several "
     "separated by '|', e.g. 'password|passkey'."):
        ("login_chain hat leere Schritte oder Alternativen: {steps}. Ein Schritt nennt einen Faktor "
         "oder mehrere, getrennt durch '|', z. B. 'password|passkey'."),
    ("login_chain={chain} cannot be satisfied: one factor satisfies at most one step, and the steps "
     "name too few different factors."):
        ("login_chain={chain} ist unerfüllbar: Ein Faktor erfüllt höchstens einen Schritt, und die "
         "Schritte nennen zu wenige verschiedene Faktoren."),
    ("magiclink_first_login_only=True, but magiclink_enabled=False: there are no sign-in links "
     "whose use the switch could limit."):
        ("magiclink_first_login_only=True, aber magiclink_enabled=False: Es gibt keine "
         "Anmeldelinks, deren Gebrauch der Schalter begrenzen könnte."),
    "login_chain names steps that are not a factor: {steps}{hint}. Allowed are {allowed}.":
        ("login_chain nennt Schritte, die kein Faktor sind: {steps}{hint}. Erlaubt sind "
         "{allowed}."),
    ("ldap_bind_dn is set, ldap_bind_password is empty. This is not an anonymous search: "
     "ldap3 rejects a DN without a password, the error only occurs at login and looks there "
     "like a wrong password for every user. Either set the password of the service account "
     "or empty ldap_bind_dn (then the search really is anonymous)."):
        ("ldap_bind_dn ist gesetzt, ldap_bind_password ist leer. Das ist keine anonyme Suche: "
         "ldap3 lehnt DN ohne Passwort ab, der Fehler fällt erst beim Login an und sieht dort "
         "für jeden Nutzer wie ein falsches Passwort aus. Entweder das Passwort des "
         "Dienstkontos setzen oder ldap_bind_dn leeren (dann wird wirklich anonym gesucht)."),
    ("{method}=True, but {empty} is empty. The method cannot work that way and fails at the "
     "first sign-in attempt — unless the client is replaced at runtime."):
        ("{method}=True, aber {empty} ist leer. So kann das Verfahren nicht arbeiten und "
         "scheitert beim ersten Anmeldeversuch — es sei denn, der Client wird zur Laufzeit "
         "ersetzt."),
    ("The configuration check names fields that do not exist in TinySesamConfig: {fields}. "
     "This is a bug in TinySesam itself — please report it."):
        ("Die Konfigurationsprüfung nennt Felder, die es in TinySesamConfig nicht gibt: "
         "{fields}. Das ist ein Fehler in TinySesam selbst — bitte melden."),
    ("ldap_enabled=True, but password_enabled=False. LDAP has no form of its own, it checks "
     "the password field of the login page against the directory — without "
     "password_enabled=True nobody signs in via LDAP."):
        ("ldap_enabled=True, aber password_enabled=False. LDAP hat kein eigenes Formular, es "
         "prüft das Passwortfeld der Login-Seite gegen das Verzeichnis — ohne "
         "password_enabled=True meldet sich niemand über LDAP an."),
    ("Not a single login method is enabled — the login page would have no field at all, "
     "nobody can sign in. At least one of: {fields} (for PIN also pin_login=True, otherwise "
     "it is only step-up). LDAP alone is not enough: ldap_enabled=True checks the password "
     "form against the directory and therefore needs password_enabled=True."):
        ("Keine einzige Anmelde-Methode ist eingeschaltet — die Login-Seite hätte kein einziges "
         "Feld, niemand kann sich anmelden. Mindestens eines von: {fields} (bei PIN zusätzlich "
         "pin_login=True, sonst ist sie nur Step-up). LDAP allein genügt nicht: "
         "ldap_enabled=True prüft das Passwortformular gegen das Verzeichnis und braucht "
         "deshalb password_enabled=True."),
    ("cookie_prefix={p!r} with forward_auth_enabled=True: the proxy templates strip only "
     "tinysesam_* cookies in front of the app — the session of this gateway would then "
     "reach every protected app. A gateway stays at cookie_prefix=\"tinysesam_\"; the "
     "prefix is for the app behind it."):
        ("cookie_prefix={p!r} mit forward_auth_enabled=True: Die Proxy-Vorlagen entfernen nur "
         "tinysesam_*-Cookies vor der App — die Sitzung dieses Gateways käme dann bei jeder "
         "geschützten App an. Ein Gateway bleibt bei cookie_prefix=\"tinysesam_\"; das Präfix "
         "ist für die App dahinter."),
    ("cookie_prefix={p!r}: 1–32 characters of letters, digits, _ and -, starting with a "
     "letter or a digit (e.g. \"myapp_\")"):
        ("cookie_prefix={p!r}: 1–32 Zeichen aus Buchstaben, Ziffern, _ und -, am Anfang ein "
         "Buchstabe oder eine Ziffer (z. B. \"meineapp_\")"),
    ("c22_stylesheet: {s!r} — a path on the app's own origin (\"/static/c22.css\"), "
     "without quotation marks, angle brackets, backslash and spaces"):
        ("c22_stylesheet: {s!r} — ein Pfad auf dem eigenen Ursprung der App (\"/static/c22.css\"), "
         "ohne Anführungszeichen, spitze Klammern, Backslash und Leerzeichen"),
    "{f}: {v!r} — each entry is a (title, target) pair with a title of 1–60 characters":
        "{f}: {v!r} — jeder Eintrag ist ein Paar (Titel, Ziel) mit einem Titel aus 1–60 Zeichen",
    "{f}: {v!r} — the visibility is {{\"admin\": True}} or {{\"role\": \"name\"}}":
        "{f}: {v!r} — die Sichtbarkeit ist {{\"admin\": True}} oder {{\"role\": \"name\"}}",
    ("{f}: the link {title!r} is shown only to the role {role!r}, which is not in "
     "available_roles — a typo hides it from everyone. List the role in available_roles."):
        ("{f}: Der Link {title!r} erscheint nur für die Rolle {role!r}, die nicht in available_roles "
         "steht — ein Tippfehler versteckt ihn vor allen. Die Rolle in available_roles eintragen."),
    ("{f}: {h!r} — a target is a path on the own origin (\"/wiki\") or an https address on the host of "
     "base_url or of trusted_redirect_hosts, without quotation marks, angle brackets, backslash and spaces"):
        ("{f}: {h!r} — ein Ziel ist ein Pfad auf dem eigenen Ursprung (\"/wiki\") oder eine "
         "https-Adresse auf dem Host von base_url oder von trusted_redirect_hosts, ohne Anführungszeichen, "
         "spitze Klammern, Backslash und Leerzeichen"),
    "topbar_menu_links: {n} entries — more than 10 run off the screen of the account menu":
        "topbar_menu_links: {n} Einträge — mehr als 10 laufen über den Rand des Kontomenüs",
    "brand_icon_title: at most 200 characters of text without control characters":
        "brand_icon_title: höchstens 200 Zeichen Text ohne Steuerzeichen",
    ("brand_icon_title works only with an image in brand_icon (a path or data:image/…) — the "
     "built-in mark and \"none\" carry no title"):
        ("brand_icon_title wirkt nur mit einem Bild in brand_icon (ein Pfad oder data:image/…) — das "
         "eingebaute Zeichen und \"none\" tragen keinen Titel"),
    "brand_background_credit_url: only http(s) addresses":
        "brand_background_credit_url: nur http(s)-Adressen",
    "brand_backgrounds: {b!r} — allowed are /path, data:image/… and https://…":
        "brand_backgrounds: {b!r} — erlaubt sind /pfad, data:image/… und https://…",
    ("brand_backgrounds: {b!r} — an address without quotation marks, parentheses, backslash "
     "and spaces (it ends up in a CSS url())"):
        ("brand_backgrounds: {b!r} — eine Adresse ohne Anführungszeichen, Klammern, Backslash "
         "und Leerzeichen (sie landet in einer CSS-url())"),
    " and ":
        " und ",
    "none":
        "keine",
    "Magic-link sign-in":
        "Magic-Link-Anmeldung",
    "\"Forgot password\"":
        "„Passwort vergessen\"",
    "Email confirmation at registration":
        "E-Mail-Bestätigung bei der Registrierung",
    "Magic link and invitation (link in the email)":
        "Magic-Link und Einladung (Link in der Mail)",
    "\"Forgot password\" (reset link in the email)":
        "„Passwort vergessen\" (Reset-Link in der Mail)",
    "Email confirmation (confirmation link in the email)":
        "E-Mail-Bestätigung (Bestätigungslink in der Mail)",
    "OIDC (redirect URI to the IdP)":
        "OIDC (Redirect-URI zum IdP)",
    "SAML (entity ID and ACS URL)":
        "SAML (Entity-ID und ACS-URL)",
    "Forward auth (redirect of the proxy to the login page)":
        "Forward-Auth (Umleitung des Proxys auf die Login-Seite)",
    ("qr_login_enabled=True, but base_url is empty. The QR code needs the public address and "
     "is never built from the Host header — the login page then shows only the short code, which "
     "the user types on the signed-in device. Set base_url for the QR code."):
        ("qr_login_enabled=True, aber base_url ist leer. Der QR-Code braucht die öffentliche "
         "Adresse und wird nie aus dem Host-Header gebaut — die Login-Seite zeigt dann nur den "
         "Kurzcode, den man auf dem angemeldeten Gerät eintippt. Für den QR-Code base_url setzen."),
    ("The group maps assign the roles {roles}, but available_roles is empty: the admin panel then "
     "offers a free-text field instead of checkboxes, and a typo there creates a role nothing checks. "
     "List the roles in available_roles."):
        ("Die Gruppenzuordnungen vergeben die Rollen {roles}, aber available_roles ist leer: Das Admin-Panel "
         "bietet dann ein Freitextfeld statt Ankreuzfeldern, und ein Tippfehler dort legt eine Rolle an, die "
         "nichts prüft. Die Rollen in available_roles eintragen."),
    ("admin_require_mfa=False: the admin panel (and require_admin) work from any old admin "
     "session without a fresh confirmation — such a session sets passwords, issues sign-in "
     "links for any account and grants admin rights. Leave it on (the default) unless another "
     "layer asks again."):
        ("admin_require_mfa=False: Das Admin-Panel (und require_admin) arbeiten aus jeder alten "
         "Admin-Sitzung ohne frische Bestätigung — eine solche Sitzung setzt Passwörter, stellt "
         "Anmeldelinks für jedes Konto aus und vergibt Admin-Rechte. Eingeschaltet lassen (Vorgabe), "
         "außer eine andere Schicht fragt erneut."),
    ("login_chain contains 'magic', but magiclink_self_request=False: the chain step leads to "
     "/auth/magic/request, which does not exist then (404). The step can only be satisfied with "
     "a link issued by the admin or by app code."):
        ("login_chain enthält 'magic', aber magiclink_self_request=False: Der Kettenschritt führt "
         "zu /auth/magic/request, das es dann nicht gibt (404). Erfüllen lässt er sich nur mit "
         "einem Link, den der Admin oder App-Code ausstellt."),
    ("csp={value!r} — probably {intended!r} (lower case) is meant. As written it would be a "
     "custom policy without a directive, and the browser would run without any CSP."):
        ("csp={value!r} — gemeint ist wohl {intended!r} (klein geschrieben). So wäre es eine "
         "eigene Policy ohne Direktive, und der Browser liefe ohne jede CSP."),
    ("csp={value!r} is neither 'strict' nor 'off' nor a policy with a known directive. The "
     "browser discards such a header, and the pages would run without any CSP."):
        ("csp={value!r} ist weder 'strict' noch 'off' noch eine Policy mit einer bekannten "
         "Direktive. Der Browser verwirft so einen Header, und die Seiten liefen ohne jede CSP."),
    ("csp={value!r} contains directives that TinySesam does not know: {unknown}. The "
     "browser skips what it does not know and applies the rest — with a typo, the intended "
     "rule therefore does not apply."):
        ("csp={value!r} enthält Direktiven, die TinySesam nicht kennt: {unknown}. Der Browser "
         "überspringt, was er nicht kennt, und wendet den Rest an — bei einem Tippfehler gilt "
         "die gemeinte Regel also nicht."),
    " — LDAP satisfies the step 'password', not 'ldap'":
        " — LDAP erfüllt den Schritt 'password', nicht 'ldap'",
    "cookie_samesite={value!r} — allowed are 'lax', 'strict', 'none' (lower case)":
        "cookie_samesite={value!r} — erlaubt sind 'lax', 'strict', 'none' (klein geschrieben)",
    "cookie_samesite='none' without cookie_secure=True — the browser discards such a cookie":
        "cookie_samesite='none' ohne cookie_secure=True — der Browser verwirft so ein Cookie",
    "https_mode={value!r} — allowed are 'off', 'warn', 'force'":
        "https_mode={value!r} — erlaubt sind 'off', 'warn', 'force'",
    "csp must be a string, is {type}":
        "csp muss ein String sein, ist {type}",
    ("https_mode='force' with cookie_secure=False — the session cookie would go out without "
     "the Secure flag"):
        ("https_mode='force' mit cookie_secure=False — das Sitzungs-Cookie ginge ohne "
         "Secure-Flag hinaus"),
    ("admin_delegates: {v!r} — a mapping of delegate role → {{\"roles\": [role, …]}} with optional "
     "\"manages\" (delegate roles below it) and \"can\" (a part of the actions); at least one role or one "
     "managed delegate role"):
        ("admin_delegates: {v!r} — eine Zuordnung Delegiertenrolle → {{\"roles\": [Rolle, …]}} mit optionalem "
         "\"manages\" (Delegiertenrollen darunter) und \"can\" (ein Teil der Aktionen); mindestens eine Rolle "
         "oder eine verwaltete Delegiertenrolle"),
    ("admin_delegates: {role!r} is not a delegate role — \"admin\" is how forward auth "
     "names the admin flag in Remote-Groups"):
        ("admin_delegates: {role!r} ist keine Delegiertenrolle — \"admin\" heißt bei Forward-Auth "
         "das Admin-Flag in Remote-Groups"),
    ("admin_delegates: the role {role!r} is not in available_roles — list every "
     "delegate role and every role it manages there"):
        ("admin_delegates: Die Rolle {role!r} steht nicht in available_roles — jede Delegiertenrolle "
         "und jede Rolle, die sie verwaltet, dort eintragen"),
    ("admin_delegates: the delegate role {role!r} stands in the roles of {owner!r} "
     "— a delegate role is appointed only through \"manages\""):
        ("admin_delegates: Die Delegiertenrolle {role!r} steht in den Rollen von {owner!r} "
         "— eine Delegiertenrolle wird nur über \"manages\" ernannt"),
    ("admin_delegates: {owner!r} manages {role!r}, which is not a delegate role — "
     "\"manages\" names delegate roles (keys of admin_delegates)"):
        ("admin_delegates: {owner!r} verwaltet {role!r}, das keine Delegiertenrolle ist — "
         "\"manages\" nennt Delegiertenrollen (Schlüssel von admin_delegates)"),
    ("admin_delegates: {owner!r} can {action!r}, which is no action — allowed are "
     "{actions}"):
        ("admin_delegates: {owner!r} darf {action!r}, das ist keine Aktion — erlaubt sind "
         "{actions}"),
    ("admin_delegates: {role!r} manages itself through \"manages\" (a cycle) — "
     "a delegate role is never above itself"):
        ("admin_delegates: {role!r} verwaltet sich über \"manages\" selbst (ein Zyklus) — "
         "eine Delegiertenrolle steht nie über sich selbst"),
    ("admin_delegates is set, but admin_enabled=False: the panel is not mounted at "
     "admin_path. Mount auth.admin_router() yourself, or delegates have no panel."):
        ("admin_delegates ist gesetzt, aber admin_enabled=False: Das Panel hängt nicht unter "
         "admin_path. auth.admin_router() selbst einhängen, sonst haben Delegierte kein Panel."),
    ("role_levels: {v!r} — a list of ladders {{\"name\": …, \"label\": …, \"levels\": [{{\"name\": "
     "…, \"label\": …, \"role\": \"prefix{{1}}suffix\"}}, …]}}, at least two levels, names and templates unique"):
        ("role_levels: {v!r} — eine Liste von Leitern {{\"name\": …, \"label\": …, \"levels\": [{{\"name\": …, "
         "\"label\": …, \"role\": \"präfix{{1}}suffix\"}}, …]}}, mindestens zwei Stufen, Namen und Vorlagen eindeutig"),
    ("role_levels: {ladder!r} level {level!r}: the role {role!r} holds a comma or a "
     "control character — Remote-Groups would read it as other roles"):
        ("role_levels: {ladder!r} Stufe {level!r}: Die Rolle {role!r} enthält ein Komma oder ein "
         "Steuerzeichen — Remote-Groups läse sie als andere Rollen"),
    ("role_levels: the templates {a!r} ({la!r}) and {b!r} ({lb!r}) can match the "
     "same role — every role belongs to one ladder at most"):
        ("role_levels: Die Vorlagen {a!r} ({la!r}) und {b!r} ({lb!r}) können dieselbe Rolle "
         "treffen — jede Rolle gehört höchstens zu einer Leiter"),
    ("role_levels: {ladder!r}: the templates {a!r} and {b!r} can match the same role "
     "and are equally specific — which entry a role belongs to would be a guess"):
        ("role_levels: {ladder!r}: Die Vorlagen {a!r} und {b!r} können dieselbe Rolle treffen "
         "und sind gleich spezifisch — zu welchem Eintrag eine Rolle gehört, wäre geraten"),
    ("role_levels: {ladder!r} has no entry among the known roles (available_roles, role "
     "catalog) — the panel shows no levels for it"):
        ("role_levels: {ladder!r} hat keinen Eintrag unter den bekannten Rollen (available_roles, "
         "Rollenkatalog) — das Panel zeigt dafür keine Stufen"),
    ("role_levels: {ladder!r}: the role {role!r} belongs to the entry {key!r} "
     "and to another one — rename the role or the template"):
        ("role_levels: {ladder!r}: Die Rolle {role!r} gehört zum Eintrag {key!r} "
         "und zu einem anderen — Rolle oder Vorlage umbenennen"),
    ("role_levels: {ladder!r} entry {key!r}: {roles} not among the known roles — the "
     "levels from there up are not offered"):
        ("role_levels: {ladder!r} Eintrag {key!r}: {roles} nicht unter den bekannten Rollen — "
         "die Stufen ab dort werden nicht angeboten"),
    ("role_levels: the delegate role {delegate!r} manages {held} but not "
     "every role below — it cannot grant that level of {key!r}"):
        ("role_levels: Die Delegiertenrolle {delegate!r} verwaltet {held}, aber nicht "
         "jede Rolle darunter — sie kann diese Stufe von {key!r} nicht vergeben"),
    ("apps: {v!r} — a mapping of application id → {{\"account\": service account, "
     "\"name\": …, \"provisioning\": {{…}}}}"):
        ("apps: {v!r} — eine Zuordnung Anwendungskennung → {{\"account\": Dienstkonto, "
         "\"name\": …, \"provisioning\": {{…}}}}"),
    ("apps: the id {app!r} — lower-case letters, digits and _ , starting with a letter, "
     "at most 32 characters"):
        ("apps: Die Kennung {app!r} — Kleinbuchstaben, Ziffern und _ , beginnend mit einem Buchstaben, "
         "höchstens 32 Zeichen"),
    "apps[{app!r}]: {v!r} — allowed members are {keys}":
        "apps[{app!r}]: {v!r} — erlaubt sind {keys}",
    ("apps[{app!r}]: \"account\" must name the service account (is_service) whose "
     "automation keys speak for the application"):
        ("apps[{app!r}]: \"account\" muss das Dienstkonto (is_service) nennen, dessen "
         "Automation-Keys für die Anwendung sprechen"),
    ("apps: {a!r} and {b!r} name the same service account {account!r} — it would "
     "be unclear for which application a key speaks"):
        ("apps: {a!r} und {b!r} nennen dasselbe Dienstkonto {account!r} — es wäre "
         "unklar, für welche Anwendung ein Key spricht"),
    ("apps[{app!r}]: \"name\" is a text or a mapping language → text "
     "({{\"en\": \"Example\", \"de\": \"Example\"}})"):
        ("apps[{app!r}]: \"name\" ist ein Text oder eine Zuordnung Sprache → Text "
         "({{\"en\": \"Example\", \"de\": \"Example\"}})"),
    "apps[{app!r}].provisioning: {v!r} — allowed members are {keys}":
        "apps[{app!r}].provisioning: {v!r} — erlaubt sind {keys}",
    ("apps[{app!r}].provisioning.roles: a non-empty list of roles the application "
     "may grant (its allowlist)"):
        ("apps[{app!r}].provisioning.roles: eine nicht leere Liste der Rollen, die die Anwendung "
         "vergeben darf (ihre Allowlist)"),
    ("apps[{app!r}].provisioning.roles: \"admin\" is never grantable by an "
     "application — forward auth reads it as the admin flag"):
        ("apps[{app!r}].provisioning.roles: \"admin\" vergibt eine Anwendung nie — "
         "Forward-Auth liest es als Admin-Flag"),
    ("apps[{app!r}].provisioning.roles: {role!r} is a delegate role "
     "(admin_delegates) — an application key never appoints delegates"):
        ("apps[{app!r}].provisioning.roles: {role!r} ist eine Delegiertenrolle "
         "(admin_delegates) — ein Anwendungs-Key ernennt nie Delegierte"),
    ("apps[{app!r}].provisioning.roles: {role!r} is assigned by a group map — the "
     "next sign-in would overwrite what the application set (two sources of one "
     "truth)"):
        ("apps[{app!r}].provisioning.roles: {role!r} vergibt eine Gruppen-Abbildung — die "
         "nächste Anmeldung überschriebe, was die Anwendung gesetzt hat (zwei Quellen einer "
         "Wahrheit)"),
    ("apps[{app!r}].provisioning.roles: {role!r} contains a comma, a control "
     "character or surrounding spaces — Remote-Groups would read it as other "
     "roles"):
        ("apps[{app!r}].provisioning.roles: {role!r} enthält ein Komma, ein Steuerzeichen "
         "oder Leerzeichen am Rand — Remote-Groups läse sie als andere Rollen"),
    "apps[{app!r}].provisioning.roles: {role!r} is not in available_roles":
        "apps[{app!r}].provisioning.roles: {role!r} steht nicht in available_roles",
    ("apps[{app!r}].provisioning.roles: {role!r} does not begin with "
     "{prefix!r} — such a role may also open something else, e.g. a gate "
     "rule of another application"):
        ("apps[{app!r}].provisioning.roles: {role!r} beginnt nicht mit "
         "{prefix!r} — eine solche Rolle öffnet vielleicht auch anderes, etwa eine Gate-"
         "Regel einer anderen Anwendung"),
    ("apps: {a!r} and {b!r} share the role {role!r} — each application "
     "grants what opens the other"):
        ("apps: {a!r} und {b!r} teilen sich die Rolle {role!r} — jede Anwendung "
         "vergibt, was die andere öffnet"),
    "apps[{app!r}].provisioning.scopes: a non-empty list of {scopes}":
        "apps[{app!r}].provisioning.scopes: eine nicht leere Liste aus {scopes}",
    ("apps[{app!r}]: the scope users:invite needs magiclink_enabled=True — "
     "otherwise no route redeems the one-time link"):
        ("apps[{app!r}]: Der Scope users:invite braucht magiclink_enabled=True — "
         "sonst löst keine Route den Einmal-Link ein"),
    ("apps[{app!r}]: the scope users:invite needs base_url — the one-time link "
     "is built from it, never from the Host header"):
        ("apps[{app!r}]: Der Scope users:invite braucht base_url — der Einmal-Link "
         "wird daraus gebaut, nie aus dem Host-Header"),
    ("apps[{app!r}].provisioning.link_ttl_min={v!r} — 1 to signin_link_max_ttl_min "
     "({max})"):
        ("apps[{app!r}].provisioning.link_ttl_min={v!r} — 1 bis signin_link_max_ttl_min "
         "({max})"),
    "apps[{app!r}].provisioning.max_accounts={v!r} — 1 to {max}":
        "apps[{app!r}].provisioning.max_accounts={v!r} — 1 bis {max}",
    "apps[{app!r}].provisioning.delete_grace_days={v!r} — 0 (at once) to {max} days":
        "apps[{app!r}].provisioning.delete_grace_days={v!r} — 0 (sofort) bis {max} Tage",
    "apps[{app!r}].provisioning.limits: {v!r} — numbers from 1 to {max} for {keys}":
        "apps[{app!r}].provisioning.limits: {v!r} — Zahlen von 1 bis {max} für {keys}",
    ("apps with provisioning and apikey_enabled=False: an application calls the account "
     "API with an automation key of its service account"):
        ("apps mit provisioning und apikey_enabled=False: Eine Anwendung ruft die Konten-API "
         "mit einem Automation-Key ihres Dienstkontos auf"),
    ("apps[{app!r}]: the scope users:reset needs provisioning.approver_role — the "
     "role of the people who may confirm a reset"):
        ("apps[{app!r}]: Der Scope users:reset braucht provisioning.approver_role — die "
         "Rolle der Personen, die ein Zurücksetzen bestätigen dürfen"),
    ("apps[{app!r}].provisioning.approver_role={v!r} — one role name without comma, "
     "control character or surrounding spaces"):
        ("apps[{app!r}].provisioning.approver_role={v!r} — ein Rollenname ohne Komma, "
         "Steuerzeichen oder Leerzeichen am Rand"),
    ("apps[{app!r}].provisioning.approver_role: \"admin\" is the admin flag, not a "
     "role — name the role of the people who confirm a reset"):
        ("apps[{app!r}].provisioning.approver_role: \"admin\" ist das Admin-Flag, keine "
         "Rolle — nenne die Rolle der Personen, die ein Zurücksetzen bestätigen"),
    "apps[{app!r}].provisioning.approver_role: {role!r} is not in available_roles":
        "apps[{app!r}].provisioning.approver_role: {role!r} steht nicht in available_roles",
    ("apps[{app!r}].provisioning.approver_role: {role!r} stands in the allowlist "
     "of {other!r} — an application key could give it to an account it created, "
     "sign in with that account's one-time link and confirm the reset itself"):
        ("apps[{app!r}].provisioning.approver_role: {role!r} steht in der Allowlist "
         "von {other!r} — ein Anwendungs-Key könnte sie einem selbst angelegten Konto geben, "
         "sich über dessen Einmal-Link anmelden und das Zurücksetzen selbst bestätigen"),
    ("apps[{app!r}].provisioning.approver_role: {role!r} may be granted by the "
     "delegates of {delegate!r} (admin_delegates) — they appoint who confirms a "
     "reset of the application's accounts"):
        ("apps[{app!r}].provisioning.approver_role: {role!r} dürfen die Delegierten "
         "von {delegate!r} vergeben (admin_delegates) — sie ernennen, wer ein Zurücksetzen "
         "der Konten der Anwendung bestätigt"),
    ("apps[{app!r}].provisioning.approver_role is set, but the scope users:reset "
     "is missing — nobody can ask for a reset, the role has no effect here"):
        ("apps[{app!r}].provisioning.approver_role ist gesetzt, aber der Scope users:reset "
         "fehlt — niemand kann ein Zurücksetzen anfragen, die Rolle wirkt hier nicht"),
    ("apps[{app!r}]: the scope users:reset needs approvals_enabled=True — the reset is "
     "an approval the approver confirms in the browser"):
        ("apps[{app!r}]: Der Scope users:reset braucht approvals_enabled=True — das Zurücksetzen "
         "ist eine Freigabe, die der Freigeber im Browser bestätigt"),
    ("apps[{app!r}]: the scope users:reset needs magiclink_enabled=True — the new "
     "one-time link is the only way back into the account"):
        ("apps[{app!r}]: Der Scope users:reset braucht magiclink_enabled=True — der neue "
         "Einmal-Link ist der einzige Weg zurück ins Konto"),
    ("apps[{app!r}]: the scope users:reset with magiclink_first_login_only=True and "
     "no login_chain — the door would refuse the new link of an account that has "
     "signed in before"):
        ("apps[{app!r}]: Der Scope users:reset mit magiclink_first_login_only=True und "
         "ohne login_chain — die Tür wiese den neuen Link eines Kontos ab, das schon "
         "angemeldet war"),
    ("apps[{app!r}]: the scope users:reset needs base_url — the one-time link is "
     "built from it, never from the Host header"):
        ("apps[{app!r}]: Der Scope users:reset braucht base_url — der Einmal-Link wird "
         "daraus gebaut, nie aus dem Host-Header"),
    ("admin_path='/auth' with apps: /auth/api/ is reserved for the machine APIs — the "
     "panel's JSON would lie under /auth/api/users, the path of the account API"):
        ("admin_path='/auth' mit apps: /auth/api/ ist für die Maschinen-APIs reserviert — das "
         "JSON des Panels läge unter /auth/api/users, dem Pfad der Konten-API"),
}
