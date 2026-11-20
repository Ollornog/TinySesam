# Home network — a domain, or HTTPS on a bare IP address

TinySesam needs HTTPS outside of `localhost`: its cookies are `Secure` (`__Host-` prefix), and OAuth clients
refuse a token endpoint over plain HTTP unless it is a loopback address. In a home network that raises the question
of where the certificate comes from. This page answers it in two ways — **a domain (recommended)** and, if that is
really not possible, **a bare IP address with a CA of your own**. The template for the second way is
[`deploy/home-network/`](../deploy/home-network/).

Local development needs neither: `http://127.0.0.1:8000` and `http://localhost:8000` count as a secure context in
browsers, and OAuth clients accept loopback over HTTP (RFC 8252). The configuration check therefore stays silent for
them and warns only for other IP addresses in `base_url`.

## Recommended: a domain

With a domain of your own, Caddy gets a **publicly trusted** certificate from Let's Encrypt — no device needs
anything installed, phones and guests included. This works even when the name resolves **only inside your network**:
the DNS-01 challenge proves control over the domain through a TXT record at your DNS provider, and Let's Encrypt never
has to reach your server.

1. Register a domain (or use a subdomain of one you have), e.g. `home.example.com`.
2. Point the names at your server **inside** your network: a local DNS entry in the router, Pi-hole/AdGuard,
   or a public A record with the private address. Some routers block answers with private addresses (DNS rebinding
   protection) — allow the domain there.
3. Use a Caddy build with the module of your DNS provider ([caddy-dns](https://github.com/caddy-dns)) — one build
   argument to [`deploy/forward-auth/caddy-gate/Dockerfile`](../deploy/forward-auth/caddy-gate/Dockerfile):
   `docker build --build-arg CADDY_EXTRA_MODULES=github.com/caddy-dns/<provider> -t caddy-gate-dns
   deploy/forward-auth/caddy-gate` — and give it an API token of the provider, scoped to that one zone. The quickstart
   stack ([`deploy/quickstart/`](../deploy/quickstart/)) does this with `TS_TLS=dns`; by hand it looks like this:

   ```caddyfile
   auth.home.example.com {
   	tls {
   		dns <provider> {env.DNS_API_TOKEN}
   	}
   	reverse_proxy tinysesam:8000
   }
   ```

4. Use the normal templates in [`deploy/forward-auth/`](../deploy/forward-auth/) — subdomains, `cookie_domain`,
   everything as described there.

Good to know: every publicly trusted certificate is listed in the public Certificate Transparency logs, names
included (addresses are not). A wildcard certificate (`*.home.example.com`) shows only the wildcard.

A domain also keeps **passkeys** possible. WebAuthn refuses them on an IP address outright — the specification
allows only domain names as the host of the origin (Web Authentication Level 3, §5.1.3), whichever certificate is used.

## Fallback: a bare IP address

If it has to be the IP, Caddy's local CA (`tls internal`) issues and renews the certificate for the address itself
(Subject Alternative Name = IP). Every device then has to trust that CA **once**.

### Start the template

The template is an override for the reference stack — it keeps its hardening and pins and changes only what an IP
needs. In both files of [`deploy/home-network/`](../deploy/home-network/), replace the documentation address
`192.0.2.10` with the LAN address of your server, set your provider in `TINYSESAM_OIDC_ISSUER`, then from the
repository root:

```bash
docker compose -f deploy/forward-auth/docker-compose.yml -f deploy/home-network/docker-compose.yml up -d
```

Shorter: the quickstart stack ([`deploy/quickstart/`](../deploy/quickstart/)) does the same with `TS_TLS=ip` in its
`.env` — the IP as `TS_AUTH_HOST` and `TS_APP_HOST`, `TS_APP_PORT=8443`, `TS_COOKIE_DOMAIN` empty — including an example
application behind the gate. The steps below (exporting and trusting the root) apply to both; with the quickstart the
service is called `caddy` in `deploy/quickstart/docker-compose.yml`.

The sign-in runs at `https://192.0.2.10`, the protected application at `https://192.0.2.10:8443`. A bare IP has no
subdomains, so applications are separated by port; cookies are not separated by port (RFC 6265, section 8.5), so one
sign-in covers all of them. The TinySesam settings this needs:

| Setting | Value | Why |
|---|---|---|
| `base_url` | `https://192.0.2.10` | the sign-in page, port 443 |
| `cookie_domain` | empty | browsers reject a `Domain` attribute that names an IP address; host-only covers every port |
| `trusted_redirect_hosts` | `["192.0.2.10"]` | the host is compared without the port, so the application on `:8443` is included |

If you embed TinySesam in your own app instead of running the gateway, the first site block of the
[Caddyfile](../deploy/home-network/Caddyfile) is all you need: it terminates TLS and passes everything to your app.

Two details in the Caddyfile matter and are easy to lose when adapting it:

- **`default_sni`** — clients send no SNI for an IP address. Caddy then picks the certificate by the address the
  connection arrived at, which inside a Docker bridge network is the container's address. Without `default_sni` the
  handshake fails (`tlsv1 alert internal error`; measured with Caddy 2.11.9).
- **Keep the volume `caddy-data`.** It holds the CA. A new volume is a new root, and every device would have to
  trust it again.

Validity with Caddy's defaults: root 10 years, intermediate 7 days, leaf 12 hours. Only the root is distributed;
the others renew themselves.

### Export the root certificate

```bash
docker compose -f deploy/forward-auth/docker-compose.yml -f deploy/home-network/docker-compose.yml \
  cp caddy:/data/caddy/pki/authorities/local/root.crt ./tinysesam-home-root.crt
openssl x509 -in tinysesam-home-root.crt -noout -subject -fingerprint -sha256
```

Distribute this file — it contains no secret. The key (`root.key`) stays in the volume: whoever has it can issue
certificates that all your devices trust, for **any** name. Compare the fingerprint on each device before you trust it.

### Trust it on every device

| Device | How |
|---|---|
| **Windows** | `certutil -addstore -f Root tinysesam-home-root.crt` (administrator), or double-click → *Install Certificate* → *Local Machine* → *Trusted Root Certification Authorities*. Chrome and Edge use this store. |
| **macOS** | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain tinysesam-home-root.crt`. Safari and Chrome use it. |
| **Linux (Debian, Ubuntu, Mint)** | `sudo cp tinysesam-home-root.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates` (the file must end in `.crt`). |
| **Linux (Fedora, RHEL)** | `sudo cp tinysesam-home-root.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust`. |
| **Chrome/Chromium on Linux** | reads its own NSS database: `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n tinysesam-home -i tinysesam-home-root.crt` (package `libnss3-tools`). |
| **Firefox** | own store on every system: *Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import*, tick "Trust this CA to identify websites". |
| **Android** | *Settings → Security → Encryption & credentials → Install a certificate → CA certificate* (the path differs by manufacturer). Browsers accept it; many apps do not trust user-installed CAs since Android 7. |
| **iOS / iPadOS** | Send the file to the device and open it, install the profile under *Settings → General → VPN & Device Management*, then switch on full trust under *Settings → General → About → Certificate Trust Settings*. |
| **Claude Code** | It trusts the operating system store by default (native installer; npm installs from Node 22.15). Otherwise point it at the file: `export NODE_EXTRA_CA_CERTS=/path/to/tinysesam-home-root.crt` in the shell, or in the `env` block of Claude Code's user settings file (`settings.json`, see Claude Code's settings documentation) as `"NODE_EXTRA_CA_CERTS": "/path/to/tinysesam-home-root.crt"` — the settings file also reaches background sessions. |
| **Other Node.js tools** | `NODE_EXTRA_CA_CERTS` as above. |
| **Python tools (httpx, requests)** | `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` — note that these **replace** the public list: use a bundle of the public roots plus this one. |

### The provider on the same CA

The gateway talks to the OIDC provider itself. A provider with a public domain needs nothing. If the provider also
runs behind this Caddy on an IP address, the gateway has to trust the root as well: mount a bundle (the public roots
plus `tinysesam-home-root.crt`) into the `tinysesam` container and set `SSL_CERT_FILE` to it. The bundle must keep the
public roots — `SSL_CERT_FILE` replaces the built-in list rather than adding to it.

### Limits of the IP way

- **Every new device needs the CA** — phones of guests, a new laptop, a reinstalled system.
- **No passkeys.** WebAuthn does not allow an IP address as the host; only password, PIN, sign-in links and OIDC
  work. Moving to a domain later makes passkeys possible — they are then registered fresh on the domain.
- **The address must not change.** Give the server a fixed address (DHCP reservation); a new address means a new
  certificate name and new links.
- **Connectors from the cloud do not reach it.** Remote connectors added in the Claude web app or Claude Desktop are called
  from Anthropic's servers, not from your device — a server inside your network is unreachable for them, with an IP
  address just as with a name that resolves only at home. Claude Code on a device in your network does reach it.
