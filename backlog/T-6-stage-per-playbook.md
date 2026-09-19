---
id: T-6
type: Task
title: Die E2E-Bühne per Playbook aufbauen statt von Hand
status: erledigt
milestone: M-1
tags: [e2e, deploy, testlab]
created: 2026-09-19
---

# T-6 — Die Bühne für `e2e_stage.py` reproduzierbar machen

[T-1](T-1-e2e-gegen-echten-idp.md) hat bewiesen, dass die drei Ceremony-Wege gegen echte
Gegenstellen laufen. Die Instanz dafür wurde allerdings **von Hand** eingerichtet: Zertifikat
verteilen, Reverse-Proxy, Dienst, IdP mit Realm-Import, Konfiguration. Beim nächsten Mal ist das
wieder Handarbeit — und was genau lief, weiss nur, wer dabei war.

**Fertig, wenn:** ein Lauf aus einem frischen Wegwerf-Container die vollständige Bühne baut
(Proxy + Dienst + IdP + Konfiguration), `e2e_stage.py` danach grün durchläuft, und ein zweiter
Lauf nichts mehr ändert. Adressen und Zugangsdaten kommen dabei aus der Umgebung, nicht aus dem
Repo.

**Beachten:** Der Peer-Name des Wegwerf-Containers ist nicht stabil, solange der alte Peer nicht
aufgeräumt wird — sonst wandert eine Kennung in den Namen und die beim Provider registrierte
Redirect-URI passt nicht mehr.

## Erledigt (2026-09-19)

Ein Lauf baut aus einem frischen Wegwerf-Container die vollständige Bühne: Peer mit festem Namen,
Zertifikat, Reverse-Proxy, eigener SAML-Provider, Anwendung mit allen drei Anmeldewegen. Danach
läuft `tests/e2e_stage.py` grün dagegen; der zweite Lauf meldet `changed=0`.

Das Playbook liegt im Deploy-Repo, nicht hier — es ist Infrastruktur, und Adressen wie
Zugangsdaten gehören ohnehin nicht in ein öffentliches Repo. Von hier aus führt nur der Aufruf
hin: erst die Bühne bauen, dann `STAGE_BASE_URL=… python tests/e2e_stage.py`.

Die Warnung oben hat sich bestätigt, und schärfer als erwartet: Der Name wird **auch dann** mit
einer Kennung versehen, wenn er frei ist. Repariert wird das durch Umbenennen über die API — aber
nur, wenn sich der Name dabei ändert; ein Schreibvorgang mit demselben Namen rechnet das Label
nicht neu. Der Umweg über einen Zwischennamen steht als Kommentar im Playbook.
