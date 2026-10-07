---
id: T-18
type: Task
title: Wackeltest test_vorbuchung_schwebe — einmal rot im CI-Job repeat, Ursache offen
status: erledigt
milestone: M-2
tags: [tests, wackeltest, ci, parallel]
created: 2026-09-28
---

# T-18 — `test_vorbuchung_schwebe.py` war einmal rot, ohne dass zu sehen war, woran

**Befund.** Im CI-Job `repeat` von PR #108 (Lauf 36360175849, Commit 4c7ba7e, `ubuntu-latest`,
2 Test-Jobs, FastAPI 0.141.1) war `test_vorbuchung_schwebe.py` einmal rot: `42 ok, 1 Fehler`.
Welche Prüfung scheiterte, stand nicht im Protokoll. `tests/run_all.py` zeigte nur die letzten
2000 Zeichen der Ausgabe, und die `FEHL`-Zeile stand davor. Das ist seit PR #108 behoben: Unter
`FAIL` stehen jetzt alle `FEHL`-Zeilen (`tests/test_testlauf.py` I).

**Eingegrenzt.** Der sichtbare Ausschnitt begann bei der Prüfung „is_locked an der Serien-Grenze …
als Aufschub“, und von dort an war alles grün. Die gescheiterte Prüfung steht also **davor**, in
den Abschnitten (a) erstes Fenster, R7-2-Salve, verwaiste Vorbuchungen, (d) paralleler Login an
der Grenze oder (d3) Aufschub an der Serien-Grenze. Drei davon warten mit einem festen
`time.sleep(HAENGT * 0.4)` darauf, dass die parallelen Anmeldungen im hängenden Verzeichnis
angekommen sind. Unter Last kann das zu kurz sein.

**Nicht nachzustellen.** Lokal 20× ohne Last und 30× unter Volllast (12 Busy-Loops auf 12
Threads) grün, und in zwei weiteren CI-Läufen desselben PRs auch `repeat` grün.

## Offen

- [ ] Beim nächsten roten Lauf die `FEHL`-Zeile aus dem Protokoll holen, die Anzeige ist jetzt da.
- [ ] Liegt es an einer Wartestelle: nicht die Zeit verlängern, sondern auf den Zustand warten
      (`Verzeichnis.fragen` bzw. die Zahl schwebender Vorbuchungen, mit Frist) und das Hängen
      des Verzeichnisses so lange halten, bis der Test es freigibt.

## Erledigt 2026-10-07

Seit PR #108 nicht wieder rot gesehen (die `FEHL`-Zeile wäre seitdem im Protokoll). Umgesetzt ist der
zweite Punkt, ohne auf den nächsten roten Lauf zu warten:

- Alle sechs festen Wartestellen (`time.sleep(HAENGT * 0.4)`, `* 0.3`, `0.15`) warten jetzt mit
  `warte_bis()` auf den Zustand, den die Prüfung danach liest: die Zahl der Anläufe, die im Verzeichnis
  angekommen sind (`Verzeichnis.fragen`), mit Frist und benanntem Fehler.
- **Nicht** umgesetzt: das Verzeichnis „hängen lassen, bis der Test freigibt“. In (d), (d3) und (h)
  gehen die parallelen Anmeldungen selbst ins Verzeichnis. Eine Freigabe erst nach ihrem Ergebnis hätte
  sie gegenseitig blockiert, und die Zeitprüfungen in (a) und (e) hängen an der Hängedauer. Das Warten
  auf die Ankunft beseitigt die vermutete Ursache (gelesen, bevor alle da waren) ohne diesen Umbau.
- Beleg: 3 Läufe ohne Last, 15 Läufe unter Volllast (12 Busy-Loops auf 12 Threads), alle grün. Wird
  die Suite trotzdem wieder rot, steht die `FEHL`-Zeile im Protokoll — dann ein neuer Bug-Eintrag mit
  ihr.
