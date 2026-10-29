"""The German words the English-code guard (`tests/test_english_code.py`) looks for.

One word list, two uses: in an IDENTIFIER (function, class, variable, parameter, constant, attribute, module and file
name) every word counts, split at `_`, `.` and CamelCase; in running TEXT (comments, docstrings) only the words that are
no English word (`ENGLISH_HOMOGRAPHS` are left out there: `art`, `stand`, `hand`, `fall` ...). Transliterations
(`ae oe ue ss`) are spelled the way the code spelled them. Add a word here when the guard lets a German word through
(the self-test in the guard proves that a listed word is found); remove one only when it turns out to be an English or
technical word.
"""

GERMAN_WORDS = frozenset("""
    ab abbild abbruch aber abfrage abfragen abgebrochen abgelaufen abgelaufene abgelehnt abgemeldet
    abgeschnitten abgesenkt abgestanden abgewiesen ablage ablauf ableiten abmelden abmeldungen abraeumen abrufe
    abschluss abschnitt abschnitte absenden absender absenken abstand abstuerze absturz abwarten abwehr
    abweichend abweichler abweichung abweichungen abweisen abweisung adresse adressen aend aenderung akt akteur
    aktiv aktive aktuell aktuelle aliase alle allein alles allgemein als alt alte altem altern altes altnamen
    altwert andere anderen anderer anderes anderswo anf anfang anforderung anforderungen anfr anfrage ang
    angeboten angekommen angemeldet angestossen angreifer angriff anhang anker ankercache anlage anlegen anm
    anmeldefluss anmeldelink anmelden anmeldend anmeldung anmeldungen annehmen anonym anonymisieren ansicht
    anteil antrag antw antwort antworten anw anwendung anzahl anzeige arbeit arbeiter argumente art artefakte
    arten atome attrappe attrappen attribut attributliste auch auf aufbau auffaellig auffrischbar aufgaben
    aufgeschoben aufheben aufloesen aufruf aufrufe auftraege auftrag aufwand aufzeichnen aus ausblenden ausdruck
    ausdruecklich ausfall ausfuehrbar ausgabe ausgang ausgefallen ausgefuehrt ausgelieferte ausgenommen
    ausgestellt auslassen ausloeser ausnahme ausnahmen ausreisser aussage aussen ausser ausserhalb ausstellen
    ausweg automat automatisch basis bau baue bauen baum baustein bausteine baut bauzeit bea beanspruchen
    beantragen beantragt bedingt bedingung bedingungen beenden befehl befehle befund befunde beginn beglaubigt
    behauptung bei beide beim beispiel beispiele bekannt bekannte bekanntgeben beleg belegen belegstelle
    belegstellen belegt belegte benutzer benutzt benutzte bereich bereiche bereits bericht beschreibung besetzt
    besitzer bestaetigen bestaetigt bestaetigung bestand bestimmen betr betreff betreffe betreiber betrieb
    betroffen beurteile beute bev bevor bewertet bezeichner bezeichnung bild bilder binaer bindung bindungsname
    bis blanke bleiben bleibt blockiert blockliste bloecke bnach boden boese braucht breit bremse bricht bruch
    brueche buchen bvorher chef chefin chiffrat cnach cvoll cvor damit danach dann darf darueber das dass datei
    dateien dateiliste dateirechte daten datum dauer davor dazu dazwischen daß deckel deckt deko dekoder dem den
    der des deutsch deutsche dieb dienst dienste diese direkt direktiven dok doku dokument doppelt dort dreht
    drei drin dritt dritter drittes drossel durch durchgerutscht dvorher echef echt echte echtes eig eigen
    eigene eigener eigenes eigenschaften eimer ein eindringling eine einem einen einer eines einfuegen
    einfuehrung eingabe eingebaut eingefroren eingeloest einladung einloesen einmal einreihen einrichten
    einrueckung eins einschreiben einschreibung einstellig eintraege eintrag einzug elf eltern empfaenger
    empfiehlt empfohlen ende endung endungen eng englisch entbehrlich entfernen entfernt entstand entstanden
    ereig ereignis ereignisse erfolg ergebnis ergebnisse ergebnistyp ergebnistypen erhalten erhoehen erlaubt
    erlaubte erledigt erledigten ermitteln erneuert erneut erreichbar erreicht ersatz ersatzname ersetze
    ersetzen ersetzt erst erste erster erstes erstlogin erw erwarte erwartet erwartetes erwartung erweitert
    erweiterungen erzwingen etwas exporte faeden faehrt faelle faengt fahren faktor faktoren fall falsch falten
    familie familien fang fassung fehl fehlalarm fehlen fehlend fehlende fehler fehlserie fehlserien fehlt
    fehlversuche feld felder feldstufen fenster fertig fest feste festhalten filterzeilen finde flach
    flugfenster foederation foederiert folge folgend folgt formate formatvarianten formen formfehler formular
    fort fortsetzen fortsetzung fotos frage fragen frei freier freigabe freigaben freigeben freigegeben
    freischalten freitext fremd fremde fremder fremdressourcen frisch frische frischer frist fristen frueher
    fruehere fuell fuelle fuenfzehn fuer fund funde funktion funktionen für ganz ganzzahl gast geaendert gebaut
    gebrauch gebucht gebunden gedreht geerbt gefaelscht gefahren gefaltet gefangen gefordert gefragt gefuehrt
    gefunden gegen gegenstand gegenstelle gegraftet geh gehaertete gehe geheim geheimnis geheimnisse gehoben
    geht geklickt geladen gelesen geloescht gemeinsam gemeint gemeldet gemeldete gemerkt gemessen gemessener
    gemischt genannt generalprobe generiert generisch genug gepinnt geprueft gepruefte geraten gerendert gerufen
    gesamt gescheitert geschickt geschlossen geschrieben geschuetzt gesegnet gesehen gesehene gesendet gesenkt
    gesetzt gesetzte gesichert gespeichert gesperrt gestempelt gestoert getrackte getrennt getroffen gewacht
    gewaehlt gewarnt gewartet geworfen gewuenscht gezeigt gilt gleich gleiche gleichwertig gleichzeitig glied
    gnade grenze grenzen grenzwerte gruende grund grundschluessel grundstock grundworte gruppe gruppen gueltig
    gueltige gut haben haengen haengend haengende haengendes haenger haengt haerte haertung haken halb harmlos
    hat hatte haupt heben heil helfer hell herkunft heute heutige hexzeichen hier hilfe hilft hinter
    hintergruende hintergrund hinweis hinweise hinweiszeilen hinzu hoch holung huelle hulle idempotenz
    identitaet identitaeten ignoriere ignoriert im infrastruktur inh inhaber inhaberin inhalt inhaltsfreie innen
    innere innerhalb instanz intern interne ist ja je jede jeden jetzt juengster juengstes jung kai kandidat
    kandidaten kann kanon kanonisch kanten kaputt kaputtes karte katalog kategorien kchef kein keine keks kenner
    kennung kennungen kennungs kern kerne kernen kette kettenschritt kettenschritte keydatei klammer klar
    klartext klasse klassen klein kleinste klemme klicks klient knapp knoepfe knopf knoten koepfe koerper
    kollege kollegen kollision kollisionen kombinationen kommandos kommentar kommentare komponenten konf konsole
    konst konstant konstanten konten kontext kontexte kontextteile konto kontoname kontrolle kopf kopfname
    kopfwert kopfzeilen kopie koppeln kreis kurz können lade laden laenge laeufer laeuft lage lange langsam lauf
    laufend launisch launisches lauschender lauscher lautlos lebt lecks leer leerlauf lehnt lesbar lesen lesend
    lesepfad leseweg lesewege letzte letzter liefern lies liste listenpunkt lizenzen locker loeschen
    loeschsperre loescht loeschziele logdatei lokal los luecke luecken lueckenhaft luegner mailfaeden mangel
    marke marken maske maskiert mehr mehrere mein melde melden meldung meldungen mensch merken merker merkmal
    messen messung messwert metadaten methode methoden mindestens mindestlaenge minuten misch mischer mit
    mitgebracht mitgeschickt mitschnitt mitschreiben mitschreibendes mitschrift modul modus moeglich muell muss
    muster mutationen mutiert müssen nach nachbinden nachbindung nachfolger nachgetragen nachher nachlauf
    nachpruefen nachricht nachrichten nachschub nachtraeglich nachtragen nachweis nachziehen nackt naechster
    nahm naiv namen namens namensbindung namensfrist namensraum namenswechsel nein nennt netz netze neu neue
    neuer neues neustart nfalsch nicht nichts nie nimm noch nochmal noetig normalisiere normalisieren normalo
    normiert notfall notiz nummer nur nurui nutzer nutzerinfo nutzlast nutzung oben oberflaeche obergrenze
    objekt objekte oder oeffentlich oeffentliche oeffne oeffnen oeffner oekosystem offen offene offener ohne
    operationen opfer optionale optionen ordner ort orte paar paare paket paketdateien paketimporte passend
    passender passt passwort pauschal pfad pfade pfadname pflicht pflichtdateien pflichtfelder pinbereich
    plaetze platz platzhalter plausibel postausgang posten praefix praefixe privat privater proben probleme
    produktionswerte produktiv profil projekt projekte protokoll protokollieren prozess pruef pruefe pruefen
    pruefendes pruefer prueffunktionen pruefung pruefungen publikum puffer quell quelle quellen quellmail
    quelltext quelltexte quer raeumgrenze rang raus recht rechte rechts regel regeln registrieren regulierung
    reihe reihen reihenfolge reservieren reserviert restzeit richtig riegel roh rohdaten rohe rolle rollen rollt
    rot routen rueck rueckfall rueckkehr rueckstand ruf rufe ruht rumpf runden rundgang saat salve sammel
    sammellauf sammelt sammler satz sauber schalter schief schl schlecht schliessen schliesst schloss schluessel
    schluss schmutzig schnipsel schnitt schon schranke schreib schreibbar schreiben schreibend schreiber
    schreibprobe schreibt schreibvorgaenge schreibweise schreibzugriff schrift schriften schritt schritte
    schuetzt schutz schwach schwanz schwebe schweben schwebend schwelle schwere segmente sehr seine seit seite
    seiten seitenaufruf seitenname seitentitel sek sekunde sekunden selbst selbstpruefung selbsttest senden
    senke senken sensibel serie seriell serien setze setzen setzer setzt sich sichere sicherheit sicherheits
    sicherheitsereignisse sichern sicht signatur signiert signierte sind sitzung sitzungen sitzungs
    sitzungswirkung skript skripte soll sollen sondern sortier spaet spaeter spalte spalten spanne speichern
    sperre sperren sperrhinweis sperrliste sperrlisten sperrt spezifikation spiegel spion sprache sprachen
    sprachmails spur spuren stabil stabile stamm stand stapel starten startreihenfolge startseite statisch steht
    stelle stellen stempel stern steuerzeichen stichworte stille stimmt streng strikt struktur stueck stuecke
    stufe stufen stumm suche suchen suiten summe tabelle tabellen taeter tage takt tausch tausche teil teile
    teilstring testdateien testverzeichnis texte textpruefung tief tiefe titel toepfe tokdatei tokenzeilen
    toleranz topf tor tore tot toter traeger treff treffen treffer treffpunkt trenner tresor trifft trocken
    tueren typ typen ueber ueberall uebergang ueberlauf ueberschattet ueberschreibt ueberschrieben ueberschrift
    ueberschriften uebersehen uebersetzung uebersetzungs uebersprungen uebrig uebrige uhr umbenannt umbinden
    umfang umfeld umg umgebung umgebungsnamen umgelenkt umgeschrieben umhaengen umlaute umleiten umleitung
    umleitungen umschreiben umweg unbefristet unbekannt unbelegt unbestaetigt unbestaetigte und uneingeordnet
    ungedeckt ungedrosselt ungepinnt ungerufen ungeschuetzt ungeschuetzte ungesehen ungueltig ungueltige unten
    unter untergeschoben untergrenze unterklasse ursprung variabel variablen varianten veraltet verbindung
    verbindungen verbindungs verbogen verboten verbrauchen verdaechtig verengung verfahren verfuegbar verg
    vergeben vergehen vergleich vergleiche verlange verloren vermerk vermerke veroeffentlichen veroeffentlicht
    versand versatz verschiebung verschluckt verschluesselt versende versionen versionsgleichstand versprochen
    verstoesse versuch versuche versuchsfrist vertrag vertragsnamen vertrauen vertraut vertraute vertreter
    verwaist verwaltet verwaltung verweigert verweis verweise verwerfen verz verzeichnis verzeichnisname
    verzeichnisse verzicht vierter viertes vierzehn vize vokabular voll vollstaendig vom von vor vorab
    vorbuchung vorbuchungen vorgabe vorgaben vorgebucht vorhanden vorhandene vorher vorlage vorlagen vormerken
    vorspann vorwaerts wachsen waechst wahr wahrheit wand wandernd war warf warnen warnfilter warnt warnung
    warnungen warte warten wartend wartende warteplaetze wartestelle wartestellen wartet warum wasserlinie wdh
    wechsel wechseln weg wege weich weil weiter weitere wenn wer werden werkzeug werkzeuge wert werte widerrufen
    wie wieder wiederholt wiederholung wird wirft wirkend wirkung wo woerter woerterbuch wofuer wohin wort worte
    wortgrenze wortweise wunsch wurde wurden wurzel zaehl zaehle zaehlen zaehlend zaehlende zaehler zaehlung
    zahl zahlen zahlengrenze zahlengrenzen zahlfelder zeichen zeichenketten zeile zeilen zeilenbrecher
    zeilenfest zeilennummern zeit zeiten zeitpunkt zeitstempel zelle zerlegen zert ziel ziele zielgruppe ziffern
    zonen zu zuerst zugang zukunft zuletzt zum zuordnen zuordnung zur zurueck zuruecknehmen zuruecksetzen
    zusaetzliche zusage zusammen zusatz zustand zuweisung zuweisungen zweck zwei zweier zweit zweite zweiten
    zweiter zweites zwischen zyklen über
""".split()) | frozenset("""
    bericht generierte mitarbeiter redaktion seite trockenlauf
""".split()) | frozenset(  # words found in string literals (test data, messages, snippets) by the string-literal follow-up
    """
    egal verdacht anders irgendwas buchhaltung nachtrag erfunden unbeteiligt rennen meine kasse firma garten ruhig
    doppel pech referenz richtiges vertippt laut frisches gedrosselt quatsch gesund langes deren vorne klassik
    zweifach sicherung jemand falsches sofort leute ruft akte statt aktuelles orakel geheime einfach misst einzige
    gutes leser immer angenommen vertrieb vorbei nachbar dritte vierte beendet benutzbar galt gibt erneuern
    absichtlich roten stellvertreter zeilenumbruch rotiert rechnet echter gelaufen gescheiterte oberhalb ausschnitts
    abwinkt voraussetzungen nachinstallieren auswahl tischlampe morgen brauchbar ewig halbstark telefon dieselbe
    lagre niemand blockte gelten liest weitergereicht redakteur beitritt wett scheitert rohes betreibers faltung
    sackgasse rauschen unsichtbar greifen wartung mandant gefeuert normales feststehend vergessen fortgeschrittene
    hinaus weniger billige menschen nachgestellte angriffe uhrzeit besucher kyrillisch chinesisch konfiguration
    fremden eigenen sieben einzel weder woanders viel weist anmelde topfs falscher richtiger speicher verschachtelt
    tippfehler eingebaute sickert entscheidungen nirgends neuling persistentes
""".split())

#: The words of `GERMAN_WORDS` that are also English words — counted in identifiers, not in English prose.
ENGLISH_HOMOGRAPHS = frozenset("""
    ab aber alles als alt altes art aus basis baum bis chef das datum dem den der des elf eng ersatz fall fang
    fest fort fund gilt gut hat hell hier hinter im intern interne jung kern klein knapp knopf lade laden leer
    lies locker los mit muss muster oder paar privater puffer quell rang rot salve seine sind spur stand stern
    tor tore tot toter und wand war wer
""".split())


# ── History context of the docs ──────────────────────────────────────────────────────────────────────────
# The English docs quote OLD names and values on purpose (migration tables, "up to 0.24.x `ja|nein`", rollback SQL).
# Both doc guards — `tests/test_english_code.py` (no German words) and `tests/test_repo.py` (no stale names) —
# exempt exactly those places and nothing else; this is the one definition of "a place that talks about the past".
import re as _re

#: A line talks about the past if it carries one of these: an old → new pair of backticked names, a version
#: number (`0.24.x`, `0.22.0`), "German", "schema 15", "formerly", "previously", "old name/value/spelling ...".
HISTORY_MARKER = _re.compile(
    r"`[^`\n]+`\s*→\s*`[^`\n]+`|\b0\.\d+\.[\dx]|\bGerman\b|\bschema \*{0,2}\d+|\bformerly\b|\bpreviously\b"
    r"|\bold (?:name|value|spelling|word|text)s?\b", _re.I)
#: Sections whose whole point is to name the old names (the rollback SQL and its tables).
HISTORY_SECTION = _re.compile(r"^#{1,6} Rollback")


def history_lines(text: str) -> set:
    """Line numbers (1-based) of a Markdown text that may name old names and German values.

    A line is exempt if it, or a neighbouring line of the same paragraph (a wrapped sentence puts the marker on the
    next line), carries a `HISTORY_MARKER`; a table row only counts for itself (one marker must not excuse the whole
    table); every line below a `## Rollback …` heading up to the next heading of the same or a higher level is exempt.
    """
    lines = text.split("\n")
    exempt, in_rollback, level, fence = set(), False, 0, False
    for n, line in enumerate(lines, 1):
        if line.startswith("```"):
            fence = not fence
        head = None if fence or line.startswith("```") else _re.match(r"^(#{1,6}) ", line)
        if head:
            if HISTORY_SECTION.match(line):
                in_rollback, level = True, len(head.group(1))
            elif in_rollback and len(head.group(1)) <= level:
                in_rollback = False
        if in_rollback:
            exempt.add(n)
            continue
        if line.lstrip().startswith("|"):
            if HISTORY_MARKER.search(line):
                exempt.add(n)
        else:
            near = " ".join(lines[max(0, n - 2):n + 1]) if lines[n - 1].strip() else ""
            if HISTORY_MARKER.search(near):
                exempt.add(n)
    return exempt
