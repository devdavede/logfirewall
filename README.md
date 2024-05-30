# logfirewall
Analysetool für Apache2 Server-Requests zur Erkennung schädlichen Verhaltens

## Intro
Nachdem mein WordPress trotz aktueller Updates und aller möglichen Sicherheitsmaßnahmen gehackt wurde hielt ich es für sinnvoll, die Requests, welche an meinen Apache2 Server gesendet werden, zu analysieren.
Immer wieder tauchen im Log Einträge auf, welche darauf schließen lassen, dass jemand versucht die Domains auf meinem vServer nach Schwachstellen zu scannen.
Diese Requests sahen z.B. so aus:

[Mon May 27 05:40:23.137769 2024] [php:error] [pid 4418] [client ***:51419] script '/var/www/html/lv.php' not found or unable to stat
[Mon May 27 05:40:27.114070 2024] [php:error] [pid 4417] [client ***:59348] script '/var/www/html/seo.php' not found or unable to stat
[Mon May 27 05:40:31.253972 2024] [php:error] [pid 4416] [client ***:50104] script '/var/www/html/x.php' not found or unable to stat
[Mon May 27 05:40:38.161927 2024] [php:error] [pid 4300] [client ***:57796] script '/var/www/html/b0x.php' not found or unable to stat
[Mon May 27 05:40:43.448057 2024] [php:error] [pid 4498] [client ***:50992] script '/var/www/html/about.php' not found or unable to stat
[Mon May 27 05:40:48.281329 2024] [php:error] [pid 4419] [client ***:58221] script '/var/www/html/cloud.php' not found or unable to stat

Um dem einen Riegel vorzuschieben hatte ich es zunächst mit einer "Firewall" auf HTACCESS Basis versucht - es wurden alle Anfragen die zu einem 404 Response führen durch ein PHP Script geloggt und bei einem erhöhten Auftreten solcher Anfragen ein Captcha ausgegeben.
Das hat zwar grundlegend funktioniert, war aber nicht die schönste Art und Weise das Problem zu lösen.
So kam die Idee zur Logbasierten Firewall, welche tendenziell alle Arten von Anfragen analysieren kann und ggfs. den Nutzer aussperrt.

## Bitte beachten
Die Pfade zu allen Dateien müssen ggfs. angepasst werden!

## Struktur
Die .conf Datei des vHosts schreibt die Access-Logs nicht mehr in eine Datei sondern piped die Ausgabe an ein Python-Skript. Das Skript loggt die Anfrage weiterhin in den Access-Log, analysiert sie aber gleichzeitig und bei auffälligem Nutzerverhalten wird die Nutzer-IP in einer Blacklist gespeichert und Anfragen mit einem 403 beantwortet.

## Setup
### vHost - Config
Die vHost Configs liegen idR. unter folgendem Pfad:
/etc/apache2/sites-available

Hier muss im VirtualHost Knoten des Dokuments folgender Eintrag hinterlegt werden:

`
CustomLog "|<PfadZuPython> <PfadZuFirewall.py>" combined
`

in meinem Fall z.B.:

`
CustomLog "|/usr/bin/python3 /home/ubuntu/logfirewall.py" combined
`

Das führt dazu, dass neue Logeinträge an die logfirewall.py gepiped werden.

### Apache2 Config
Die Apache2 Config muss ebenfalls angepasst werden.
Diese befindet sich bei mir unter /etc/apache2/apache2.conf

Folgende Einträge müssen am Ende hinzugefügt werden (und die Pfade ggfs. angepasst werden):

`
RewriteMap access txt:/var/www/blocked_ips.conf
<Location />
   <RequireAll>
      Require all granted
      Include /home/ubuntu/firewall/ipblacklist.conf
   </RequireAll>
</Location>
`

Was passiert hier? Zunächst erzeugen wir eine RewriteMap. Das bedeutet, dass wir in den HTACCESS Dateien unserer VirtualHosts darauf zugreifen können.
In der Datei "/var/www/blocked_ips.conf" stehen später die IP Adressen, welche von der HTACCESS Datei blockiert werden sollen.

In den nächsten Zeilen legen wir fest, dass der Server Anfragen von Adressen blockiert, welche in der ipblacklist.conf hinterlegt wurden.
Leider liest der Apache Webserver diese Datei nur bei einem Restart ein und Änderungen werden nicht AdHoc übernommen.
Daher ist zusätzlich die Blockierung über HTACCESS Dateien notwendig (gibt es einen besseren Weg? Vielleicht...).

### HTACCESS Datei der Webseite
Der Apache Server kann IP-Blacklists integrieren. Allerdings werden Änderungen der Blacklist nicht sofort übernommen sondern erst nach einem Neustart des Servers. Um sofort auf schädliches Verhalten zu reagieren muss (ich bin offen für elegantere Vorschläge) in der HTACCESS Datei aller Virtual Hosts (oder auf globaler Ebene) folgender Eintrag hinterlegt sein:

`
RewriteEngine On
RewriteCond ${access:%{REMOTE_ADDR}} deny [NC]
RewriteRule ^ - [L,F]
`
## Was passiert jetzt?
Die Logfirewall ist aktuell sehr trivial und auf meine Bedürfnisse angepasst.
Aktuell wird nach 10 fehlgeschlagenen HTTP Requests (404 Response) der Nutzer blockiert.
Ebenfalls dann, wenn eine eindeutig verdächtige URL aufgerufen wird. Die Liste der URLs habe ich aus meinen Access Logs extrahiert und muss für deine Bedürfnisse auf jeden Fall angepasst werden.


