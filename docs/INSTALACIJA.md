# Instalacija i prvi koraci

Ove upute vode od nule do aplikacije koja radi na tvom serveru s HTTPS-om, uz probu bez ijedne prave punionice.

**Sadržaj**

1. [Što ti treba](#1-što-ti-treba)
2. [Brza proba na vlastitom računalu (10 minuta)](#2-brza-proba-na-vlastitom-računalu)
3. [Instalacija na server](#3-instalacija-na-server)
4. [Prva prijava i osnovne postavke](#4-prva-prijava-i-osnovne-postavke)
5. [Proba sa simuliranom punionicom](#5-proba-sa-simuliranom-punionicom)
6. [Spajanje pravih punionica](#6-spajanje-pravih-punionica)
7. [Korisnici i RFID kartice](#7-korisnici-i-rfid-kartice)
8. [Održavanje: ažuriranje, backup, logovi](#8-održavanje)
9. [Rješavanje problema](#9-rješavanje-problema)

---

## 1. Što ti treba

| | |
|---|---|
| **Server** | Linux (preporuka Ubuntu 22.04 ili 24.04), 1 CPU, 1 GB RAM, 10 GB diska je dovoljno za desetke punionica. Može biti VPS (Hetzner, DigitalOcean, Contabo…) ili vlastiti server. |
| **Javna IP adresa** | Punionice se spajaju na server preko interneta (ili lokalne mreže). |
| **Domena** | Npr. `ocpp.tvrtka.hr`, s DNS **A zapisom** koji pokazuje na IP servera. Potrebna je za besplatni HTTPS certifikat (Let's Encrypt). |
| **Otvoreni portovi** | `80` i `443` (TCP). Ako je server iza routera, napravi port forwarding ta dva porta na server. |
| **SSH pristup** | Za upisivanje naredbi na serveru. |

Na serveru će raditi dva Docker kontejnera:

```
punionice ──wss://ocpp.tvrtka.hr/ocpp/<ID>──┐
                                           ├─► Caddy (443, HTTPS, Let's Encrypt) ─► aplikacija (web 8000, OCPP 9000)
preglednik ──https://ocpp.tvrtka.hr────────┘
```

Caddy sam nabavlja i obnavlja HTTPS certifikat, pa se o tome ne moraš brinuti.

---

## 2. Brza proba na vlastitom računalu

Ako želiš prvo vidjeti aplikaciju prije nego diraš server:

1. Instaliraj [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/Mac) ili Docker na Linuxu.
2. Preuzmi kod: na GitHubu otvori repozitorij → zeleni gumb **Code** → **Download ZIP**, pa raspakiraj. (Ili `git clone https://github.com/sinedr2108/ocpp-tidy-connect.git`.)
3. U mapi projekta napravi datoteku `.env` s ovim sadržajem:
   ```
   CSMS_SECRET_KEY=lokalna-proba
   CSMS_ADMIN_EMAIL=admin@example.com
   CSMS_ADMIN_PASSWORD=admin12345
   CSMS_PUBLIC_HOSTNAME=localhost
   ```
4. Otvori terminal (PowerShell na Windowsu) u toj mapi i pokreni:
   ```bash
   docker compose up -d --build
   ```
5. Otvori **http://localhost:8000** i prijavi se s `admin@example.com` / `admin12345`.
6. Napravi probno punjenje simulatorom kako je opisano u [poglavlju 5](#5-proba-sa-simuliranom-punionicom). Kod lokalne probe u naredbama koristi `docker compose` bez `-f docker-compose.prod.yml`.

Za gašenje: `docker compose down`. Podaci ostaju sačuvani za sljedeće pokretanje.

---

## 3. Instalacija na server

### 3.1 DNS

Kod registrara domene dodaj A zapis, npr. `ocpp` → `IP.TVOG.SERVERA`. Provjeri sa svog računala da `ping ocpp.tvrtka.hr` vraća IP servera. Promjena DNS-a ponekad treba i do sat vremena.

### 3.2 Spoji se na server

```bash
ssh korisnik@IP.TVOG.SERVERA
```

### 3.3 Instaliraj Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
exit        # odjavi se i ponovno spoji SSH-om da grupa "docker" vrijedi
```

Provjera nakon ponovnog spajanja: `docker compose version` mora ispisati verziju.

### 3.4 Vatrozid (ako koristiš ufw)

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

Kod VPS-a provjeri i vatrozid u web sučelju pružatelja usluge (npr. Hetzner Cloud Firewall).

### 3.5 Preuzmi kod

```bash
sudo mkdir -p /opt/ocpp && sudo chown $USER /opt/ocpp
git clone https://github.com/sinedr2108/ocpp-tidy-connect.git /opt/ocpp
cd /opt/ocpp
```

Ako je repozitorij **privatan**, git će tražiti korisničko ime i lozinku. Kao lozinku upiši GitHub *Personal access token*: GitHub → Settings → Developer settings → Personal access tokens → Fine-grained, s pravom *Contents: Read-only* samo za ovaj repozitorij.

### 3.6 Postavke (.env)

```bash
cp .env.example .env
openssl rand -hex 32        # kopiraj ispis za CSMS_SECRET_KEY
nano .env
```

Popuni barem:

| Varijabla | Primjer | Napomena |
|---|---|---|
| `CSMS_SECRET_KEY` | ispis iz `openssl rand -hex 32` | štiti prijave u sučelje |
| `CSMS_ADMIN_EMAIL` | `denis@tvrtka.hr` | prvi administrator |
| `CSMS_ADMIN_PASSWORD` | duga lozinka | promijenit ćeš je nakon prve prijave |
| `CSMS_PUBLIC_HOSTNAME` | `ocpp.tvrtka.hr` | mora biti ista domena kao u DNS-u |
| `CSMS_ACME_EMAIL` | `denis@tvrtka.hr` | Let's Encrypt šalje upozorenja o certifikatu |
| `CSMS_DEFAULT_PRICE` | `0.35` | EUR/kWh, kasnije se mijenja u sučelju |

Spremi (`Ctrl+O`, `Enter`) i izađi (`Ctrl+X`).

### 3.7 Pokreni

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Prvo pokretanje traje par minuta. Provjera:

```bash
docker compose -f docker-compose.prod.yml ps          # oba servisa "running" / "healthy"
docker compose -f docker-compose.prod.yml logs caddy  # traži "certificate obtained successfully"
```

Otvori **https://ocpp.tvrtka.hr**. Trebao bi se pojaviti ekran za prijavu s ispravnim HTTPS lokotom.

> Savjet: da ne pišeš stalno `-f docker-compose.prod.yml`, jednom upiši `echo "COMPOSE_FILE=docker-compose.prod.yml" >> .env`. Nakon toga je dovoljno `docker compose ...`.

---

## 4. Prva prijava i osnovne postavke

1. Prijavi se s e-mailom i lozinkom iz `.env`.
2. **Moj račun** → promijeni lozinku.
3. **Moj račun** → skeniraj QR kod u aplikaciji za autentifikaciju (Google Authenticator, Microsoft Authenticator, 1Password…), upiši kod i klikni **Uključi MFA**. Od sada prijava traži i 6-znamenkasti kod.
4. **Postavke** → upiši cijenu energije u EUR/kWh. Cijena se zaključava na početku svakog punjenja, a pojedina punionica može imati i svoju cijenu.

---

## 5. Proba sa simuliranom punionicom

Simulator se ponaša kao prava punionica: spoji se, autorizira karticu, puni i šalje mjerenja. Pokreće se unutar kontejnera na serveru, pa na računalu ne treba ništa instalirati.

**U sučelju:**

1. **Kartice** → dodaj karticu UID `04A1B2C3D4`, naziv "Test kartica", korisnik: ti.
2. **Punionice** → dodaj punionicu: ID `TEST-01`, proizvođač *Generički*, sigurnosni profil **1**. Kopiraj prikazanu lozinku (prikazuje se samo jednom).

**Na serveru** (zamijeni `LOZINKA` onom iz sučelja):

```bash
cd /opt/ocpp
docker compose -f docker-compose.prod.yml exec csms \
  python tools/simulator.py --url ws://localhost:9000/ocpp --id TEST-01 --password LOZINKA --tag 04A1B2C3D4
```

Očekivani ispis:

```
BootNotification: Accepted
Authorize: Accepted
StartTransaction id: 1
StopTransaction: 11.00 kWh
```

U sučelju na **Pregledu** sad vidiš punjenje od 11 kWh i iznos u eurima, a u **Izvještajima** potrošnju po korisniku i kartici.

**Više proba:**

```bash
# OCPP 2.0.1 ili 2.1 (dodaj --version)
docker compose -f docker-compose.prod.yml exec csms \
  python tools/simulator.py --url ws://localhost:9000/ocpp --id TEST-01 --password LOZINKA --version 2.0.1

# Ostani spojen, pa u sučelju (Punionice → TEST-01) probaj "Daljinski start", "Zaustavi", "Soft reset"
docker compose -f docker-compose.prod.yml exec csms \
  python tools/simulator.py --url ws://localhost:9000/ocpp --id TEST-01 --password LOZINKA --stay
# (Ctrl+C za prekid)

# Nepoznata kartica: autorizacija mora biti odbijena, a UID se vidi u Postavke → Događaji
docker compose -f docker-compose.prod.yml exec csms \
  python tools/simulator.py --url ws://localhost:9000/ocpp --id TEST-01 --password LOZINKA --tag DEADBEEF
```

Kad završiš s probom, punionicu `TEST-01` možeš ostaviti ili joj maknuti oznaku *odobrena*.

---

## 6. Spajanje pravih punionica

### 6.1 Opći postupak (isti za sve proizvođače)

1. **Punionice → Dodaj punionicu**
   - **Charge Point ID**: kratko i jedinstveno, bez razmaka, npr. `GARAZA-01`. Neke punionice imaju fiksni ID (često serijski broj), pa tada upiši točno taj.
   - **Proizvođač**: odaberi s popisa.
   - **Sigurnosni profil**: **2** (preporuka).
   - Spremi i kopiraj lozinku.
2. U konfiguraciji punionice (aplikacija ili web sučelje proizvođača) upiši:

   | Polje u punionici | Vrijednost |
   |---|---|
   | OCPP verzija | 1.6J (ili 2.0.1 ako punionica podržava) |
   | Server URL / Central System URL / Backend URL | `wss://ocpp.tvrtka.hr/ocpp/` |
   | Charge Point ID / Identity / Chargebox ID | isti ID kao u sučelju |
   | Lozinka / Authorization Key / Basic Auth password | lozinka iz sučelja |
   | Korisničko ime (ako ga traži) | isti ID |

   Neke punionice traže URL **s ID-em na kraju**: `wss://ocpp.tvrtka.hr/ocpp/GARAZA-01`. Ako se ne spoji s jednim oblikom, probaj drugi.
3. U sučelju punionica postane **online** unutar minute. Proizvođač, model i firmware upisuju se sami.
4. Prisloni karticu. Ako je nepoznata, UID se pojavi u **Postavke → Događaji** (`unknown_card`), pa je dodaj u **Kartice**.

Certifikat je od Let's Encrypta, pa ga punionice prepoznaju bez dodatnog instaliranja. Ako punionica ipak javi grešku certifikata, provjeri ima li točan datum i vrijeme (NTP) i ažuriran firmware.

### 6.2 Napomene po proizvođačima

Izbornici se razlikuju ovisno o modelu i verziji firmwarea. Ovo su uobičajena mjesta, a točne korake potraži u priručniku svog modela.

| Proizvođač | Gdje se postavlja OCPP | Napomena |
|---|---|---|
| **Gewiss** (JOINON) | Gewiss aplikacija ili web sučelje punionice → OCPP / Backend | Uključi OCPP način rada, pa upiši URL, ID i lozinku. |
| **Schneider Electric** (EVlink Pro) | eSetup aplikacija → Supervision / OCPP | Podržava profile 1-3 i potpisivanje certifikata. Ima ugrađeni RFID čitač. |
| **SMA** (EV Charger Business) | Web sučelje punionice → Konfiguracija → OCPP | ID mora biti jednak ID-u u sustavu. |
| **Huawei** (SCharger / FusionCharge) | FusionSolar aplikacija → Commissioning → OCPP / Platform | UID kartice zna slati malim slovima, sustav ga sam pretvara. |
| **Fronius** (Wattpilot) | Solar.wattpilot aplikacija → Internet → OCPP | Uključi OCPP, pa upiši URL i ID. Ako Wattpilot ne podržava lozinku na tvom firmwareu, koristi profil 1 bez lozinke samo na zaštićenoj mreži ili ažuriraj firmware. |

> Ovo još nije isprobano na tvojim uređajima. Prvu punionicu svakog proizvođača spoji uz praćenje **Punionice → [ID] → Događaji** i javi mi ako nešto odstupa, pa ću dodati prilagodbu.

### 6.3 Nepoznate punionice

Punionica koja se spoji s ID-em kojeg nema u sustavu automatski se pojavi u popisu kao **čeka odobrenje**. Otvori je, označi *odobrena*, odaberi profil, spremi i klikni **Generiraj novu lozinku** (uz kvačicu *pošalji punionici*). Isključivanje ove opcije: `CSMS_AUTO_REGISTER=0` u `.env`.

### 6.4 Sigurnosni profil 3 (klijentski certifikat, najviša razina)

Samo za punionice koje to podržavaju (npr. Schneider EVlink Pro, novije punionice s OCPP 2.0.1):

1. Punionica radi na profilu 2.
2. Na stranici punionice klikni **Instaliraj CA certifikat**, pa **Zatraži certifikat (CSR)**.
3. U događajima pričekaj `certificate_signed: Accepted`.
4. U postavkama punionice odaberi profil **3** i spremi. Za OCPP 1.6J klikni i **Pošalji SecurityProfile** (3).
5. Punionica se ponovno spaja svojim certifikatom, bez lozinke.

---

## 7. Korisnici i RFID kartice

- **Korisnici** → dodaj korisnika (e-mail, ime, početna lozinka). Korisnik se prijavi, promijeni lozinku i uključi MFA u *Moj račun*. Korisnik vidi samo svoja punjenja i potrošnju.
- **Kartice** → dodaj UID i dodijeli korisniku. Jedan korisnik može imati više kartica. Gumb **Blokiraj** odmah onemogućuje karticu.
- **Izvještaji** → potrošnja u kWh i EUR po korisniku i po kartici za odabrani period.
- **Punjenja** → filter po korisniku, kartici i datumu, plus **CSV izvoz** koji se otvara u Excelu.

Administrator može korisniku resetirati MFA (izgubljen mobitel) i otključati račun zaključan nakon 5 pogrešnih lozinki.

---

## 8. Održavanje

Sve naredbe se pokreću u `/opt/ocpp`.

**Ažuriranje na novu verziju:**

```bash
git pull
docker compose -f docker-compose.prod.yml up -d --build
```

**Logovi:**

```bash
docker compose -f docker-compose.prod.yml logs -f csms     # aplikacija i OCPP poruke
docker compose -f docker-compose.prod.yml logs -f caddy    # HTTPS
```

**Backup** (baza, CA certifikati, ključevi). Napravi ga barem jednom dnevno i kopiraj na drugo mjesto:

```bash
mkdir -p ~/backup
docker compose -f docker-compose.prod.yml exec -T csms \
  python -c "import sqlite3; sqlite3.connect('/data/csms.db').backup(sqlite3.connect('/data/backup.db'))"
docker compose -f docker-compose.prod.yml cp csms:/data/backup.db ~/backup/csms-$(date +%F).db
docker compose -f docker-compose.prod.yml cp csms:/data/pki ~/backup/pki-$(date +%F)
```

Automatski svaki dan u 3:00: `crontab -e` i dodaj red (sve u jednom redu):

```
0 3 * * * cd /opt/ocpp && docker compose -f docker-compose.prod.yml exec -T csms python -c "import sqlite3; sqlite3.connect('/data/csms.db').backup(sqlite3.connect('/data/backup.db'))" && docker compose -f docker-compose.prod.yml cp csms:/data/backup.db $HOME/backup/csms-$(date +\%F).db
```

**Ponovno pokretanje / gašenje:**

```bash
docker compose -f docker-compose.prod.yml restart
docker compose -f docker-compose.prod.yml down        # podaci ostaju u Docker volumenima
```

---

## 9. Rješavanje problema

| Problem | Što provjeriti |
|---|---|
| Stranica se ne otvara | `docker compose -f docker-compose.prod.yml ps`; je li DNS točan (`ping domena`); jesu li 80/443 otvoreni. |
| Caddy ne dobiva certifikat | U `logs caddy` potraži grešku. Najčešće DNS još ne pokazuje na server ili je port 80 zatvoren. |
| Punionica se ne spaja | **Postavke → Događaji**: `connection_rejected` s razlogom (kriva lozinka, krivi profil, nema certifikata). Ako nema nikakvog događaja, punionica uopće ne dolazi do servera (URL, internet, vatrozid). |
| "profil 2 zahtijeva wss://" | U punionici je URL `ws://`, a treba `wss://`. |
| Punionica stalno "čeka odobrenje" | Označi *odobrena* i spremi, pa resetiraj punionicu (ili pričekaj da se sama ponovno spoji). |
| Kartica odbijena | Je li kartica dodana i aktivna; usporedi UID u **Događajima** s onim u **Kartice**. |
| Punjenje ima 0 kWh | Punionica ne šalje mjerenja. Za OCPP 1.6J sustav nakon spajanja sam postavlja `MeterValueSampleInterval=60`. Provjeri u logovima stižu li `MeterValues`. |
| Zaboravljena admin lozinka ili izgubljen MFA | `docker compose -f docker-compose.prod.yml exec csms python -m csms.cli reset-password admin@tvrtka.hr NovaLozinka123` (isključuje i MFA, pa ga ponovno uključi). |

Za sve ostalo pošalji mi ispis `docker compose -f docker-compose.prod.yml logs --tail 200 csms` i opis problema.
