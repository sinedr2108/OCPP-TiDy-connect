# Windows Server + Cloudflare Tunnel (bez Dockera)

Za server na kojem već radi Cloudflare Tunnel (npr. uz aplikaciju *evidencija*). TiDy Charge sluša samo na
`127.0.0.1` (web 8000, OCPP 9000), a izvana mu se pristupa preko tunela. Nema otvaranja portova na routeru ni
lokalnih certifikata: HTTPS/WSS radi Cloudflare.

## 1. Instalacija

```powershell
winget install --id Python.Python.3.13 --scope machine     # uz postojeći Python, samo za ovaj sustav
git clone https://github.com/sinedr2108/ocpp-tidy-connect C:\ocpp
cd C:\ocpp
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1 -Hostname ocpp.tid-intel.com -AdminEmail admin@tid-intel.com
```

Skripta napravi `.venv`, `.env` (s nasumičnim tajnim ključem i prvom lozinkom admina, koju ispiše jednom)
i Scheduled Task **OcppCsms** (pri startu sustava, kao SYSTEM, ponovno pokretanje nakon pada).

## 2. Cloudflare: dva pravila na postojećem tunelu

Cloudflare dashboard → **Zero Trust → Networks → Tunnels** → postojeći tunel → **Configure** →
**Public Hostname** → **Add a public hostname**. Redoslijed je bitan, pravilo s putanjom mora biti prvo:

| # | Subdomain | Domain | Path | Type | URL |
|---|---|---|---|---|---|
| 1 | `ocpp` | `tid-intel.com` | `ocpp/*` | HTTP | `localhost:9000` |
| 2 | `ocpp` | `tid-intel.com` | *(prazno)* | HTTP | `localhost:8000` |

Cloudflared se ne mora restartati, a postojeći hostnameovi (npr. `sati.tid-intel.com`) ostaju isti.

## 3. Punionice

- URL: `wss://ocpp.tid-intel.com/ocpp/<ChargePointID>`, sigurnosni profil **2** (TLS + lozinka).
- Profil **3** (klijentski certifikat) iza Cloudflare tunela **nije moguć**, jer Cloudflare završava TLS.
- Profil 1 (`ws://`, bez šifriranja) radi samo ako za ovu poddomenu nije uključeno *Always Use HTTPS*;
  koristi ga samo za punionice koje ne znaju wss.

## Nadogradnja i backup

```powershell
cd C:\ocpp
powershell -ExecutionPolicy Bypass -File deploy\windows\update.ps1
```

Prije nadogradnje se baza (`C:\ocpp\data`) zapakira u `C:\ocpp\backup\`. Za redoviti backup kopiraj mapu
`C:\ocpp\data` (baza `csms.db`, CA i VAPID ključ).

## Zaustavljanje / uklanjanje

```powershell
Stop-ScheduledTask OcppCsms
Unregister-ScheduledTask OcppCsms -Confirm:$false   # uklanja samo zadatak; mapa C:\ocpp ostaje
```
