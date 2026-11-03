# Instalacija na Windows Server 2025

Aplikacija radi u Linux Docker kontejnerima. Docker Desktop nije podržan na Windows Serveru, pa je najpouzdaniji put **mala Ubuntu virtualka u Hyper-V-u**. Hyper-V je već uključen u Windows Server 2025 Standard i ne košta ništa dodatno, a Ubuntu je besplatan.

Nakon ovih koraka virtualka se ponaša kao zaseban Linux server, pa se nastavlja po glavnim uputama [INSTALACIJA.md](INSTALACIJA.md) od koraka 3.3.

```
Internet ─► router (80, 443) ─► Ubuntu VM u Hyper-V (vlastita IP adresa) ─► Caddy + aplikacija
                                 └── na tvom Windows Serveru
```

Trajanje: oko 30-45 minuta.

---

## Prije početka: dvije provjere

1. **Je li Windows Server fizički stroj ili virtualka?** Ako je i sam virtualka (npr. kod hosting providera ili u VMware-u), Hyper-V unutar njega traži *nested virtualization*, koju mora omogućiti onaj tko upravlja hostom. Na fizičkom serveru nema problema.
2. **Koriste li portovi 80 i 443 već nešto?** Ako na istoj javnoj IP adresi već radi druga web aplikacija (npr. Evidencija radnog vremena preko IIS-a), router ne može isti port proslijediti na dva mjesta. Javi mi pa ćemo složiti zajednički reverse proxy. Ako imaš zasebnu javnu IP ili 80/443 nisu zauzeti, samo nastavi.

---

## Korak 1: Uključi Hyper-V

Otvori **PowerShell kao administrator** (desni klik na Start → *Terminal (Admin)*):

```powershell
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart
```

Server se restarta.

## Korak 2: Preuzmi Ubuntu Server

Preuzmi **Ubuntu Server 24.04 LTS** ISO sa https://ubuntu.com/download/server i spremi ga npr. u `C:\ISO\`.

## Korak 3: Napravi virtualni switch (mrežu)

Virtualka mora biti u istoj mreži kao server, s vlastitom IP adresom. Prvo pogledaj ime mrežne kartice:

```powershell
Get-NetAdapter
```

Zatim napravi vanjski switch (zamijeni `"Ethernet"` imenom iz prethodnog ispisa):

```powershell
New-VMSwitch -Name "Vanjski" -NetAdapterName "Ethernet" -AllowManagementOS $true
```

Mreža servera će se na par sekundi prekinuti. To je normalno, a ako si spojen preko RDP-a, ponovno se spoji.

## Korak 4: Napravi virtualku

Prilagodi putanju do ISO datoteke ako je drukčija:

```powershell
New-Item -ItemType Directory -Force C:\Hyper-V | Out-Null
New-VM -Name "OCPP" -Generation 2 -MemoryStartupBytes 2GB `
  -NewVHDPath "C:\Hyper-V\OCPP.vhdx" -NewVHDSizeBytes 40GB -SwitchName "Vanjski"
Set-VMProcessor -VMName "OCPP" -Count 2
Set-VMMemory -VMName "OCPP" -DynamicMemoryEnabled $false
Set-VMFirmware -VMName "OCPP" -SecureBootTemplate MicrosoftUEFICertificateAuthority
Add-VMDvdDrive -VMName "OCPP" -Path "C:\ISO\ubuntu-24.04.3-live-server-amd64.iso"
Set-VMFirmware -VMName "OCPP" -FirstBootDevice (Get-VMDvdDrive -VMName "OCPP")
Set-VM -Name "OCPP" -AutomaticStartAction Start -AutomaticStartDelay 30 -AutomaticStopAction ShutDown
Start-VM -Name "OCPP"
vmconnect.exe localhost "OCPP"
```

Što ovo radi: virtualka s 2 CPU-a, 2 GB RAM-a i 40 GB diska, Secure Boot podešen za Linux, te **automatsko pokretanje kad se Windows Server upali** i uredno gašenje kad se gasi.

> Ime ISO datoteke (`ubuntu-24.04.3-...`) promijeni u ono koje si stvarno preuzeo.

## Korak 5: Instaliraj Ubuntu

U prozoru virtualke prati instalaciju. Većina koraka je *Done* / *Continue*, a bitno je:

| Ekran | Što odabrati |
|---|---|
| Language / Keyboard | English, a tipkovnicu po želji (Croatian) |
| Network | Zapiši IP adresu koju dobije (npr. `192.168.1.50`). Preporuka je fiksna IP: *Edit IPv4* → *Manual* (subnet npr. `192.168.1.0/24`, adresa, gateway = router, DNS `1.1.1.1,8.8.8.8`). Druga mogućnost je rezervacija adrese na routeru. |
| Storage | *Use an entire disk* (to je virtualni disk, ne disk servera) |
| Profile | ime, korisničko ime (npr. `ocpp`) i jaka lozinka |
| **SSH** | ✅ **Install OpenSSH server** |
| Featured snaps | ništa ne označavaj (Docker instaliramo posebno) |

Na kraju odaberi *Reboot Now*. Ako traži "remove installation medium", samo stisni Enter.

## Korak 6: Spoji se na virtualku preko SSH-a

S Windows Servera (ili bilo kojeg računala u mreži) otvori PowerShell:

```powershell
ssh ocpp@192.168.1.50
```

(korisničko ime i IP iz koraka 5). Prvi put odgovori `yes`.

Ažuriraj sustav:

```bash
sudo apt update && sudo apt -y upgrade
```

## Korak 7: Router: proslijedi portove na virtualku

Na routeru/firewallu postavi **port forwarding**:

| Vanjski port | Unutarnja IP | Unutarnji port |
|---|---|---|
| 80 TCP | IP virtualke (npr. `192.168.1.50`) | 80 |
| 443 TCP | IP virtualke | 443 |

Promet ide izravno na virtualku, pa **Windows vatrozid na serveru nije potrebno dirati**.

DNS A zapis tvoje domene (npr. `ocpp.tvrtka.hr`) mora pokazivati na **javnu** IP adresu (onu od routera).

## Korak 8: Nastavi po glavnim uputama

Od ovdje je sve isto kao na bilo kojem Linux serveru. U SSH sesiji nastavi u [INSTALACIJA.md](INSTALACIJA.md) od **koraka 3.3 (Instaliraj Docker)**. Korak 3.4 (ufw) možeš preskočiti, jer je virtualka iza routera i otvoreni su samo proslijeđeni portovi.

---

## Svakodnevni rad

| Što | Gdje / kako |
|---|---|
| Web sučelje | `https://ocpp.tvrtka.hr` s bilo kojeg računala |
| Naredbe na serveru (ažuriranje, logovi) | `ssh ocpp@192.168.1.50`, pa naredbe iz poglavlja 8 u INSTALACIJA.md |
| Upaliti / ugasiti virtualku | Hyper-V Manager, ili `Start-VM OCPP` / `Stop-VM OCPP` u PowerShellu |
| Restart Windows Servera | virtualka se uredno ugasi i sama ponovno upali, a aplikacija se sama pokrene |

## Backup cijele virtualke

Uz backup baze iz glavnih uputa, na Windows strani možeš povremeno izvesti cijelu virtualku (PowerShell kao admin):

```powershell
Export-VM -Name "OCPP" -Path "D:\Backup\Hyper-V"
```

Hyper-V *checkpoint* (snimka stanja) prije većih ažuriranja: `Checkpoint-VM -Name "OCPP" -SnapshotName "prije-azuriranja"`.

Ako koristiš Windows Server Backup ili Veeam, oni znaju raditi backup Hyper-V virtualki izravno.
