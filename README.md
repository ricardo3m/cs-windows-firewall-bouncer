<p align="center">
<img src="https://github.com/crowdsecurity/cs-windows-firewall-bouncer/raw/main/assets/logo.png" alt="CrowdSec" title="CrowdSec" width="300" height="280" />
</p>
<p align="center">
&#x1F4DA; <a href="https://docs.crowdsec.net/docs/bouncers/windows_firewall">Documentation</a>
&#x1F4A0; <a href="https://hub.crowdsec.net">Hub</a>
&#128172; <a href="https://discourse.crowdsec.net">Discourse </a>
</p>


# Windows Firewall Bouncer
CrowdSec bouncer written in **C#** for the Windows Firewall.

The bouncer fetches new and deleted decisions from the CrowdSec LAPI and manages Windows Firewall block rules accordingly.

See the [GitHub Releases](https://github.com/crowdsecurity/cs-windows-firewall-bouncer/releases) page for the changelog.

# Installation

Please follow the [official documentation](https://docs.crowdsec.net/docs/bouncers/windows_firewall).

# Configuration

The bouncer reads its configuration from `C:\ProgramData\CrowdSec\config\bouncers\cs-windows-firewall-bouncer.yaml` by default.

| Key | Type | Default | Description |
|---|---|---|---|
| `api_endpoint` | string | — | URL of the CrowdSec LAPI (e.g. `http://localhost:8080`) |
| `api_key` | string | — | Bouncer API key registered with CrowdSec |
| `update_frequency` | int | `10` | Polling interval in seconds |
| `log_media` | string | `file` | Logging target: `file` or `console` |
| `log_dir` | string | `C:\ProgramData\CrowdSec\log` | Directory for log files (when `log_media=file`) |
| `log_level` | string | `info` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error`, `fatal` |
| `fw_profiles` | list | current profile | Windows Firewall profiles to apply rules to: `domain`, `private`, `public` |
| `batch_size` | int | `1000` | Maximum number of IPs per Windows Firewall rule |

Example:

```yaml
api_endpoint: http://localhost:8080
api_key: your-api-key-here
update_frequency: 10
log_media: file
log_dir: C:\ProgramData\CrowdSec\log\
log_level: info
batch_size: 1000
```

# Building from Source

**Prerequisites:**

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) (with Desktop development workload) or MSBuild 17
- [WiX Toolset v4/v6](https://wixtoolset.org/releases/) (for installer projects)

**Build the bouncer only:**

```powershell
msbuild cs-windows-firewall-bouncer.sln -t:cs-windows-firewall-bouncer:rebuild -property:Configuration=Release -property:Platform=x64
```

**Build all including installer:**

```powershell
nuget restore cs-windows-firewall-bouncer.sln
msbuild cs-windows-firewall-bouncer.sln -t:cs-windows-firewall-installer-bundle -property:Configuration=Release -property:RunWixToolsOutOfProc=true
```

The signed MSI and bundle installer are produced at:
- `cs-windows-firewall-bouncer-setup\bin\x64\Release\cs_windows_firewall_bouncer_setup.msi`
- `cs-windows-firewall-installer-bundle\bin\Release\cs_windows_firewall_installer_bundle.exe`
