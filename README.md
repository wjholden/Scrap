# Scrap

Scrap is a security policy auditing tool for Cisco IOS routers and switches.
Scrap is written in pure PowerShell and depends on Plink and Pageant.

# Project Goals

1. Scrap aims to give network administrators an **estimate** of their compliance to security requirements.
2. Scrap depends only on common utilities (PowerShell and PuTTY).
3. Scrap is implemented in an interpreted language and uses human-readable data. The program requires no compilation and no unintelligible data files.

# Project Non-Goals

1. Scrap is **not** a perfect solution. Policies use very basic pattern matching. Some policies can be tricked by inconsistent or misleading configuration, such as a banner that contains configuration commands that are not actually applied.
2. Scrap assumes that all routers/switches accept public key authentication and default to privileged exec mode. This program provides no mechanism for keyboard-interactive or password-based authentication.
3. Scrap works only with SSH. Scrap is not intended for static analysis or for use with Telnet.

# Example

```
$definitions = (Get-Content -Path .\definitions.json | ConvertFrom-Json)
$routers = @('198.51.100.1', '198.51.100.2', '198.51.100.3')
Get-NetworkAudit -ComputerName $routers -Username 'cisco' -Definitions $definitions
```
