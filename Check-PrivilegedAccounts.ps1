#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Valida contas do AD, identifica privilegios e gera report HTML para sanitizacao.
.PARAMETER Users
    Lista de SAMAccountNames para validar.
.PARAMETER InputFile
    Arquivo .txt com uma conta por linha.
.PARAMETER ExportCSV
    Exporta resultado em CSV.
.PARAMETER ReportHTML
    Caminho para o report HTML (default: PrivilegedAccounts_Report_<data>.html).
.EXAMPLE
    .\Check-PrivilegedAccounts.ps1 -Users "jsilva","bill.gates"
.EXAMPLE
    .\Check-PrivilegedAccounts.ps1 -InputFile "C:\contas.txt" -ReportHTML "C:\report.html"
.NOTES
    Autor   : Hackers Hive - Daniel Donda
    Website : hackershive.io | danieldonda.com
    Versao  : 2.1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)] [string[]]$Users,
    [Parameter(Mandatory = $false)] [string]$InputFile,
    [Parameter(Mandatory = $false)] [string]$ExportCSV,
    [Parameter(Mandatory = $false)] [string]$ReportHTML
)

# ============================================================
#  CONFIGURACAO - Grupos e niveis de risco
# ============================================================
$script:PrivilegedGroupRisk = [ordered]@{
    "Domain Admins"                   = "CRITICO"
    "Enterprise Admins"               = "CRITICO"
    "Schema Admins"                   = "CRITICO"
    "Administrators"                  = "CRITICO"
    "Account Operators"               = "ALTO"
    "Backup Operators"                = "ALTO"
    "Server Operators"                = "ALTO"
    "Print Operators"                 = "ALTO"
    "Group Policy Creator Owners"     = "ALTO"
    "DnsAdmins"                       = "ALTO"
    "DHCP Administrators"             = "MEDIO"
    "Remote Desktop Users"            = "MEDIO"
    "Network Configuration Operators" = "MEDIO"
    "Cryptographic Operators"         = "MEDIO"
    "Distributed COM Users"           = "MEDIO"
    "Event Log Readers"               = "BAIXO"
    "Cert Publishers"                 = "BAIXO"
    "Protected Users"                 = "BAIXO"
    # Grupos customizados:
    # "TI-Administradores"            = "ALTO"
    # "SOC-Analistas"                 = "MEDIO"
}
$script:PrivilegedGroups = @($script:PrivilegedGroupRisk.Keys)
# ============================================================
#  FUNCOES AD
# ============================================================
function Get-ADUserSafe {
    param([string]$Sam)
    try {
        $props = @("Enabled","PasswordNeverExpires","LastLogonDate","Description",
                   "PasswordLastSet","LockedOut","WhenCreated","DisplayName","EmailAddress")
        return Get-ADUser -Identity $Sam -Properties $props -ErrorAction Stop
    }
    catch {
        Write-Host "  [DEBUG] Erro ao buscar $Sam : $($_.Exception.Message)" -ForegroundColor DarkGray
        return $null
    }
}

function Get-UserMemberships {
    param([string]$Sam)
    try {
        $groups = Get-ADPrincipalGroupMembership -Identity $Sam -ErrorAction Stop
        return @($groups | Select-Object -ExpandProperty Name)
    }
    catch {
        Write-Host "  [DEBUG] Erro memberships $Sam : $($_.Exception.Message)" -ForegroundColor DarkGray
        return @()
    }
}

function Get-HighestRisk {
    param([string[]]$Groups)
    foreach ($nivel in @("CRITICO","ALTO","MEDIO","BAIXO")) {
        foreach ($g in $Groups) {
            if ($script:PrivilegedGroupRisk[$g] -eq $nivel) { return $nivel }
        }
    }
    return "NENHUM"
}

# ============================================================
#  GERACAO DO REPORT HTML
# ============================================================
function New-HTMLReport {
    param(
        [object[]]$Data,
        [string]$OutputPath,
        [int]$TotalPriv,
        [int]$TotalNormal,
        [int]$TotalNotFound,
        [int]$TotalCritico,
        [int]$TotalAlto,
        [int]$TotalMedio,
        [int]$TotalBaixo
    )

    $geradoEm = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    $dominio  = try { (Get-ADDomain).DNSRoot } catch { "N/A" }

    $tableRows = ""
    foreach ($r in $Data) {
        if ($r.Encontrado -eq "Nao") {
            $tableRows += "<tr class=`"row-notfound`"><td>$($r.Usuario)</td>"
            $tableRows += "<td><span class=`"badge badge-gray`">NAO ENCONTRADO</span></td>"
            $tableRows += "<td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>"
            continue
        }

        $statusBadge = if ($r.Privilegiado -eq "Sim") { "<span class=`"badge badge-red`">PRIVILEGIADA</span>" } else { "<span class=`"badge badge-green`">NORMAL</span>" }
        $contaBadge  = if ($r.ContaAtiva -eq "Ativa") { "<span class=`"badge badge-green`">Ativa</span>" } else { "<span class=`"badge badge-gray`">Desativada</span>" }
        $pwdBadge    = if ($r.SenhaNuncaExpira -eq "Sim") { "<span class=`"badge badge-orange`">Sim</span>" } else { "<span class=`"badge badge-green`">Nao</span>" }
        $lockBadge   = if ($r.Bloqueada -eq "Sim") { "<span class=`"badge badge-red`">Sim</span>" } else { "<span class=`"badge badge-green`">Nao</span>" }
        $riskBadge   = switch ($r.RiscoMaximo) {
            "CRITICO" { "<span class=`"badge badge-red`">CRITICO</span>" }
            "ALTO"    { "<span class=`"badge badge-orange`">ALTO</span>" }
            "MEDIO"   { "<span class=`"badge badge-yellow`">MEDIO</span>" }
            "BAIXO"   { "<span class=`"badge badge-blue`">BAIXO</span>" }
            default   { "<span class=`"badge badge-green`">-</span>" }
        }

        $gruposBadges = ""
        if ($r.GruposPrivArray.Count -gt 0) {
            foreach ($g in $r.GruposPrivArray) {
                $riskG = $script:PrivilegedGroupRisk[$g]
                $cls = switch ($riskG) {
                    "CRITICO" { "badge-red" }
                    "ALTO"    { "badge-orange" }
                    "MEDIO"   { "badge-yellow" }
                    default   { "badge-blue" }
                }
                $gruposBadges += "<span class=`"badge $cls`">$g</span> "
            }
        } else {
            $gruposBadges = "<span class=`"badge badge-gray`">Nenhum</span>"
        }

        $sanitizeCmds = ""
        foreach ($g in $r.GruposPrivArray) {
            $sanitizeCmds += "Remove-ADGroupMember -Identity `"$g`" -Members `"$($r.Usuario)`" -Confirm:`$false<br>"
        }
        if ($sanitizeCmds -eq "") { $sanitizeCmds = "-" }

        $rowClass = if ($r.Privilegiado -eq "Sim") { "row-priv" } else { "row-normal" }

        $tableRows += "<tr class=`"$rowClass`">"
        $tableRows += "<td>$($r.Usuario)<br><small>$($r.DisplayName)</small></td>"
        $tableRows += "<td>$statusBadge</td>"
        $tableRows += "<td>$contaBadge</td>"
        $tableRows += "<td>$($r.UltimoLogin)</td>"
        $tableRows += "<td>$($r.SenhaCriada)</td>"
        $tableRows += "<td>$pwdBadge</td>"
        $tableRows += "<td>$lockBadge</td>"
        $tableRows += "<td>$gruposBadges</td>"
        $tableRows += "<td>$riskBadge</td>"
        $tableRows += "<td><code>$sanitizeCmds</code></td>"
        $tableRows += "</tr>"
    }

    # Secao de sanitizacao
    $sanitizeSection = ""
    $privOnly = @($Data | Where-Object { $_.Privilegiado -eq "Sim" })
    if ($privOnly.Count -gt 0) {
        $sanitizeSection += "<div class=`"section`"><h2>Plano de Sanitizacao</h2>"
        $sanitizeSection += "<p>Comandos PowerShell prontos para remover privilegios. Valide o impacto antes de executar em producao.</p>"
        foreach ($r in $privOnly) {
            $riskColor = switch ($r.RiscoMaximo) {
                "CRITICO" { "#ff4444" } "ALTO" { "#ff8800" } "MEDIO" { "#f5c400" } default { "#4488ff" }
            }
            $sanitizeSection += "<div class=`"sanitize-card`" style=`"border-left:4px solid $riskColor`">"
            $sanitizeSection += "<div class=`"sanitize-header`"><strong>$($r.Usuario)</strong> <span>$($r.DisplayName)</span> <span class=`"badge`" style=`"background:$riskColor;color:#000`">$($r.RiscoMaximo)</span></div>"
            $sanitizeSection += "<div class=`"sanitize-body`">"
            foreach ($g in $r.GruposPrivArray) {
                $riskG = $script:PrivilegedGroupRisk[$g]
                $riskColor2 = switch ($riskG) {
                    "CRITICO" { "#ff4444" } "ALTO" { "#ff8800" } "MEDIO" { "#f5c400" } default { "#4488ff" }
                }
                $sanitizeSection += "<div class=`"cmd-line`"><span class=`"risk-dot`" style=`"background:$riskColor2`"></span>"
                $sanitizeSection += "<code>Remove-ADGroupMember -Identity `"$g`" -Members `"$($r.Usuario)`" -Confirm:`$false</code>"
                $sanitizeSection += "<span class=`"risk-label`" style=`"color:$riskColor2`">[$riskG]</span></div>"
            }
            $sanitizeSection += "</div></div>"
        }
        $sanitizeSection += "</div>"
    }

    $css = @"
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0d0d0d; color: #e0e0e0; font-family: Segoe UI, Arial, sans-serif; font-size: 14px; }
.header { background: #111; border-bottom: 2px solid #f5a623; padding: 28px 36px; }
.header h1 { color: #f5a623; font-size: 1.6em; letter-spacing: 2px; }
.header .meta { margin-top: 12px; color: #888; font-size: 0.85em; }
.header .meta strong { color: #f5a623; }
.stats { display: flex; gap: 14px; padding: 20px 36px; flex-wrap: wrap; }
.stat-card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 8px; padding: 14px 20px; flex: 1; min-width: 120px; text-align: center; }
.stat-card .num { font-size: 2em; font-weight: bold; }
.stat-card .lbl { font-size: 0.75em; color: #888; margin-top: 4px; }
.stat-card.red    { border-color: #ff4444; } .stat-card.red .num    { color: #ff4444; }
.stat-card.orange { border-color: #ff8800; } .stat-card.orange .num { color: #ff8800; }
.stat-card.yellow { border-color: #f5c400; } .stat-card.yellow .num { color: #f5c400; }
.stat-card.blue   { border-color: #4488ff; } .stat-card.blue .num   { color: #4488ff; }
.stat-card.green  { border-color: #44cc44; } .stat-card.green .num  { color: #44cc44; }
.stat-card.gray   { border-color: #555;    } .stat-card.gray .num   { color: #888;    }
.section { padding: 20px 36px; }
.section h2 { color: #f5a623; margin-bottom: 14px; font-size: 1.05em; letter-spacing: 1px; }
.section p { color: #888; margin-bottom: 16px; font-size: 0.85em; }
table { width: 100%; border-collapse: collapse; }
th { background: #1e1e1e; color: #f5a623; padding: 10px 12px; text-align: left; font-size: 0.78em; letter-spacing: 1px; border-bottom: 2px solid #f5a623; }
td { padding: 9px 12px; border-bottom: 1px solid #1e1e1e; vertical-align: top; font-size: 0.88em; }
tr.row-priv   { background: #1a1010; }
tr.row-normal { background: #0f1a0f; }
tr.row-notfound { background: #111; opacity: 0.6; }
tr:hover td { background: rgba(245,166,35,0.06); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.73em; font-weight: bold; margin: 1px; }
.badge-red    { background: #3d0000; color: #ff6666; border: 1px solid #ff4444; }
.badge-orange { background: #2a1500; color: #ffaa44; border: 1px solid #ff8800; }
.badge-yellow { background: #2a2000; color: #f5c400; border: 1px solid #f5c400; }
.badge-blue   { background: #001a3d; color: #66aaff; border: 1px solid #4488ff; }
.badge-green  { background: #003300; color: #66cc66; border: 1px solid #44cc44; }
.badge-gray   { background: #222;    color: #888;    border: 1px solid #444;    }
code { font-family: Consolas, monospace; font-size: 0.82em; color: #f5a623; }
.sanitize-card { background: #141414; border-radius: 8px; margin-bottom: 14px; overflow: hidden; }
.sanitize-header { padding: 10px 16px; background: #1a1a1a; display: flex; align-items: center; gap: 10px; }
.sanitize-body   { padding: 10px 16px; }
.cmd-line { display: flex; align-items: center; gap: 10px; padding: 6px 0; border-bottom: 1px solid #1e1e1e; }
.cmd-line:last-child { border-bottom: none; }
.cmd-line code { background: #0d0d0d; padding: 4px 8px; border-radius: 4px; flex: 1; color: #ddd; }
.risk-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.risk-label { font-size: 0.73em; font-weight: bold; white-space: nowrap; }
.warn { background: #1a1000; border: 1px solid #f5a623; border-radius: 6px; padding: 12px 16px; color: #f5a623; font-size: 0.83em; margin-bottom: 16px; }
.footer { padding: 20px 36px; border-top: 1px solid #222; color: #444; font-size: 0.78em; display: flex; justify-content: space-between; }
.footer a { color: #f5a623; text-decoration: none; }
small { color: #666; font-size: 0.85em; }
"@

    $html = "<!DOCTYPE html><html lang=`"pt-BR`"><head><meta charset=`"UTF-8`">"
    $html += "<title>Privileged Account Report - Hackers Hive</title>"
    $html += "<style>$css</style></head><body>"
    $html += "<div class=`"header`"><h1>PRIVILEGED ACCOUNT REPORT</h1>"
    $html += "<div class=`"meta`">Gerado em: <strong>$geradoEm</strong> | Dominio: <strong>$dominio</strong> | Contas analisadas: <strong>$($Data.Count)</strong></div></div>"
    $html += "<div class=`"stats`">"
    $html += "<div class=`"stat-card red`"><div class=`"num`">$TotalPriv</div><div class=`"lbl`">PRIVILEGIADAS</div></div>"
    $html += "<div class=`"stat-card green`"><div class=`"num`">$TotalNormal</div><div class=`"lbl`">NORMAIS</div></div>"
    $html += "<div class=`"stat-card gray`"><div class=`"num`">$TotalNotFound</div><div class=`"lbl`">NAO ENCONTRADAS</div></div>"
    $html += "<div class=`"stat-card red`"><div class=`"num`">$TotalCritico</div><div class=`"lbl`">CRITICO</div></div>"
    $html += "<div class=`"stat-card orange`"><div class=`"num`">$TotalAlto</div><div class=`"lbl`">ALTO</div></div>"
    $html += "<div class=`"stat-card yellow`"><div class=`"num`">$TotalMedio</div><div class=`"lbl`">MEDIO</div></div>"
    $html += "<div class=`"stat-card blue`"><div class=`"num`">$TotalBaixo</div><div class=`"lbl`">BAIXO</div></div>"
    $html += "</div>"
    $html += "<div class=`"section`"><h2>Inventario de Contas</h2>"
    $html += "<table><thead><tr>"
    $html += "<th>USUARIO</th><th>STATUS</th><th>CONTA</th><th>ULTIMO LOGIN</th><th>SENHA CRIADA</th>"
    $html += "<th>PWD NEVER EXPIRES</th><th>BLOQUEADA</th><th>GRUPOS PRIVILEGIADOS</th><th>RISCO</th><th>REMOCAO</th>"
    $html += "</tr></thead><tbody>$tableRows</tbody></table></div>"
    $html += $sanitizeSection
    $html += "<div class=`"section`"><div class=`"warn`">ATENCAO: Valide o impacto antes de executar os comandos de remocao em producao.</div></div>"
    $html += "<div class=`"footer`"><span>Hackers Hive - <a href=`"https://hackershive.io`">hackershive.io</a> | <a href=`"https://danieldonda.com`">danieldonda.com</a></span>"
    $html += "<span>Check-PrivilegedAccounts.ps1 v2.1 | $geradoEm</span></div>"
    $html += "</body></html>"

    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
}

# ============================================================
#  INICIO
# ============================================================
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host " [ERRO] Modulo ActiveDirectory nao disponivel. Instale RSAT ou rode no DC." -ForegroundColor Red
    exit 1
}
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# Montar lista de usuarios
$UserList = @()

if ($InputFile) {
    if (Test-Path $InputFile) {
        $UserList = @(Get-Content $InputFile | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() })
        Write-Host " [*] $($UserList.Count) usuario(s) carregado(s) de: $InputFile" -ForegroundColor Cyan
        Write-Host ""
    } else {
        Write-Host " [ERRO] Arquivo nao encontrado: $InputFile" -ForegroundColor Red
        exit 1
    }
} elseif ($Users -and $Users.Count -gt 0) {
    $UserList = @($Users)
} else {
    Write-Host " Digite os SAMAccountNames separados por virgula (ex: jsilva,bill.gates):" -ForegroundColor Cyan
    $inp = Read-Host " Usuarios"
    $UserList = @($inp -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
}

if ($UserList.Count -eq 0) {
    Write-Host " [ERRO] Nenhum usuario informado." -ForegroundColor Red
    exit 1
}

Write-Host " [*] Verificando $($UserList.Count) conta(s)..." -ForegroundColor Cyan
Write-Host (" " + "=" * 100) -ForegroundColor DarkGray
Write-Host ("  {0,-25} {1,-16} {2,-12} {3,-13} {4,-10} {5}" -f "USUARIO","STATUS","CONTA","ULTIMO LOGIN","RISCO","GRUPOS PRIVILEGIADOS") -ForegroundColor White
Write-Host (" " + "=" * 100) -ForegroundColor DarkGray

$Results      = [System.Collections.Generic.List[object]]::new()
$TotalPriv    = 0; $TotalNormal = 0; $TotalNotFound = 0
$TotalCritico = 0; $TotalAlto   = 0; $TotalMedio    = 0; $TotalBaixo = 0

foreach ($user in $UserList) {
    $user = $user.Trim()
    if ($user -eq "") { continue }

    $adUser = Get-ADUserSafe -Sam $user

    if ($null -eq $adUser) {
        $TotalNotFound++
        Write-Host ("  {0,-25} " -f $user) -NoNewline -ForegroundColor DarkGray
        Write-Host "NAO ENCONTRADO" -ForegroundColor DarkGray
        $Results.Add([PSCustomObject]@{
            Usuario = $user; DisplayName = ""; Encontrado = "Nao"; Privilegiado = "N/A"
            ContaAtiva = "N/A"; UltimoLogin = "N/A"; SenhaCriada = "N/A"
            SenhaNuncaExpira = "N/A"; Bloqueada = "N/A"
            GruposPriv = "-"; GruposPrivArray = @(); RiscoMaximo = "N/A"; TotalGruposPriv = 0
        })
        continue
    }

    $memberships = Get-UserMemberships -Sam $user
    $privMatches = [System.Collections.Generic.List[string]]::new()
    foreach ($pg in $script:PrivilegedGroups) {
        if ($memberships -contains $pg) { $privMatches.Add($pg) }
    }

    $isPriv      = $privMatches.Count -gt 0
    $riscoMax    = if ($isPriv) { Get-HighestRisk -Groups @($privMatches) } else { "NENHUM" }
    $acctEnabled = if ($adUser.Enabled) { "Ativa" } else { "Desativada" }
    $lastLogon   = if ($adUser.LastLogonDate) { $adUser.LastLogonDate.ToString("dd/MM/yyyy") } else { "Nunca" }
    $pwdSet      = if ($adUser.PasswordLastSet) { $adUser.PasswordLastSet.ToString("dd/MM/yyyy") } else { "N/A" }
    $pwdNever    = if ($adUser.PasswordNeverExpires) { "Sim" } else { "Nao" }
    $locked      = if ($adUser.LockedOut) { "Sim" } else { "Nao" }
    $privStr     = if ($privMatches.Count -gt 0) { $privMatches -join " | " } else { "Nenhum" }

    if ($isPriv) {
        $TotalPriv++
        switch ($riscoMax) {
            "CRITICO" { $TotalCritico++ }
            "ALTO"    { $TotalAlto++    }
            "MEDIO"   { $TotalMedio++   }
            "BAIXO"   { $TotalBaixo++   }
        }
        $statusTxt   = "[PRIVILEGIADA]"
        $statusColor = "Red"
        $userColor   = "Yellow"
        $riskColor   = switch ($riscoMax) { "CRITICO" { "Red" } "ALTO" { "DarkYellow" } "MEDIO" { "Yellow" } default { "Cyan" } }
    } else {
        $TotalNormal++
        $statusTxt   = "[NORMAL]      "
        $statusColor = "Green"
        $userColor   = "White"
        $riskColor   = "DarkGray"
    }

    Write-Host ("  {0,-25} " -f $user)     -NoNewline -ForegroundColor $userColor
    Write-Host ("{0,-16} " -f $statusTxt)  -NoNewline -ForegroundColor $statusColor
    Write-Host ("{0,-12} " -f $acctEnabled)-NoNewline -ForegroundColor Gray
    Write-Host ("{0,-13} " -f $lastLogon)  -NoNewline -ForegroundColor Gray
    Write-Host ("{0,-10} " -f $riscoMax)   -NoNewline -ForegroundColor $riskColor
    Write-Host $privStr                                -ForegroundColor DarkYellow

    $Results.Add([PSCustomObject]@{
        Usuario          = $user
        DisplayName      = $adUser.DisplayName
        Encontrado       = "Sim"
        Privilegiado     = if ($isPriv) { "Sim" } else { "Nao" }
        ContaAtiva       = $acctEnabled
        UltimoLogin      = $lastLogon
        SenhaCriada      = $pwdSet
        SenhaNuncaExpira = $pwdNever
        Bloqueada        = $locked
        GruposPriv       = $privStr
        GruposPrivArray  = @($privMatches)
        RiscoMaximo      = $riscoMax
        TotalGruposPriv  = $privMatches.Count
    })
}

# ============================================================
#  RESUMO NO CONSOLE
# ============================================================
Write-Host (" " + "=" * 100) -ForegroundColor DarkGray
Write-Host ""
Write-Host "  RESUMO" -ForegroundColor Cyan
Write-Host "  ------" -ForegroundColor DarkGray
Write-Host ("  Total verificado   : {0}" -f $UserList.Count)  -ForegroundColor White
Write-Host ("  Privilegiadas      : {0}" -f $TotalPriv)       -ForegroundColor Red
Write-Host ("    > Critico        : {0}" -f $TotalCritico)    -ForegroundColor Red
Write-Host ("    > Alto           : {0}" -f $TotalAlto)       -ForegroundColor DarkYellow
Write-Host ("    > Medio          : {0}" -f $TotalMedio)      -ForegroundColor Yellow
Write-Host ("    > Baixo          : {0}" -f $TotalBaixo)      -ForegroundColor Cyan
Write-Host ("  Normais            : {0}" -f $TotalNormal)     -ForegroundColor Green
Write-Host ("  Nao encontradas    : {0}" -f $TotalNotFound)   -ForegroundColor DarkGray
Write-Host ""

# CSV
if ($ExportCSV) {
    try {
        $Results | Select-Object Usuario,DisplayName,Encontrado,Privilegiado,ContaAtiva,
            UltimoLogin,SenhaCriada,SenhaNuncaExpira,Bloqueada,GruposPriv,RiscoMaximo,TotalGruposPriv |
            Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8 -Force
        Write-Host ("  [OK] CSV exportado: {0}" -f $ExportCSV) -ForegroundColor Cyan
    } catch {
        Write-Host ("  [ERRO] CSV: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
}

# HTML
if (-not $ReportHTML) {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportHTML = ".\PrivilegedAccounts_Report_$ts.html"
}

try {
    New-HTMLReport -Data @($Results) -OutputPath $ReportHTML `
        -TotalPriv $TotalPriv -TotalNormal $TotalNormal -TotalNotFound $TotalNotFound `
        -TotalCritico $TotalCritico -TotalAlto $TotalAlto -TotalMedio $TotalMedio -TotalBaixo $TotalBaixo
    Write-Host ("  [OK] Report HTML gerado: {0}" -f $ReportHTML) -ForegroundColor Green
    Start-Process $ReportHTML
} catch {
    Write-Host ("  [ERRO] Report HTML: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

Write-Host ""
Write-Host "  hackershive.io | danieldonda.com" -ForegroundColor DarkYellow
Write-Host ""
