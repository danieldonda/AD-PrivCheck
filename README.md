# Check-PrivilegedAccounts.ps1

> **Active Directory Privileged Account Validator**  identifica contas com privilégios elevados, classifica por nível de risco e gera um report HTML com plano de sanitização pronto para execução.

Desenvolvido por **[Daniel Donda](https://danieldonda.com)** | **[Hackers Hive](https://hackershive.io)**

---

## Sumário

- [Visão Geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Pré-requisitos](#pré-requisitos)
- [Como usar](#como-usar)
- [Parâmetros](#parâmetros)
- [Grupos Monitorados e Níveis de Risco](#grupos-monitorados-e-níveis-de-risco)
- [Report HTML](#report-html)
- [Exportação CSV](#exportação-csv)
- [Sanitização](#sanitização)
- [Aviso Legal](#aviso-legal)

---

## Visão Geral

O script percorre uma lista de usuários do Active Directory, verifica a qual dos 18 grupos privilegiados cada um pertence, classifica o risco e produz:

- **Saída colorida no console** com status, nível de risco e grupos de cada conta
- **Report HTML** com dashboard de resumo, inventário completo e plano de sanitização
- **Exportação CSV** opcional para integração com outros processos

---

## Funcionalidades

| # | Funcionalidade |
|---|----------------|
| 1 | Validação de contas via parâmetro, arquivo ou entrada interativa |
| 2 | Detecção de pertencimento a 18 grupos privilegiados nativos do AD |
| 3 | Classificação de risco por grupo: **CRÍTICO / ALTO / MÉDIO / BAIXO** |
| 4 | Exibição de atributos: conta ativa, último login, senha nunca expira, bloqueada |
| 5 | Report HTML com dashboard, tabela de inventário e plano de sanitização |
| 6 | Comandos `Remove-ADGroupMember` gerados automaticamente por conta |
| 7 | Exportação CSV |
| 8 | Suporte a grupos customizados da organização |

---

## Pré-requisitos

- Windows PowerShell 5.1 ou PowerShell 7+
- Módulo **ActiveDirectory** instalado
  - Em Domain Controllers: já disponível por padrão
  - Em workstations: instalar **RSAT (Remote Server Administration Tools)**
    ```powershell
    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
    ```
- Permissão de **leitura no Active Directory** (usuário de domínio comum é suficiente)

---

## Como usar

### Modo 1 — Usuários via parâmetro

```powershell
.\Check-PrivilegedAccounts.ps1 -Users "jsilva","bill.gates","admin.ti"
```

### Modo 2 — Arquivo de texto

Crie um arquivo `contas.txt` com um SAMAccountName por linha:

```
jsilva
bill.gates
admin.ti
svc.backup
```

```powershell
.\Check-PrivilegedAccounts.ps1 -InputFile ".\contas.txt"
```

### Modo 3 — Interativo

```powershell
.\Check-PrivilegedAccounts.ps1
# O script solicitará os usuários separados por vírgula
```

### Modo 4 — Completo com todas as saídas

```powershell
.\Check-PrivilegedAccounts.ps1 `
    -InputFile ".\contas.txt" `
    -ReportHTML "C:\Reports\AD_Privilegios.html" `
    -ExportCSV  "C:\Reports\AD_Privilegios.csv"
```

---

## Parâmetros

| Parâmetro | Tipo | Obrigatório | Descrição |
|-----------|------|-------------|-----------|
| `-Users` | `string[]` | Não | Lista de SAMAccountNames separados por vírgula |
| `-InputFile` | `string` | Não | Caminho para `.txt` com uma conta por linha |
| `-ReportHTML` | `string` | Não | Caminho de saída do report HTML (gerado automaticamente se omitido) |
| `-ExportCSV` | `string` | Não | Caminho de saída do arquivo CSV |

> Se nenhum parâmetro for fornecido, o script entra em modo interativo.

---

## Grupos Monitorados e Níveis de Risco

| Nível | Grupos |
|-------|--------|
| 🔴 **CRÍTICO** | Domain Admins, Enterprise Admins, Schema Admins, Administrators |
| 🟠 **ALTO** | Account Operators, Backup Operators, Server Operators, Print Operators, Group Policy Creator Owners, DnsAdmins |
| 🟡 **MÉDIO** | DHCP Administrators, Remote Desktop Users, Network Configuration Operators, Cryptographic Operators, Distributed COM Users |
| 🔵 **BAIXO** | Event Log Readers, Cert Publishers, Protected Users |

### Adicionando grupos customizados

Edite o bloco `$script:PrivilegedGroupRisk` no início do script:

```powershell
$script:PrivilegedGroupRisk = [ordered]@{
    # grupos nativos...
    "TI-Administradores" = "ALTO"
    "SOC-Analistas"      = "MEDIO"
}
```

---

## Report HTML

O report é gerado automaticamente na pasta atual com o nome:

```
PrivilegedAccounts_Report_YYYYMMDD_HHmmss.html
```

O arquivo é aberto no browser ao final da execução e contém:

- **Dashboard** com contagem total por nível de risco
- **Tabela de inventário** com todos os atributos de cada conta
- **Plano de sanitização** com comandos PowerShell prontos para remoção de privilégios
<img width="800" height="382" alt="image" src="https://github.com/user-attachments/assets/317ab4cd-3821-4397-85a3-ff4d1da9d3ca" />



---

## Exportação CSV

O CSV exportado contém as seguintes colunas:

```
Usuario, DisplayName, Encontrado, Privilegiado, ContaAtiva,
UltimoLogin, SenhaCriada, SenhaNuncaExpira, Bloqueada,
GruposPriv, RiscoMaximo, TotalGruposPriv
```

---

## Sanitização

Para cada conta privilegiada encontrada, o script gera os comandos de remoção correspondentes. Exemplo:

```powershell
Remove-ADGroupMember -Identity "Domain Admins"  -Members "bill.gates" -Confirm:$false
Remove-ADGroupMember -Identity "Administrators" -Members "bill.gates" -Confirm:$false
```

> ⚠️ **Recomendações antes de executar:**
> - Valide o impacto com o time de TI e negócio
> - Teste em ambiente de homologação
> - Registre as alterações no processo de Change Management
> - Execute com uma conta Domain Admin

---

## Aviso Legal

Este script é fornecido para fins educacionais e de auditoria de segurança. Utilize apenas em ambientes nos quais você tenha autorização explícita. O autor não se responsabiliza por uso indevido.

---

<p align="center">
  <a href="https://hackershive.io">hackershive.io</a> &nbsp;|&nbsp;
  <a href="https://danieldonda.com">danieldonda.com</a> &nbsp;|&nbsp;
  <a href="https://youtube.com/@danieldonda">YouTube @danieldonda</a>
</p>
