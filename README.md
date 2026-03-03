# ERP-TI-WEB

## HTTPS para rede interna
Veja HTTPS_SETUP.md para configurar acesso HTTPS em outros PCs.

## Inventario automatico via agente (GPO)
Para inventariar PCs automaticamente sem depender de acesso remoto por WMI:

1. Configure no `.env` do servidor:
- `INVENTORY_AGENT_TOKEN=<token-forte>`

2. Copie `scripts/inventory_agent.ps1` para os computadores (ex.: `C:\ProgramData\ERP-TI\inventory_agent.ps1`).

3. Registre a tarefa agendada (boot + diario) em cada maquina:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/register_inventory_task.ps1 `
  -ScriptPath "C:\ProgramData\ERP-TI\inventory_agent.ps1" `
  -ServerUrl "https://erp-ti.local/api/inventory/push/" `
  -Token "<token-forte>"
```

Opcionalmente, o `scripts/inventory_agent_run.bat` usa o token da variavel de ambiente
`INVENTORY_AGENT_TOKEN` (ou recebe o token no segundo parametro).

4. Endpoint de recebimento no ERP:
- `POST /api/inventory/push/`
- Header: `Authorization: Bearer <token>`

As abas `Equipamentos` e `Softwares` serao atualizadas automaticamente quando cada agente enviar os dados.

## Inventario sob demanda (daemon via tarefa agendada)
Agora o ERP tambem permite solicitar atualizacao de um host especifico (botao `Atualizar` em `Equipamentos`).

Fluxo:
1. TI clica em `Atualizar` no equipamento.
2. O ERP cria uma solicitacao pendente para o host.
3. A tarefa agendada SYSTEM executa `inventory_agent_daemon.ps1`, que consulta periodicamente `/api/inventory/pull-next/`.
4. Quando recebe uma solicitacao, executa `inventory_agent.ps1` local e envia para `/api/inventory/push/`.
5. Ao logon de usuario no Windows, a tarefa `ERP TI Inventory Agent - Logon Push` envia uma coleta imediata para atualizar usuario logado/softwares.

Atualizacao em massa (sem sobrecarregar a rede):
- Na tela `Equipamentos`, use o botao `Atualizar todos os PCs`.
- O ERP enfileira os hosts conhecidos e o processamento ocorre em lotes.
- Limites configuraveis no `.env`:
  - `INVENTORY_AGENT_MAX_CONCURRENT_RUNNING` (padrao `8`)
  - `INVENTORY_REFRESH_RUNNING_TIMEOUT_MINUTES` (padrao `30`)
  - `INVENTORY_REFRESH_ALL_MAX_HOSTS` (padrao `500`)

Instalacao da tarefa nas maquinas (GPO startup):

Opcao recomendada (evita bloqueios de script via UNC):
1. Em `Startup Scripts` da GPO, use o arquivo `bootstrap_inventory_agent_gpo.cmd`.
2. Passe parametros:
```bat
http://ti-fabiano:8000 inv-4303e90894724852b3f2ea858209b010-5f506a1ec1b5 45
```
3. O bootstrap copia os arquivos para `C:\ProgramData\ERP-TI\bootstrap`, faz `Unblock-File`, instala/atualiza a tarefa SYSTEM e grava log em:
- `C:\ProgramData\ERP-TI\logs\gpo_bootstrap.log`

Opcao direta (PowerShell):
```powershell
powershell -ExecutionPolicy Bypass -File "\\servidor\deploy\install_inventory_agent_service.ps1" `
  -ServerBaseUrl "https://erp-ti.local" `
  -Token "<token-forte>" `
  -PollIntervalSec 45
```

Arquivos envolvidos:
- `scripts/bootstrap_inventory_agent_gpo.cmd`
- `scripts/inventory_agent.ps1`
- `scripts/inventory_agent_daemon.ps1`
- `scripts/install_inventory_agent_service.ps1`

Observacao:
- Se quiser desativar envio automatico no logon, use `-EnableLogonPush $false` no instalador.

## Agente VNC como servico (GPO)
Para acesso remoto de tela sem depender de protocolo RDP no navegador:

1. Copie `scripts/install_vnc_agent.ps1` para os computadores (ex.: `C:\ProgramData\ERP-TI\install_vnc_agent.ps1`).
2. Na GPO de startup (computador), execute:
```powershell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\ERP-TI\install_vnc_agent.ps1 `
  -InstallerPath "\\servidor\deploy\TightVNC.msi" `
  -AllowedRemote "10.0.0.0/8,192.168.0.0/16"
```
3. O script instala o TightVNC, garante o servico `tvnserver` automatico e cria regra de firewall na porta 5900.

Observacoes:
- Execute com privilegio de Administrador (startup de computador ja atende).
- Se nao informar `-InstallerPath`, ele tenta instalar via `winget` (`GlavSoft.TightVNC`).
- O botao `VNC` no modulo `Equipamentos` usa `vnc://HOST:5900`.
