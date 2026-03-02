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
