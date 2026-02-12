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
  -ServerUrl "http://ti-fabiano:8000/api/inventory/push/" `
  -Token "<token-forte>"
```

4. Endpoint de recebimento no ERP:
- `POST /api/inventory/push/`
- Header: `Authorization: Bearer <token>`

As abas `Equipamentos` e `Softwares` serao atualizadas automaticamente quando cada agente enviar os dados.
