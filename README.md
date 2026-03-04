# ERP-TI-WEB

## HTTPS para rede interna
Veja HTTPS_SETUP.md para configurar acesso HTTPS em outros PCs.

## Inventario automatico via script (GPO)
Para inventariar PCs automaticamente sem depender de acesso remoto por WMI:

1. Configure no `.env` do servidor:
- `INVENTORY_AGENT_TOKEN=<token-forte>`

2. Copie `scripts/inventory_agent.ps1` para os computadores (ex.: `C:\ProgramData\ERP-TI\inventory_agent.ps1`).

3. Endpoint de recebimento no ERP:
- `POST /api/inventory/push/`
- Header: `Authorization: Bearer <token>`

As abas `Equipamentos` e `Softwares` serao atualizadas automaticamente quando cada script enviar os dados.

Instalacao da tarefa nas maquinas (GPO startup):

Opcao recomendada (evita bloqueios de script via UNC):
1. Em `Startup Scripts` da GPO, use o arquivo `bootstrap_inventory_agent_gpo.cmd`.
2. Passe parametros:
```bat
http://ti-fabiano:8000 inv-4303e90894724852b3f2ea858209b010-5f506a1ec1b5 45
```
3. O bootstrap copia os arquivos para `C:\ProgramData\ERP-TI\bootstrap`, faz `Unblock-File`, instala/atualiza as tarefas de envio no startup/logon e grava log em:
- `C:\ProgramData\ERP-TI\logs\gpo_bootstrap.log`

Opcao direta (PowerShell):
```powershell
powershell -ExecutionPolicy Bypass -File "\\servidor\deploy\install_inventory_agent_service.ps1" `
  -ServerBaseUrl "https://erp-ti.local" `
  -Token "<token-forte>"
```

Arquivos envolvidos:
- `scripts/bootstrap_inventory_agent_gpo.cmd`
- `scripts/inventory_agent.ps1`
- `scripts/install_inventory_agent_service.ps1`

Observacao:
- Se quiser desativar envio automatico no logon, use `-EnableLogonPush $false` no instalador.
- Se quiser desativar envio automatico no reinicio, use `-EnableStartupPush $false` no instalador.
