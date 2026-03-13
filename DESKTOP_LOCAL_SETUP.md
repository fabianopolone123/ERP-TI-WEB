# ERP TI como app desktop por maquina

Este fluxo usa o ERP web (Django) com cliente em modo app (Edge/Chrome) instalado em cada computador.

## 1) Servidor

1. Configure e inicie o ERP normalmente.
2. Se usar HTTPS interno, siga `HTTPS_SETUP.md`.
3. Garanta que os clientes acessam a URL do ERP (exemplo: `https://erp-ti.local`).

## 2) Publicar versao (para notificar atualizacao)

Quando houver nova atualizacao no servidor (deploy), execute:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\bump_release_version.ps1
```

Opcionalmente, publique uma versao manual:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\bump_release_version.ps1 -Version 2026.03.04-1
```

Isso atualiza `.release-version` e os clientes passam a receber aviso de "Nova versao disponivel".

## 3) Instalar app desktop em cada PC

No computador do usuario:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_desktop_app_edge.ps1 -AppUrl "https://erp-ti.local"
```

Opcoes uteis:

```powershell
# Com inicializacao automatica no logon
powershell -ExecutionPolicy Bypass -File scripts\install_desktop_app_edge.ps1 -AppUrl "https://erp-ti.local" -InstallStartup

# Se ainda nao instalou o certificado raiz HTTPS no cliente (apenas teste)
powershell -ExecutionPolicy Bypass -File scripts\install_desktop_app_edge.ps1 -AppUrl "https://erp-ti.local" -AllowInsecureTls
```

## 4) Comportamento de atualizacao no cliente

- O app verifica versao no endpoint `GET /api/app/version/`.
- Quando a versao mudar, aparece aviso no canto da tela.
- Usuario clica em **Atualizar agora** para recarregar o app.

## 5) Variaveis opcionais no `.env`

```env
ERP_APP_VERSION=
ERP_APP_VERSION_FILE=.release-version
```

- `ERP_APP_VERSION`: se preenchida, tem prioridade e trava versao fixa.
- `ERP_APP_VERSION_FILE`: arquivo usado para ler versao publicada.
