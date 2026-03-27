# Ubuntu Server: Estado Atual

## Escopo
Este documento registra o estado operacional esperado do servidor Ubuntu que hospeda o ERP-TI e o cofre, com base na validacao feita em 27 de marco de 2026.

Ele serve como referencia de:
- topologia dos servicos
- portas e responsabilidades
- caminhos e comandos de operacao
- hardening aplicado
- AppArmor
- deploy, verificacao e rollback

Importante:
- este documento descreve o estado validado em producao na data acima
- se algo for alterado no servidor depois disso, use os comandos de verificacao ao final para confirmar o estado real

## Resumo rapido
Estado validado em 27/03/2026:
- host: `srvglpi`
- sistema: Ubuntu 24.04.3 LTS
- ERP-TI: porta `8000`
- GLPI/Apache: porta `8080`
- Caddy: porta `80`
- `443`: nao estava em uso na validacao
- firewall `ufw`: inativo na validacao
- repositorio de producao: `/opt/erp-ti`
- usuario do servico ERP: `ti`
- deploy por atalho: `erp-deploy`
- AppArmor do ERP: perfil `erp-ti-python`

## Host validado

### Identificacao
- hostname: `srvglpi`
- sistema operacional: Ubuntu 24.04.3 LTS
- kernel validado: `6.8.0-106-generic`
- virtualizacao observada: Microsoft Hyper-V

### Recursos observados na validacao
- memoria: 7.8 GiB
- swap: 4.0 GiB
- disco raiz: 61 GiB com folga ampla

## Topologia dos servicos

### ERP-TI
- servico: `erp-ti.service`
- bind: `0.0.0.0:8000`
- stack: Django + Gunicorn
- usuario: `ti`
- working directory: `/opt/erp-ti`

### GLPI
- servico: `apache2.service`
- bind: `:8080`
- funcao: sistema legado/GLPI separado do ERP-TI

### Proxy/entrada HTTP
- servico: `caddy.service`
- bind: `:80`
- funcao: entrada HTTP do host

### HTTPS
Estado observado na validacao:
- porta `443` nao estava ativa

Se isso mudar depois, valide com:
```bash
ss -ltnp | grep -E ':80|:443|:8000|:8080'
```

## Estrutura de caminhos

### Aplicacao ERP
- raiz do projeto: `/opt/erp-ti`
- ambiente virtual: `/opt/erp-ti/.venv`
- entrypoint do Gunicorn: `/opt/erp-ti/.venv/bin/gunicorn`
- settings do Django: `config.settings`

### Systemd
- unit principal: `/etc/systemd/system/erp-ti.service`
- drop-ins: `/etc/systemd/system/erp-ti.service.d/`

### AppArmor
- perfil: `/etc/apparmor.d/erp-ti-python`

### Secrets e envs
- env principal da app: `/opt/erp-ti/.env`
- env adicional historico: `/etc/erp-ti/erp-ti.env`
- segredos externos previstos no perfil: `/etc/erp-ti/secrets/`

## Unit do ERP

### Estado esperado
O servico do ERP deve continuar simples e previsivel:

```ini
[Unit]
Description=ERP TI Django
After=network.target

[Service]
User=ti
Group=ti
WorkingDirectory=/opt/erp-ti
ExecStart=/opt/erp-ti/.venv/bin/gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Validar unit real
```bash
systemctl cat erp-ti
```

## Hardening systemd

### Estrategia aplicada
O endurecimento do host foi reintroduzido em camadas pequenas, com validacao funcional do ERP e do cofre a cada etapa.

### Arquivo legado desativado
Permaneceu desativado:
- `/etc/systemd/system/erp-ti.service.d/10-hardening.conf.disabled`

Esse arquivo representa uma tentativa anterior mais agressiva que foi desativada para estabilizar a producao.

### Drop-ins de hardening leve/gradual
Os nomes esperados dos drop-ins aplicados sao:
- `11-hardening-light.conf`
- `12-hardening-capabilities.conf`
- `13-hardening-isolation.conf`
- `14-hardening-filesystem.conf`

### Controles que ja foram validados
- `UMask=0077`
- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `ProtectControlGroups=true`
- `ProtectKernelTunables=true`
- `ProtectKernelModules=true`
- `ProtectKernelLogs=true`
- `RestrictSUIDSGID=true`
- `LockPersonality=true`
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
- `SystemCallArchitectures=native`
- `CapabilityBoundingSet=`
- `AmbientCapabilities=`
- `RestrictNamespaces=true`
- `RestrictRealtime=true`
- `ProtectHome=true`
- `PrivateDevices=true`
- `ProtectClock=true`

### Filesystem hardening
O endurecimento de filesystem foi o mais sensivel do rollout.

Licao operacional:
- `ProtectSystem=strict` sozinho nao basta
- caminhos de escrita precisam estar explicitamente em `ReadWritePaths`
- erros de schema legado podem parecer erro de hardening, por isso troubleshooting deve sempre olhar o `journalctl`

Estado operacional recomendado:
- manter a configuracao de filesystem que foi validada em producao
- se houver duvida, confirmar o estado real com:

```bash
systemctl cat erp-ti
ls -la /etc/systemd/system/erp-ti.service.d
cat /etc/systemd/system/erp-ti.service.d/14-hardening-filesystem.conf
```

## AppArmor

### Perfil em uso
Arquivo:
- `/etc/apparmor.d/erp-ti-python`

Conteudo validado:
- leitura em `/opt/erp-ti/**`
- escrita em `/var/lib/erp-ti/**`, `/var/log/erp-ti/**`, `/run/erp-ti/**`
- leitura em `/etc/erp-ti/secrets/**`
- rede `inet`, `inet6` e `unix`
- `deny /root/**`

### Modo validado
Fluxo usado:
1. `complain`
2. testes funcionais completos
3. revisao de logs
4. `enforce`

Na validacao final, o perfil ficou aceitavel para uso real.

### Comandos uteis
```bash
aa-status | grep -i erp-ti
journalctl -k -n 200 --no-pager | grep -i "apparmor.*erp-ti-python" || true
```

## Porta e conectividade

### Estado validado
- `:8000` -> ERP-TI / Gunicorn
- `:8080` -> Apache / GLPI
- `:80` -> Caddy
- `:443` -> nao ativo na validacao

### Comando de conferencia
```bash
ss -ltnp | grep -E ':80|:443|:8000|:8080'
```

## Firewall

### Estado observado
Na validacao de 27/03/2026:
- `ufw` estava `inactive`

### Conferir novamente
```bash
ufw status verbose
```

## Repositorio e deploy

### Caminho do projeto
- `/opt/erp-ti`

### Branch validada em producao
Durante a reimplantacao segura do cofre, a branch ativa validada foi:
- `vault-reimpl-safe`

Como isso pode mudar com o tempo, sempre conferir:
```bash
cd /opt/erp-ti
git branch --show-current
git rev-parse --short HEAD
```

### Deploy
Atalho operacional:
- `erp-deploy`

Implementacao:
- symlink/atalho para `/opt/erp-ti/scripts/deploy_linux.sh`

Script:
- [deploy_linux.sh](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\scripts\deploy_linux.sh)

### O que o deploy faz
- verifica worktree limpo
- atualiza a branch atual
- instala dependencias
- faz backup do banco
- roda `manage.py check`
- roda `manage.py migrate --noinput`
- reinicia `erp-ti`

## Estado atual do cofre no Ubuntu

### Fluxo funcional validado
- abrir `/cofre/`
- desbloquear cofre
- cadastrar credencial
- editar credencial
- revelar senha
- excluir credencial
- trocar senha secundaria
- expirar sessao e bloquear automaticamente

### Restricao de usuarios
Usuarios autorizados validados:
- `fabiano.polone`
- `fabio.generoso`

### Dependencias operacionais
- `VAULT_MASTER_KEY` ainda reside no `.env`
- senha secundaria do cofre migrou para hash no banco
- `VAULT_ACCESS_PASSWORD` e `VAULT_ACCESS_PASSWORD_HASH` devem permanecer ausentes do `.env` apos bootstrap

### Migrations estruturais importantes ja necessarias em producao
- `0076`
- `0078`
- `0079`

Essas migrations corrigem os problemas reais encontrados no schema legado do SQLite.

## Incidentes importantes aprendidos no rollout

### 1. Cofre nao pode derrubar o ERP
Falha anterior:
- configuracao do cofre derrubando a inicializacao

Diretriz atual:
- o cofre precisa sempre falhar de forma isolada

### 2. Schema legado enganou o diagnostico
Falha real observada:
- `NOT NULL constraint failed: core_passwordvaultitem.account_username`

Isso mostrou que parte dos erros vistos durante hardening nao eram de host, mas do schema antigo do banco.

### 3. `sudo -i` separado atrapalhou operacao
Licao pratica:
- em operacao remota, prefira blocos `sudo bash -lc '...'`
- evita que o shell entre em outro contexto e deixe metade dos comandos sem executar

## Comandos de verificacao rapida

### Estado geral
```bash
hostnamectl
systemctl --no-pager --full status erp-ti
systemctl --no-pager --full status caddy
systemctl --no-pager --full status apache2
```

### Portas
```bash
ss -ltnp | grep -E ':80|:443|:8000|:8080'
```

### ERP
```bash
curl -I --max-time 5 http://127.0.0.1:8000/login/
journalctl -u erp-ti -n 120 --no-pager
```

### AppArmor
```bash
aa-status | grep -i erp-ti
journalctl -k -n 200 --no-pager | grep -i "apparmor.*erp-ti-python" || true
```

### Hardening do servico
```bash
systemctl cat erp-ti
ls -la /etc/systemd/system/erp-ti.service.d
```

## Rollback rapido

### Voltar AppArmor para complain
```bash
aa-complain erp-ti-python
systemctl restart erp-ti
```

### Remover camada de filesystem hardening
```bash
rm -f /etc/systemd/system/erp-ti.service.d/14-hardening-filesystem.conf
systemctl daemon-reload
systemctl restart erp-ti
```

### Voltar codigo para main
```bash
cd /opt/erp-ti
git fetch origin
git checkout main
git reset --hard origin/main
systemctl restart erp-ti
```

## Riscos residuais do host

### 1. `VAULT_MASTER_KEY` ainda local
Este continua sendo o principal risco operacional do cofre no servidor.

### 2. `443` nao validado na mesma rodada
Na validacao base, a porta `443` nao estava ativa. Se o acesso HTTPS fizer parte do objetivo final, isso precisa de uma rodada propria de configuracao e teste.

### 3. Firewall do host inativo
`ufw` estava inativo na rodada validada. Se a politica da empresa exigir filtragem no host, essa frente ainda precisa de planejamento separado.

## Proximos passos recomendados no Ubuntu
1. mover `VAULT_MASTER_KEY` para fonte externa controlada
2. revisar politica de backup da chave mestre e do banco
3. validar estrategia de `443` com Caddy
4. revisar se `ufw` deve continuar inativo
5. manter a regra: qualquer endurecimento novo sobe uma camada por vez
