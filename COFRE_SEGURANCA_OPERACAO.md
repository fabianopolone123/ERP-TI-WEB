# Cofre: Seguranca e Operacao

## Objetivo
Este documento registra o desenho atual de seguranca do cofre, a ordem segura de deploy em producao, os controles ja aplicados no Ubuntu e os procedimentos de validacao, troubleshooting e rollback.

O foco aqui e evitar dois tipos de falha:
- o cofre derrubar o ERP inteiro na inicializacao
- endurecimentos de host ou schema legado quebrarem o uso normal do cofre

## Resumo executivo
No estado atual, o cofre ja esta em um nivel bom para uso real interno, com protecoes relevantes na aplicacao e no host. Ao mesmo tempo, ele ainda nao e o estado final ideal de seguranca porque a `VAULT_MASTER_KEY` continua no `.env` do servidor e ainda nao foi movida para uma fonte externa dedicada.

## Principios adotados
- Falha isolada: o cofre nunca deve derrubar o boot do ERP.
- Rollout em camadas: funcionalidade primeiro, hardening depois.
- Segredo operacional separado: a senha secundaria do cofre nao deve depender permanentemente de texto puro no `.env`.
- Endurecimento reversivel: toda camada de seguranca precisa ter rollback simples.
- Compatibilidade com legado: migrations precisam reparar schema antigo sem destruir dados.

## Arquitetura atual do cofre

### Componentes principais
- Criptografia do cofre: [core/vault_crypto.py](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\core\vault_crypto.py)
- Regras e fluxo da tela do cofre: [core/views.py](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\core\views.py)
- Interface do cofre: [templates/core/cofre.html](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\templates\core\cofre.html)
- Modelo das credenciais: [core/models.py](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\core\models.py)
- Auditoria: [core/audit.py](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\core\audit.py)
- Hardening de sessao TI: [core/middleware.py](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\core\middleware.py)

### Migrations relevantes do cofre
- [0075_passwordvaultitem.py](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\core\migrations\0075_passwordvaultitem.py): tabela principal do cofre
- [0076_passwordvaultitem_legacy_schema_repair.py](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\core\migrations\0076_passwordvaultitem_legacy_schema_repair.py): adiciona colunas criptografadas ausentes em bases antigas
- [0077_passwordvaultaccessconfig.py](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\core\migrations\0077_passwordvaultaccessconfig.py): cria configuracao da senha secundaria do cofre
- [0078_bootstrap_vault_access_password_config.py](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\core\migrations\0078_bootstrap_vault_access_password_config.py): materializa a senha secundaria no banco
- [0079_rebuild_legacy_passwordvaultitem_table.py](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\core\migrations\0079_rebuild_legacy_passwordvaultitem_table.py): reconstrucao segura da tabela antiga do cofre

## Controles de seguranca da aplicacao

### 1. Feature flag
O cofre so e habilitado se `FEATURE_VAULT_ENABLED=True`.

### 2. Restricao por usuarios autorizados
O cofre e liberado apenas para usernames definidos em `VAULT_ALLOWED_USERNAMES`.

Observacoes:
- a comparacao e normalizada para cenarios AD
- formatos aceitos: `usuario`, `DOMINIO\\usuario`, `usuario@dominio`
- a validacao exige tambem que o usuario esteja em `department=TI`

### 3. Criptografia das credenciais
As credenciais do cofre usam criptografia simetrica baseada em `cryptography` e derivacao da chave a partir de:
- `VAULT_MASTER_KEY`
- `VAULT_KEY_SALT`

Campos criptografados:
- `account_username_encrypted`
- `account_url_encrypted`
- `password_encrypted`
- `notes_encrypted`

### 4. Senha secundaria do cofre
O acesso ao cofre exige uma senha secundaria, separada do login do ERP.

Estado atual:
- a senha secundaria fica persistida por hash no banco
- o `.env` e usado apenas para bootstrap ou recuperacao inicial
- depois da migration de bootstrap, `VAULT_ACCESS_PASSWORD` e `VAULT_ACCESS_PASSWORD_HASH` devem ser removidos do servidor

### 5. Sessao temporaria do cofre
Ao desbloquear o cofre:
- a sessao e liberada por `VAULT_UNLOCK_SESSION_MINUTES`
- existe countdown visual na tela
- ao expirar, o cofre volta a bloquear automaticamente

### 6. Reveal sem senha extra enquanto o cofre estiver desbloqueado
Decisao atual de UX e seguranca:
- enquanto a sessao do cofre estiver desbloqueada, `Revelar senha` nao pede a senha secundaria novamente
- se a sessao do cofre expirar, o usuario precisa desbloquear o cofre de novo

### 7. Troca da senha secundaria pela tela
A senha secundaria do cofre pode ser alterada na propria pagina do cofre.

### 8. Rate limit de login
O ERP aplica limitacao de tentativas invalidas de login.

Configuracoes:
- `LOGIN_RATE_LIMIT_WINDOW_MINUTES`
- `LOGIN_RATE_LIMIT_MAX_FAILURES_PER_USER_IP`
- `LOGIN_RATE_LIMIT_MAX_FAILURES_PER_IP`

### 9. Timeout de sessao TI
Usuarios do TI passam por hardening de sessao na middleware.

Configuracoes:
- `TI_SESSION_IDLE_MINUTES`
- `TI_SESSION_ACTIVITY_GRACE_SECONDS`

### 10. Auditoria
Eventos do cofre sao auditados:
- desbloqueio
- bloqueio manual
- troca da senha secundaria
- cadastro, edicao e exclusao de credenciais
- visualizacao de senha

Importante:
- auditoria e `best effort`
- falha na auditoria nao pode derrubar a operacao do cofre

## Controles de seguranca do host

### Servico systemd
O servico base do ERP deve permanecer simples:
- arquivo: `/etc/systemd/system/erp-ti.service`
- usuario atual: `ti`
- diretorio de trabalho: `/opt/erp-ti`

### Drop-ins de hardening aplicados em camadas
No Ubuntu, os endurecimentos foram aplicados gradualmente via drop-ins em:
- `/etc/systemd/system/erp-ti.service.d/`

Camadas tipicas aplicadas:
- `11-hardening-light.conf`
- `12-hardening-capabilities.conf`
- `13-hardening-isolation.conf`
- `14-hardening-filesystem.conf`

Direcao das camadas:
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
- `ProtectSystem=full` ou `ProtectSystem=strict` com `ReadWritePaths` minimos

### AppArmor
Perfil em uso no Ubuntu:
- `/etc/apparmor.d/erp-ti-python`

Perfil observado:
- leitura em `/opt/erp-ti/**`
- escrita controlada em `/var/lib/erp-ti/**`, `/var/log/erp-ti/**`, `/run/erp-ti/**`
- leitura em `/etc/erp-ti/secrets/**`
- rede `inet`, `inet6` e `unix`
- `deny /root/**`

Fluxo recomendado:
1. `complain`
2. testes funcionais completos
3. revisao de logs
4. `enforce`

## Variaveis de ambiente do cofre
Referencia atual em [config/settings.py](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\config\settings.py) e [.env.example](c:\Users\fabiano.polone\Documents\ERP-TI-WEB\.env.example).

### Minimas para funcionamento
- `FEATURE_VAULT_ENABLED`
- `VAULT_ALLOWED_USERNAMES`
- `VAULT_MASTER_KEY`
- `VAULT_KEY_SALT`
- `VAULT_UNLOCK_SESSION_MINUTES`

### Bootstrap/legado da senha secundaria
- `VAULT_ACCESS_PASSWORD`
- `VAULT_ACCESS_PASSWORD_HASH`

Importante:
- essas duas nao devem permanecer indefinidamente no servidor
- depois do bootstrap e validacao, remover do `.env`

### Controles de tempo e bloqueio
- `VAULT_UNLOCK_SESSION_MINUTES`
- `VAULT_UNLOCK_MAX_ATTEMPTS`
- `VAULT_UNLOCK_BLOCK_WINDOW_MINUTES`

### Configs ainda presentes, mas hoje sem uso funcional no reveal
- `VAULT_REVEAL_MAX_ATTEMPTS`
- `VAULT_REVEAL_BLOCK_WINDOW_MINUTES`

## Ordem segura de deploy
Esta foi a ordem que evitou novos incidentes:
1. baseline estavel do ERP
2. branch do cofre com feature flag desligada
3. migrations
4. habilitar cofre
5. validar fluxo funcional
6. migrar senha secundaria para hash no banco
7. remover segredo legado do `.env`
8. aplicar hardening do host em camadas
9. AppArmor `complain`
10. AppArmor `enforce`

## Checklist de validacao em producao

### Apos deploy
- `python manage.py check`
- `python manage.py migrate --noinput`
- `systemctl --no-pager --full status erp-ti`
- `curl -I http://127.0.0.1:8000/login/`

### Teste funcional do cofre
1. login com usuario autorizado
2. abrir `/cofre/`
3. desbloquear o cofre
4. cadastrar credencial de teste
5. revelar senha
6. editar credencial
7. excluir credencial
8. trocar senha secundaria
9. esperar expirar a sessao do cofre
10. confirmar bloqueio automatico

## Troubleshooting

### 1. ERP nao sobe por causa do cofre
- conferir `FEATURE_VAULT_ENABLED`
- conferir `VAULT_MASTER_KEY`
- o cofre nunca deve ser condicao para o boot do ERP

### 2. Unlock do cofre funciona, mas listar itens quebra
Exemplo tipico:
- `no such column: core_passwordvaultitem.account_username_encrypted`

Causa:
- schema legado parcial no SQLite

Correcoes relacionadas:
- migration `0076`
- migration `0079`

### 3. Cadastro de nova credencial falha com erro de banco
Sintoma real observado:
- `NOT NULL constraint failed: core_passwordvaultitem.account_username`

Causa:
- tabela antiga ainda exigia colunas legadas `account_username`/`account_url`

Correcao:
- migration `0079_rebuild_legacy_passwordvaultitem_table`

### 4. Usuario autorizado do AD nao entra no cofre
Causa tipica:
- diferenca entre formatos:
  - `usuario`
  - `DOMINIO\\usuario`
  - `usuario@dominio`

Diretriz:
- manter comparacao normalizada
- conferir `VAULT_ALLOWED_USERNAMES`
- conferir `ERPUser.department=TI`

### 5. Hardening quebra gravacao do ERP
Sintoma:
- leitura funciona
- gravacao falha
- `500` ao cadastrar/editar

Causa tipica:
- `ProtectSystem=strict` sem `ReadWritePaths` suficientes

Conduta:
- voltar uma camada
- confirmar caminho real de escrita do banco e arquivos
- reintroduzir a regra gradualmente

### 6. Erros de auditoria
Diretriz:
- auditoria nunca deve quebrar a funcionalidade
- `log_audit_event()` precisa permanecer tolerante a falhas

## Rollback

### Rollback de codigo
```bash
cd /opt/erp-ti
git fetch origin
git checkout main
git reset --hard origin/main
systemctl restart erp-ti
```

### Rollback de hardening do filesystem
```bash
rm -f /etc/systemd/system/erp-ti.service.d/14-hardening-filesystem.conf
systemctl daemon-reload
systemctl restart erp-ti
```

### Rollback do AppArmor
```bash
aa-complain erp-ti-python
systemctl restart erp-ti
```

## Riscos residuais atuais
Mesmo com o estado atual bem melhor, estes riscos ainda existem:

### 1. `VAULT_MASTER_KEY` ainda no `.env`
Hoje este e o maior risco residual.

Se um invasor ler o `.env` e tiver acesso ao banco, consegue descriptografar o cofre.

### 2. Segregacao fina de acesso
O cofre hoje trabalha com allowlist de usuarios autorizados, nao com segregacao por item, dono, grupo ou classificacao.

### 3. Segredo mestre ainda local
Ainda nao existe integracao com KMS, HSM ou secret manager externo.

## Proximos passos recomendados

### Prioridade alta
1. mover `VAULT_MASTER_KEY` para fonte externa segura
2. documentar backup e recuperacao da chave mestre
3. registrar procedimento formal de troca da senha secundaria

### Prioridade media
1. remover configs antigas nao utilizadas do reveal
2. revisar se o perfil AppArmor pode ficar mais estrito
3. revisar se `ReadWritePaths` podem ser mais enxutos

### Prioridade baixa
1. segregacao por grupos ou proprietarios de credenciais
2. classificacao de sensibilidade dos itens do cofre
3. relatorio de auditoria especifico do cofre

## Decisoes operacionais importantes
- Nao reativar endurecimentos fortes todos de uma vez.
- Nao fazer rollout simultaneo de cofre, usuario de servico, KMS e hardening pesado.
- Nao manter `VAULT_ACCESS_PASSWORD` em texto puro apos o bootstrap.
- Nao promover hardening novo sem teste funcional completo do cofre.

## Comandos uteis

### Verificar branch e status do ERP
```bash
cd /opt/erp-ti
git branch --show-current
systemctl --no-pager --full status erp-ti
curl -I --max-time 5 http://127.0.0.1:8000/login/
```

### Verificar schema do cofre no SQLite
```bash
python - <<'PY'
import sqlite3
conn = sqlite3.connect('/opt/erp-ti/db.sqlite3')
cur = conn.cursor()
print(cur.execute('pragma table_info(core_passwordvaultitem)').fetchall())
PY
```

### Verificar AppArmor
```bash
aa-status | grep -i erp-ti
journalctl -k -n 200 --no-pager | grep -i "apparmor.*erp-ti-python" || true
```

### Verificar logs recentes do ERP
```bash
journalctl -u erp-ti -n 120 --no-pager
```

## Referencia rapida
- Cofre funcional nao pode derrubar o ERP.
- Senha secundaria deve ficar no banco, nao no `.env`.
- Reveal hoje usa apenas a sessao desbloqueada do cofre.
- `VAULT_MASTER_KEY` ainda e o principal ponto de endurecimento pendente.
