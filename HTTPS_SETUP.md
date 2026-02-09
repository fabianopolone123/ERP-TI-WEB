# HTTPS na rede interna (outros PCs)

## 1) No servidor ERP
Abra PowerShell como administrador e execute:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_https.ps1 -HostName erp-ti.local -ServerIP 192.168.22.10
```

Troque:
- `erp-ti.local` pelo hostname que voce quer usar
- `192.168.22.10` pelo IP do servidor ERP na rede

Depois inicie:

```bat
start_erp_https.bat
```

## 2) Em cada PC cliente
### 2.1 hosts
Editar `C:\Windows\System32\drivers\etc\hosts` e adicionar:

```txt
192.168.22.10    erp-ti.local
```

### 2.2 Certificado raiz
Copiar do servidor:

```txt
%APPDATA%\Caddy\pki\authorities\local\root.crt
```

Instalar em:
- `Trusted Root Certification Authorities` (Computador Local)

## 3) Acesso
No cliente, abrir:

```txt
https://erp-ti.local
```

## Observacoes
- Sem HTTPS em outro PC, captura de tela do navegador pode ser bloqueada.
- `localhost` so funciona como contexto seguro na propria maquina.
