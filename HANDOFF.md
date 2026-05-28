# HANDOFF - EmbedXPL-Forge

## [2026-05-28 17:50] - CVE-2026-35616 rewrite + FIRESTARTER chain + catalog update

### Estado ao encerrar
- Reescrito `forticlient_ems_preauth_rce_cve_2026_35616.py` (v1.1.0 -> v2.0.0):
  - Versao anterior usava credential stuffing (incorreto)
  - Nova versao implementa mecanismo real: HTTP header spoofing via X-SSL-CLIENT-VERIFY
  - DN-only certificate bypass (sem verificacao X.509) + forged PEM com DN strings Fortinet
  - Fases: bypass probe, endpoint enumeration, EKZ-style update push (demo)
- Adicionado `cisco_asa_ftd_firestarter_chain_cve_2025_20362_20333.py` em `exploits/firewalls/cisco/`
  - Cobre CVE-2025-20362 (pre-auth URL bypass) + CVE-2025-20333 (post-auth RCE, CVSS 9.9)
  - APT UAT4356/ArcaneDoor, CISA AR26-113A + ED 25-03
  - Fonte: `C:\Users\mrhen\OneDrive\Guides\OT-IOT-ICS-SCADA\Firestarter Backdoor.pdf`
- Atualizado `embedxpl/resources/catalogs/cve_extended_catalog.json`:
  - +4 novas entradas: CVE-2026-35616, CVE-2026-24858, CVE-2025-20362, CVE-2025-20333
  - entry_count: 350 -> 354 | last_updated: 2026-05-28

### Arquivos modificados
- `embedxpl/modules/exploits/firewalls/fortinet/forticlient_ems_preauth_rce_cve_2026_35616.py` (reescrito)
- `embedxpl/modules/exploits/firewalls/cisco/cisco_asa_ftd_firestarter_chain_cve_2025_20362_20333.py` (novo)
- `embedxpl/resources/catalogs/cve_extended_catalog.json` (atualizado)

### Proximo passo imediato
- Verificar se `tools/phase_gate.py` passa em todos os novos modulos
- Executar `tools/gen_wiki_module_index.py` para regenerar ANEXO-INDICE-MODULOS.md
- Considerar adicionar NSE Nmap para CVE-2026-35616 em `nse/`

### Pendencias conhecidas
- [ ] Regenerar wiki index com `python tools/gen_wiki_module_index.py`
- [ ] Adicionar modulo `fortiweb/fortiweb_*_cve_2025_25257.py` ao FWX (ja existe no EmbedXPL)
- [ ] Adicionar CVE-2025-59718/59719 FortiOS SSO ao catalogo estendido quando PoC publica disponivel
- [ ] Revisitar EmbedXPL v3.2.0 release com novos modulos

### Ambiente necessario
- Python 3.8+
- `pip install -r requirements.txt`
- Windows: `D:\Projetos-SafeLabs\submodules\IoT\EmbedXPL-Forge`
- Linux: `/mnt/predator/Projetos-SafeLabs/submodules/IoT/EmbedXPL-Forge`

### Paths importantes
- Windows: `D:\Projetos-SafeLabs\submodules\IoT\EmbedXPL-Forge`
- Linux: `/mnt/predator/Projetos-SafeLabs/submodules/IoT/EmbedXPL-Forge`
