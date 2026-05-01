# Requisitos de Hardware

Este documento lista todos os adaptadores de hardware fisico que os modulos
do EmbedXPL-Forge podem requerer. Cada entrada inclui um produto recomendado,
informacoes de chipset, preco aproximado, links de compra, drivers/ferramentas
necessarios e compatibilidade de SO.

Os modulos declaram seus requisitos atraves da chave `required_hardware` no
dict `__info__`. O hardware gate do framework (`embedxpl.core.hardware`)
alerta o operador antes da execucao quando adaptadores fisicos sao necessarios.

Para uma versao gerada automaticamente deste arquivo (refletindo os dados
mais recentes dos modulos), execute:

```bash
python -m embedxpl.tools.docgen --lang en-US --output docs/en-US/
```

---

## Wi-Fi Monitor (`wifi_monitor_mode`)

Adaptador Wi-Fi com suporte a modo monitor e injecao de pacotes. Necessario
para sniffing passivo, frames de deautenticacao e criacao de frames 802.11
raw nas bandas 2.4/5 GHz.

| Campo | Valor |
|-------|-------|
| **Produto** | Alfa AWUS036ACH |
| **Chipset** | Realtek RTL8812AU |
| **Preco (USD)** | $65.00 |
| **Compra** | <https://www.alfa.com.tw/products/awus036ach> |
| **Drivers/Ferramentas** | aircrack-ng, rtl8812au-dkms, hostapd |
| **Suporte de SO** | Linux, Windows (limitado), macOS (limitado) |

### Notas de Uso

- Melhor desempenho no Linux com drivers rtl8812au patcheados.
- O modo monitor deve ser habilitado via `airmon-ng start wlan0`.
- Algumas revisoes de chipset requerem versoes especificas de firmware.
- Modulos que usam este adaptador: Wi-Fi deauth, captura de WPA handshake,
  evil twin AP, extracao de PMKID.

---

## Adaptador BLE (`ble_adapter`)

Adaptador USB Bluetooth Low Energy com acesso HCI raw. Necessario para
scanning de advertisements BLE, enumeracao de servicos GATT, spoofing
de dispositivos, hijack de pareamento e manipulacao de conexao.

| Campo | Valor |
|-------|-------|
| **Produto** | Sena UD100 / CSR 4.0 USB Dongle |
| **Chipset** | CSR8510 / TI CC2540 |
| **Preco (USD)** | $15.00 |
| **Compra** | <https://www.senanetworks.com/ud100.html> |
| **Drivers/Ferramentas** | bluez, hcitool, gatttool, bettercap |
| **Suporte de SO** | Linux, Windows, macOS |

### Notas de Uso

- Requer BlueZ 5.50+ para suporte completo a scanning BLE.
- A variante TI CC2540 oferece melhor acesso HCI raw para modo sniffer.
- Alguns modulos tambem suportam o Ubertooth One para sniffing na camada de enlace.
- Modulos que usam este adaptador: enumeracao BLE, fuzzing GATT,
  hijack de pareamento BLE, spoofing de beacon.

---

## SDR TX/RX (`sdr_txrx`)

Radio Definido por Software com capacidade de transmissao e recepcao. Usado
para captura de sinais em banda ISM, replay attacks e analise de protocolos RF
em sub-GHz (315/433/868/915 MHz) e frequencias de 2.4 GHz.

| Campo | Valor |
|-------|-------|
| **Produto** | HackRF One |
| **Chipset** | MAX2837 / MAX5864 / CPLD |
| **Preco (USD)** | $350.00 |
| **Compra** | <https://greatscottgadgets.com/hackrf/one/> |
| **Drivers/Ferramentas** | gnuradio, gqrx, inspectrum, URH |
| **Suporte de SO** | Linux, Windows, macOS |

### Notas de Uso

- Cobre de 1 MHz a 6 GHz com 20 MHz de largura de banda.
- Half-duplex: nao e possivel transmitir e receber simultaneamente.
- Para operacoes full-duplex, considere o USRP B200/B210.
- Modulos que usam este adaptador: replay sub-GHz, analise de banda ISM,
  captura de sinal de portao de garagem, deteccao de RF jamming.

---

## RFID Proxmark (`rfid_proxmark`)

Proxmark3 ou ferramenta de pesquisa RFID/NFC compativel. Necessario para
clonagem de cartoes LF 125 kHz e HF 13.56 MHz, emulacao de leitor,
sniffing de protocolo, recuperacao de chaves e extracao de credenciais.

| Campo | Valor |
|-------|-------|
| **Produto** | Proxmark3 RDV4 |
| **Chipset** | AT91SAM7S512 + Xilinx FPGA |
| **Preco (USD)** | $300.00 |
| **Compra** | <https://proxmark.com/> |
| **Drivers/Ferramentas** | proxmark3 client, iceman firmware, libnfc |
| **Suporte de SO** | Linux, Windows, macOS |

### Notas de Uso

- Faca flash do firmware da comunidade Iceman para suporte estendido de cartoes.
- O RDV4 inclui bateria integrada para operacoes standalone.
- Suporta: HID, EM4100, T55xx, Mifare Classic, DESFire, iCLASS.
- Modulos que usam este adaptador: clone RFID, recuperacao de chaves Mifare,
  emulacao de cracha de acesso, relay attack NFC.

---

## Interface CAN (`can_interface`)

Adaptador CAN bus (USB-to-CAN ou compativel com SocketCAN). Necessario para
injecao de frames CAN 2.0 / CAN FD automotivo e industrial, sniffing passivo,
diagnosticos UDS e fuzzing de barramento.

| Campo | Valor |
|-------|-------|
| **Produto** | CANable 2.0 (USB-C) |
| **Chipset** | STM32G0B1 |
| **Preco (USD)** | $40.00 |
| **Compra** | <https://canable.io/> |
| **Drivers/Ferramentas** | can-utils, socketcan, python-can |
| **Suporte de SO** | Linux, Windows |

### Notas de Uso

- O CANable 2.0 suporta tanto CAN 2.0B quanto CAN FD.
- No Linux, use `slcand` ou firmware `candleLight` para SocketCAN.
- Para testes de ECU automotivo, combine com um adaptador OBD-II para DB9.
- Modulos que usam este adaptador: sniffing de CAN bus, scanning UDS,
  injecao de frames CAN, fuzzing de ECU.

---

## Adaptador UART (`uart_ttl_adapter`)

Adaptador serial USB-to-UART TTL (niveis logicos 3.3V ou 5V). Necessario
para acesso ao console serial, interacao com bootloader U-Boot, dump de
firmware via console e acesso a root shell em dispositivos embarcados com
pads de debug expostos.

| Campo | Valor |
|-------|-------|
| **Produto** | FTDI FT232RL USB-to-UART |
| **Chipset** | FTDI FT232RL |
| **Preco (USD)** | $12.00 |
| **Compra** | <https://ftdichip.com/products/ft232rl/> |
| **Drivers/Ferramentas** | minicom, picocom, screen, PuTTY |
| **Suporte de SO** | Linux, Windows, macOS |

### Notas de Uso

- Verifique o nivel logico do alvo antes de conectar (3.3V vs 5V).
- Conexao cruzada TX/RX: TX do adaptador no RX do dispositivo e vice-versa.
- Baud rates comuns: 9600, 19200, 38400, 57600, 115200.
- Modulos que usam este adaptador: root shell via UART, interrupcao de U-Boot,
  dump serial de firmware, modificacao de bootloader.

---

## Alto-falante Ultrassonico (`ultrasonic_speaker`)

Transdutor ultrassonico ou array de alto-falante parametrico capaz de emitir
audio modulado acima de 20 kHz. Necessario para injecao de comandos de voz
inaudiveis (DolphinAttack, SurfingAttack) contra microfones MEMS em
assistentes inteligentes.

| Campo | Valor |
|-------|-------|
| **Produto** | Murata MA40S4S (array piezo 40 kHz) |
| **Chipset** | Placa amplificadora customizada + DAC |
| **Preco (USD)** | $85.00 |
| **Compra** | <https://www.murata.com/products/sensor/ultrasonic> |
| **Drivers/Ferramentas** | audacity (mod carrier), firmware MCU customizado |
| **Suporte de SO** | Linux, Windows, macOS |

### Notas de Uso

- Alcance efetivo: 1-3 metros dependendo da potencia do transdutor.
- Requer sinal portador ultrassonico modulado com comandos de voz.
- Funciona contra dispositivos Google Home, Amazon Echo, Apple Siri.
- Modulos que usam este adaptador: injecao de voz DolphinAttack,
  replay de comando ultrassonico.

---

## Thread Border USB (`thread_border_usb`)

Dongle USB border router Thread/OpenThread (radio 802.15.4). Necessario
para captura de pacotes em redes mesh Thread, ataques ao protocolo de
commissioning e injecao de frames IEEE 802.15.4.

| Campo | Valor |
|-------|-------|
| **Produto** | Nordic nRF52840 Dongle |
| **Chipset** | nRF52840 (ARM Cortex-M4F) |
| **Preco (USD)** | $10.00 |
| **Compra** | <https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle> |
| **Drivers/Ferramentas** | wpantund, ot-commissioner, wireshark (802.15.4) |
| **Suporte de SO** | Linux, Windows, macOS |

### Notas de Uso

- Faca flash do firmware sniffer OpenThread para integracao com Wireshark.
- Suporta canais IEEE 802.15.4 de 11 a 26 (banda 2.4 GHz).
- Pode atuar como Thread border router para ataques de commissioning de rede.
- Modulos que usam este adaptador: sniffing de rede Thread, injecao de
  frames 802.15.4, exploit de commissioning Thread.

---

## Resumo de Custos

| Adaptador | Preco (USD) |
|-----------|-------------|
| Wi-Fi Monitor (Alfa AWUS036ACH) | $65.00 |
| Adaptador BLE (CSR 4.0) | $15.00 |
| SDR TX/RX (HackRF One) | $350.00 |
| RFID Proxmark (RDV4) | $300.00 |
| Interface CAN (CANable 2.0) | $40.00 |
| Adaptador UART (FT232RL) | $12.00 |
| Alto-falante Ultrassonico (MA40S4S) | $85.00 |
| Thread Border USB (nRF52840) | $10.00 |
| **Total (todos os adaptadores)** | **$877.00** |

A maioria dos modulos requer apenas conectividade de rede (sem hardware especial).
Adaptadores fisicos sao necessarios principalmente para modulos de ataque RF,
console serial e nivel de barramento.

---

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
