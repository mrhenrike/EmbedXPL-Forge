# frozen_string_literal: true

# Helper script to discover a Lorex device on the network, via broadcast UDP.
#
# Author: Stephen Fewer, Rapid7. Sept 6, 2024.
#
# Example Usage (Note, the MachineName/SerialNo/DeviceID values have been redacted):
#
# C:\Users\steve\Desktop\lorex_2k_camera>ruby LOREX_DISCOVER.rb
# {"mac"=>"00:1f:54:a9:2e:58",
#  "method"=>"client.notifyDevInfo",
#  "params"=>
#   {"deviceInfo"=>
#     {"AlarmInputChannels"=>0,
#      "AlarmOutputChannels"=>0,
#      "DeviceClass"=>"IPC",
#      "DeviceType"=>"W461ASC",
#      "HttpPort"=>80,
#      "Port3"=>80,
#      "Port"=>35000,
#      "UnLoginFuncMask"=>1,
#      "IPv4Address"=>{"DefaultGateway"=>"192.168.86.1", "DhcpEnable"=>true, "IPAddress"=>"192.168.86.81", "SubnetMask"=>"255.255.255.0"},
#      "MachineName"=>"**************",
#      "Manufacturer"=>"Private",
#      "RemoteVideoInputChannels"=>0,
#      "SerialNo"=>"**************",
#      "DeviceID"=>"***************",
#      "Vendor"=>"Lorex",
#      "Version"=>"2.800.030000000.3.R",
#      "VideoInputChannels"=>1,
#      "VideoOutputChannels"=>0,
#      "Init"=>1162,
#      "Find"=>"BC",
#      "FindVersion"=>1}}}

require 'optparse'
require 'socket'
require 'json'

def broadcast_dhip_packet(command)
  dest_ip = '239.255.255.251'

  dest_port = 37_810

  s = UDPSocket.new

  maddr = dest_ip.split('.').collect!(&:to_i).pack('CCCC')

  mreq = "#{maddr}\u0000\u0000\u0000\u0000" # INADDR_ANY

  s.setsockopt(Socket::IPPROTO_IP, Socket::IP_ADD_MEMBERSHIP, mreq)

  data = [
    0x20,
    0x50494844, # 'DHIP' magic value
    0,
    0,
    command.length,
    0,
    command.length,
    0
  ].pack('V*') << command

  s.send(data, 0, dest_ip, dest_port)

  response, = s.recvfrom(8192)

  if response.nil? || (response.length <= 32)
    $stdout.puts 'Bad response'
    return nil
  end

  JSON.parse(response[32..response.length - 2])
rescue JSON::ParserError
  $stdout.puts 'JSON parsing error'
  nil
end

def dhdiscover_search(target_mac)
  command = {
    'method' => 'DHDiscover.search',
    'params' => {
      'mac' => target_mac
    }
  }.to_json

  broadcast_dhip_packet(command)
end

target_mac = ''

OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"

  opts.on('-m', '--mac MAC', 'Target MAC address') do |v|
    target_mac = v
  end
end.parse!

json = dhdiscover_search(target_mac.downcase)

pp json
