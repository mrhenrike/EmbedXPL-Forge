#!/usr/bin/env python3
import time
import telnetlib
import re
import socket

# "display optic" output example

#LinkStatus  : ok 
#Voltage      : 3322 (mV)
#Bias         : 13 (mA)
#Temperature  : 36 (C)
#RxPower      : -17.26 (dBm)
#TxPower      :  2.34 (dBm)
#RfRxPower    : -- (dBm)
#RfOutputPower: -- (dBmV)
#VendorName   : HUAWEI         
#VendorSN     : 1937WJ3xxxx   
#VendorRev    :
#VendorPN     : HW-BOB-0007     
#DateCode     : 191024

ont_host        = "192.168.100.1"
ont_user        = "root"
ont_password    = "adminHW"
graphite_host   = "graphite.lab"
graphite_port   = 2003
graphite_prefix = "stats.network.ftth.ont"

# Get current date for Graphite
current_date = int(time.time())

# Python method to test if a string is a float
def isfloat(value):
  try:
    float(value)
    return True
  except ValueError:
    return False

# Open telnet connexion
tn = telnetlib.Telnet(ont_host, 23, 5)
#tn.set_debuglevel(True)

# authentication
tn.read_until(b"Login:")
tn.write(ont_user.encode('ascii') + b"\n")
tn.read_until(b"Password:")
tn.write(ont_password.encode('ascii') + b"\n")
tn.read_until(b"WAP>")
# display optic stats
tn.write(b"display optic\n")
optic_stats = tn.read_until(b"WAP>").decode()
# disconnect
tn.write(b"quit\n")
tn.close()

graphite_data = []

# Fake data
#optic_stats = "\r\nLinkStatus  : ok \r\nVoltage      : 3322 (mV)\r\nBias         : 13 (mA)\r\nTemperature  : 36 (C)\r\nRxPower      : -17.26 (dBm)\r\nTxPower      :  2.34 (dBm)\r\nRfRxPower    : -- (dBm)\r\nRfOutputPower: -- (dBmV)\r\nVendorName   : HUAWEI         \r\nVendorSN     : 1937WJ3xxxx   \r\nVendorRev    :\r\nVendorPN     : HW-BOB-0007     \r\nDateCode     : 191024\r\n"

for line in optic_stats.split("\r\n"):
  # LinkStatus
  if line.startswith('LinkStatus'):
    re_LinkStatus = re.compile("^LinkStatus  : (\S*)\s*$")
    result_LinkStatus = re_LinkStatus.match(line)[1]
    if str(result_LinkStatus) == "ok":
      graphite_data.append("{:s}.linkstatus 1 {:d}".format(graphite_prefix, current_date))
      graphite_data.append("{:s}.linkstatus_up 1 {:d}".format(graphite_prefix, current_date))
    else:
      graphite_data.append("{:s}.linkstatus 0 {:d}".format(graphite_prefix, current_date))
      graphite_data.append("{:s}.linkstatus_down 1 {:d}".format(graphite_prefix, current_date))

  # Voltage
  elif line.startswith('Voltage'):
    re_Voltage = re.compile("^Voltage      :\s*(\S*)\s*\(mV\)$")
    result_Voltage = re_Voltage.match(line)[1]
    if str(result_Voltage).isdigit():
      graphite_data.append("{:s}.voltage_in_mv {:d} {:d}".format(graphite_prefix, int(result_Voltage), current_date))

  # Temperature
  elif line.startswith('Temperature'):
    re_Temperature = re.compile("^Temperature  :\s*(\S*)\s*\(C\)$")
    result_Temperature = re_Temperature.match(line)[1]
    if str(result_Temperature).isdigit():
      graphite_data.append("{:s}.temperature_in_c {:d} {:d}".format(graphite_prefix, int(result_Temperature), current_date))

  # RxPower
  elif line.startswith('RxPower'):
    re_RxPower = re.compile("^RxPower      :\s*(\S*)\s*\(dBm\)$")
    result_RxPower = re_RxPower.match(line)[1]
    if isfloat(result_RxPower):
      graphite_data.append("{:s}.rxpower_in_mdbm {:d} {:d}".format(graphite_prefix, int(float(result_RxPower)*1000), current_date))

  # TxPower
  elif line.startswith('TxPower'):
    re_TxPower = re.compile("^TxPower      :\s*(\S*)\s*\(dBm\)$")
    result_TxPower = re_TxPower.match(line)[1]
    if isfloat(result_TxPower):
      graphite_data.append("{:s}.txpower_in_mdbm {:d} {:d}".format(graphite_prefix, int(float(result_TxPower)*1000), current_date))
 
  # RfRxPower
  elif line.startswith('RfRxPower'):
    re_RfRxPower = re.compile("^RfRxPower    :\s*(\S*)\s*\(dBm\)$")
    result_RfRxPower = re_RfRxPower.match(line)[1]
    if isfloat(result_RfRxPower):
      graphite_data.append("{:s}.rfrxpower_in_mdbm {:d} {:d}".format(graphite_prefix, int(float(result_RfRxPower)*1000), current_date))

  # RfOutputPower
  elif line.startswith('RfOutputPower'):
    re_RfOutputPower = re.compile("^RfOutputPower:\s*(\S*)\s*\(dBmV\)$")
    result_RfOutputPower = re_RfOutputPower.match(line)[1]
    if isfloat(result_RfOutputPower):
      graphite_data.append("{:s}.rfoutputpower_in_mdbmv {:d} {:d}".format(graphite_prefix, int(float(result_RfOutputPower)*1000), current_date))

#print("\n".join(graphite_data))

# Send to Carbon/Graphite
carbon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
carbon_socket.connect((graphite_host, graphite_port))
carbon_socket.sendall(("\n".join(graphite_data) + "\n").encode())
carbon_socket.close()

exit(0)
