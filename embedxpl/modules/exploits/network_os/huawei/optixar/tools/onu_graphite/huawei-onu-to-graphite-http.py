#!/usr/bin/env python3
import requests
import base64
import time
import socket

## Default
#ont_host     = "192.168.100.1"
#ont_username = "root"
#ont_password = "adminHW"

## Orange custom
#ont_host     = "192.168.4.254"
#ont_username = "root"
#ont_password = "admin"

# User vars
ont_host        = "192.168.4.254"
ont_username    = "root"
ont_password    = "admin"
graphite_host   = "graphite.lab"
graphite_port   = 2003
graphite_prefix = "stats.network.ftth.ont"

# Python method to test if a string is a float
def isfloat(value):
  try:
    float(value)
    return True
  except ValueError:
    return False

# Build URL prefix
ont_urlprefix = "http://" + ont_host

# Start http session
ont_session = requests.Session()
# Get the mystery random stuff
req = ont_session.post(ont_urlprefix + "/asp/GetRandCount.asp")
sid = req.text[-32:]
# Session authentication
headers = {"Cookie": "Cookie=body:Language:english:id=-1"}
auth_data = {"UserName": ont_username, "PassWord": base64.b64encode(ont_password.encode()), "x.X_HW_Token": sid}
req = ont_session.post(ont_urlprefix + "/login.cgi", headers=headers, data=auth_data)
# Get current date for Graphite
current_date = int(time.time())
# Get optic info
req = ont_session.get(ont_urlprefix + "/html/amp/opticinfo/opticinfo.asp")
# Logout
ont_session.post(ont_urlprefix + "/logout.cgi?RequestFile=html/logout.html")

# Result parsing
graphite_data = []
for line in req.text.split("\n"):
  if line.startswith('var opticInfos'):
    opticInfos_split = line.split("\",\"")
    # LinkStatus
    # ToDo

    # TxPower
    result_TxPower = opticInfos_split[1]
    if isfloat(result_TxPower):
      graphite_data.append("{:s}.txpower_in_mdbm {:d} {:d}".format(graphite_prefix, int(float(result_TxPower)*1000), current_date))
      graphite_data.append("{:s}.linkstatus 1 {:d}".format(graphite_prefix, current_date))
      graphite_data.append("{:s}.linkstatus_up 1 {:d}".format(graphite_prefix, current_date))
    else:
      graphite_data.append("{:s}.linkstatus 0 {:d}".format(graphite_prefix, current_date))
      graphite_data.append("{:s}.linkstatus_down 1 {:d}".format(graphite_prefix, current_date))

    # RxPower
    result_RxPower = opticInfos_split[2]
    if isfloat(result_RxPower):
      graphite_data.append("{:s}.rxpower_in_mdbm {:d} {:d}".format(graphite_prefix, int(float(result_RxPower)*1000), current_date))

    # Voltage
    result_Voltage = opticInfos_split[3]
    if str(result_Voltage).isdigit():
      graphite_data.append("{:s}.voltage_in_mv {:d} {:d}".format(graphite_prefix, int(result_Voltage), current_date))

    # Temperature
    result_Temperature = opticInfos_split[4]
    if str(result_Temperature).isdigit():
      graphite_data.append("{:s}.temperature_in_c {:d} {:d}".format(graphite_prefix, int(result_Temperature), current_date))

    # BiasCurrent
    result_BiasCurrent = opticInfos_split[5]
    if str(result_BiasCurrent).isdigit():
      graphite_data.append("{:s}.biascurrent_in_ma {:d} {:d}".format(graphite_prefix, int(result_BiasCurrent), current_date))

    break

#print("\n".join(graphite_data))

# Send to Carbon/Graphite
carbon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
carbon_socket.connect((graphite_host, graphite_port))
carbon_socket.sendall(("\n".join(graphite_data) + "\n").encode())
carbon_socket.close()

exit(0)
