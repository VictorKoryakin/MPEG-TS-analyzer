# MPEG-TS-analyzer
MPEG-TS IP multicast analyzer
This program receives the stream, determines some of its parameters and sends the received information to Zabbix monitoring server.
Startup option:
"-m", "--multicast" - stream IP multicast address
"-p", "--port", type=int   -  stream IP multicast port
"-z", "--zabbix"  -  Zabbix server IP adress
"-s", "--server"  -  analyzer hostname in zabbix system
"-k", "--key"    -  Key for the data element in zabbix
"-t", "--timeN", type=int   - The value of the period of analysis. seconds
Define parameters:
1) Bitrate, zabbix key: <--key>rate
2) Useful вitrate, zabbix key: <--key>rate_useful
3) Continuity count error, zabbix key: <--key>cc. This option is cumulative and resets every 60 minutes
The current parameter value is sent to the server every "--timeN" seconds. Sending of messages occurs using a utility zabbix_sender.
