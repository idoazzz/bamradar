# bamradar
######  Detect wifi devices in classified rooms.
Bamradar is a sniffer that monitors and detects 
wifi devices. The tool gets a specific RSSI threshold, 
every sniffed packet that has bigger RSSI value 
will be alerted.
<br><br>
#####Prerequisite
* Kali Linux.
* Wifi Adapter that support monitor mode.
* Python 3.8.
<br>
<br>

#### So how it will work?
###### STAGE 1 - Calibrate the tool.
Calibrate the tool and search for compatible threshold. 
You should walk in the specific room, 
measure the RSSI values that your
specific phone signals (Sniff and filter on your specific MAC).
<br><br> 
This command will record the RSSI values of 
frames of specific smartphone and prints 
calculated threshold.

`python sniffer.py --interface wlan0 --calibrate --target 50:3e:aa:01:71:ce`
<br><br>
Take the maximum RSSI value that you have measured 
and define it as your **threshold**.

###### STAGE 2 - Monitor devices.
Now we need to take our threshold value and pass it to
the bamradar program. The program will alert when
device with strong signal will be detected.
<br>

NOTE: Don't forget to filter your own wireless interface.
It will spam the bamradar and will show a ghost device 
with strong signal strength. 
<br><br>
`python sniffer.py --interface wlan0 --threshold -30 --ignore 50:3e:aa:01:71
:ce`

#####Notes
* Smartphones with disabled Wifi switch are still
transmitting wifi (Especially probes).
* The Bamradar will not find each smartphones in realtime.
Sometimes it takes few minute for smartphone to transmit
frame, or the signals are very weak because of obstacles
in the room. In experiments that I performed - Bamradar was worked,
With small enough threshold value the bamradar will
able detect smartphones easily.
* Recommended (Sometimes works): In the calibration stage you can turn on
and turn off the screen of the smartphone. When we
turn on smartphone screen, the smartphone transmit probes 
(Wifi Frames) => Faster calibration.