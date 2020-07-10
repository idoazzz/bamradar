# bamradar
######  Detect wifi devices in classified rooms.
Bamradar is a sniffer that monitors and detects 
wifi devices. The tool generates a specific RSSI threshold, 
every sniffed packet that has bigger RSSI value 
will be alerted.
<br>
##### Prerequisite
* Kali Linux.
* Wifi Adapter that supports monitor mode.
* Python 3.8.
<br><br>
#### So how it will work?
###### STAGE 1 - Calibrate the tool.
Calibrate the tool and search for compatible threshold. 
You should walk in the specific room, 
measure the RSSI values that your
specific phone signals (Sniff and filter on your specific MAC with bamradar).
<br><br> 
This command will record the RSSI values of 
frames of specific smartphone and prints 
calculated threshold.
`python sniffer.py --interface wlan0 --calibrate --target 50:3e:aa:01:71:ce`
<br><br>
If your phone has randomised MAC you can run the 
program without target, be aware that the threshold
will be calculated by all the signals that transmitted
around. Get sterile wifi devices environment.<br><br>
`python sniffer.py --interface wlan0 --calibrate`
The tool takes the maximum RSSI value that have measured and print it.
Define it as your **threshold**.
###### STAGE 2 - Monitor devices.
Now we need to take our threshold value and pass it to
the bamradar program. The program will alert when
device with strong signal will be detected.
<br>
NOTE: Don't forget to filter your own wireless interfaces.
It will spam the bamradar and will show a ghost devices
with strong signal strength. 
<br><br>
`python sniffer.py --interface wlan0 --threshold -30 --ignore 50:3e:aa:01:71:ce`
##### Notes
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
* Bamradar has channel hopper. It can be disabled
with the flag `--disable_hopping` or pick specific
channel to sniff - `--channel CHANNEL`.  
* There is a verbose flag for debug the ignored frames.