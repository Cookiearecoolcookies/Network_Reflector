# Overview

The objective of this repo was to create a reflector, which takes packets from the attacker and chucks it
right back at them. The concept sounds simple, and the code is tight, but the detail is in understanding
the order of events. As mentioned in the video lecture, it was really important to draw out each step of how
packets are sent and received. Below is a descriptions of all the communications that occur:

1) The attacker sends an ARP request to the Victim.
2) The Victim replies with their details.
3) Now the attacker sends some IP packet to the Victim.
Instead of replying from the Victim, we send the same packet from the
reflector, and wait for a response.
4) once the Attacker responds to the reflector, we take that packet
and respond with the same data to the Attacker.


Now there are couple of key points around scapy:

* Scapy has a method called sniff, which enables packets to be picked up on an interface, and provides a method
as a parameter. As seen in the code, the class method "main_pkt_checker" executes the conditional flow detailed
above.

* Its important to remember that, there is always an Ethernet layer, meaning at each stage we need to actively modify
the MAC address of the packets.

* Next we need to determine if the packet protocol is a Link Layer, Internet Layer, or Transport Later. As scapy is
really annoying and does not use a common naming convention for source and destination. We are forced to write more code
to handle for this.

* For a lot of protocols there is a checksum, which is designed to detect corruption in the header of IPv4 packets. Meaning
when we send packets to the Attacker we need to delete the checksum form the original packet that we sent to us. While
I tried several method, to calculate the checksum, I found all of them to work. This is because the checksum
is calculated by scapy when the packet is being sent (Calling Scapy functions — Scapy 2.4.4. documentation, 2021). Hence,
as recommend by the stackover flow post I just deleted it form the incoming packets, before sending them out.
(how-to-recalculate-ip-checksum-with-scapy, 2021).

Given that we now understand how the communication flow occurs and the code base is working, lets look at an example flow:

```
E.G:
10.0.0.1 = Attacker
10.0.0.3 = Victim
10.0.0.4 = Reflector

Ether / ARP who has 10.0.0.3 says 10.0.0.1
Ether / ARP is at ff:b2:bb:ee:aa:8f says 10.0.0.3
Ether / IP / ICMP 10.0.0.1 > 10.0.0.3 echo-request 0 / Raw
Ether / IP / ICMP 10.0.0.4 > 10.0.0.1 echo-request 0 / Raw
Ether / ARP who has 10.0.0.4 says 10.0.0.1
Ether / ARP is at aa:11:86:99:88:8f says 10.0.0.4
Ether / IP / ICMP 10.0.0.1 > 10.0.0.4 echo-reply 0 / Raw
Ether / IP / ICMP 10.0.0.3 > 10.0.0.1 echo-reply 0 / Raw
```

From the above flow it can see that, we fist response to the attacker with the victims details, then when the attacker
attacks we send it right back at them from the reflector and then pass their response back to them via the Victim.

# References :
* Scapy.readthedocs.io. 2021. Calling Scapy Functions — Scapy 2.4.4. Documentation.
[online] Available at: <https://scapy.readthedocs.io/en/latest/functions.html>
[Accessed 22 January 2021].

* stackoverflow, 2021. how-to-recalculate-ip-checksum-with-scapy.
[online] Available at: <https://stackoverflow.com/questions/6112913/how-to-recalculate-ip-checksum-with-scapy>
[Accessed 22 January 2021].

# Useful links used in research but no direct reference.

https://www.youtube.com/watch?v=LvaII2PEwcQ&t=638s

https://www.youtube.com/watch?v=9ctJaieX5Ds

https://scapy.readthedocs.io/en/latest/api/scapy.layers.l2.html?highlight=ARP#scapy.layers.l2.ARP_am

https://scapy.readthedocs.io/en/latest/usage.html?highlight=sendp#sending-packets

https://scapy.readthedocs.io/en/latest/api/scapy.layers.l2.html?highlight=Ether#scapy.layers.l2.Ether

https://scapy.readthedocs.io/en/latest/usage.html#stacking-layers

https://en.wikipedia.org/wiki/Lists_of_network_protocols

