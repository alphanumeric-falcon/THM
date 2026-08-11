Scenario

A short capture from the hotel's guest network shows requests to a `:8080`
address at very regular intervals (roughly every second) — typical C2
beaconing behavior rather than normal application traffic.


1.Analyzing `traffic.pcapng` (with scapy), traffic to `34.41.103.191:8080`
(hostname `byte-lotus-hotel.thm`) appeared every second — matching exactly
what `@0xMia` described in her story.

2. Extracting the malware source

One of the requests (`GET /temp/updates.py`) returned the source code of a
Python keylogger built on `pynput`:

- captures every key press (`on_press`)
- encrypts each character with XOR using the key
  `H0t3lSt@ff0Nly` + `K3epS3cr3t!` = `H0t3lSt@ff0NlyK3epS3cr3t!`
- base64-encodes the result
- sends it to the C2 as the value of the `hotel_sess_state` cookie, in a
  `GET /` request to `http://byte-lotus-hotel.thm:8080/`

This is the "covert channel" exfiltration mechanism: each keystroke becomes
a separate HTTP request, disguised as an ordinary session cookie.

3. Reassembling the exfiltrated data

- Extracted from the pcap, in chronological order (by timestamp), all
  requests to `34.41.103.191:8080` containing the header
  `Cookie: hotel_sess_state=<base64>`
'1. HA==
 2. AA==
 3. BQ==
 4. Mw==
 5. Hg==
 6. ew==
 7. Og==
 8. fA==
 9. Fw==
10. eQ==
11. Ow==
12. Fw==
13. Pw==
14. fA==
15. PA==
16. Kw==
17. IA==
18. eQ==
19. Jg==
20. Lw==
21. Fw==
22. eA==
23. Pg==
24. LQ==
25. Gg==
26. Fw==
27. MQ==
28. eA==
29. PQ==
30. NQ=='

- For each value: `base64_decode` -> XOR with the key found in
  `updates.py` -> decoded character
- Concatenating the characters in order reconstructed the text typed on the
  compromised machine

4. Result

Decoding and reassembling all the captured keystrokes reveals the flag in
`THM{...}` format, submitted to complete the room.

Tools Used

- Wireshark
- cyberchef.org to decript the format 

Lessons / Observations

- "Session" cookies with short, changing values on a fixed time interval are
  a strong signal of a covert channel / beaconing.
- A custom User-Agent (`ByteLotusClient/1.1`) combined with a plain
  `SimpleHTTP` server directly serving `.py` files is a good indicator of
  test/C2 infrastructure rather than a real application.
- The XOR key was found directly in the malware source exposed on the same
  server — a classic operational security mistake in labs of this type.
