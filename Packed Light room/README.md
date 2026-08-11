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
- For each value: `base64_decode` -> XOR with the key found in
  `updates.py` -> decoded character
- Concatenating the characters in order reconstructed the text typed on the
  compromised machine

4. Result

Decoding and reassembling all the captured keystrokes reveals the flag in
`THM{...}` format, submitted to complete the room.

Tools Used

- `ffuf` — discovering exposed `.git` (earlier stage of the lab)
- `git-dumper` — extracting the repo from the exposed `.git`
- Python `scapy` — parsing the pcap, extracting HTTP payload per packet
- Python `base64` + manual XOR — decrypting the exfiltrated data

Lessons / Observations

- "Session" cookies with short, changing values on a fixed time interval are
  a strong signal of a covert channel / beaconing.
- A custom User-Agent (`ByteLotusClient/1.1`) combined with a plain
  `SimpleHTTP` server directly serving `.py` files is a good indicator of
  test/C2 infrastructure rather than a real application.
- The XOR key was found directly in the malware source exposed on the same
  server — a classic operational security mistake in labs of this type.
