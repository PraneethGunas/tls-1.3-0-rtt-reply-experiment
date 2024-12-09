# TLS 1.3 0-RTT Replay Attack Demonstration

This repository demonstrates the vulnerability of **TLS 1.3 0-RTT** to replay attacks, using a forked implementation of the [Rustls](https://github.com/rustls/rustls) library. The project includes a custom server implementation, packet sniffing, and replay attack simulation tools.

---

## Features
1. A custom **Rustls**-based TLS 1.3 server with support for 0-RTT.
2. Packet sniffing to analyze client-server communication.
3. Replay attack simulation to exploit 0-RTT early data.

---

## Prerequisites

1. **Install Rust and Cargo**:
   Follow instructions [here](https://www.rust-lang.org/tools/install).

2. **Install OpenSSL**:
   On Ubuntu/Debian:
   ```bash
   sudo apt update
   sudo apt install openssl
   ```

3. **Install Python and Dependencies**:
   Ensure Python 3 is installed. Install necessary packages:
   ```bash
   pip install scapy
   ```

4. **Generate Certificates**:
   Generate a self-signed certificate for the server:
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
   ```
   When prompted, set `Common Name (CN)` to `localhost`.

---

## Project Structure
- **`rustls/`**: The forked Rustls repository containing the TLS server implementation.
- **`sniff_session.py`**: Python script to sniff packets during client-server communication.
- **`reply0rtt.py`**: Python script to replay captured 0-RTT packets.

---

## Running the Project

### 1. Start the Server
Run the TLS 1.3 server:
```bash
cargo run --bin simple_0rtt_server --package rustls-examples server.crt server.key
```

### 2. Packet Sniffing
Capture packets during client-server communication:
```bash
sudo python sniff_session.py
```

### 3. Client Requests and Session Resumption
#### Initial Client Request
Use OpenSSL to initiate a connection and save the session:
```bash
openssl s_client -connect localhost:4443 -sess_out sess.pem
```

#### Session Resumption with 0-RTT Data
To resume the session and send early data:
1. Create a file `early.txt` containing the early data to send.
2. Execute the following:
   ```bash
   openssl s_client -connect localhost:4443 -sess_in sess.pem -early_data early.txt
   ```

### 4. Replay Attack
Replay the captured **ClientHello** message and simulate a 0-RTT attack:
```bash
python reply0rtt.py
```

---

## Expected Results
1. **Packet Sniffing**:
   - Inspect captured packets to confirm session establishment, resumption, and 0-RTT data transmission.
2. **Replay Attack**:
   - Observe the server processing replayed 0-RTT data, highlighting the vulnerability.

---

## Notes
- **Replay Vulnerability**:
  This demonstration highlights the lack of inherent replay protection in 0-RTT early data and the risks in unsynchronized distributed systems.
- **Use in Controlled Environments**:
  Ensure that this setup is used strictly for research and testing purposes in a controlled environment.

---

## References
- [Rustls Documentation](https://github.com/rustls/rustls)
- [TLS 1.3 Specification (RFC 8446)](https://www.rfc-editor.org/rfc/rfc8446.html)

---

## License
This project is licensed under the terms of the original Rustls repository.
```