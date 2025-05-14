# DNS Analyzer GUI 

A Python-based DNS Analyzer with a simple Tkinter GUI — allows you to resolve domain names (A, AAAA, MX, NS, CNAME), analyze DNS response times, estimate hop counts using traceroute, and optionally cross-check expected IPs. You can also use Wireshark alongside it for deeper packet-level inspection.

---

## 🚀 Features

- Resolve DNS records (`A`, `AAAA`, `MX`, `NS`, `CNAME`)
- Measure DNS response time
- Estimate hop count using built-in traceroute
- Optional security check: compare resolved IPs with an expected IP
- CSV logging of all queries (`dns_query_log.csv`)
- User-friendly GUI using `tkinter`
- Cross-platform (Windows, macOS, Linux)
- Can be used alongside **Wireshark** for advanced network analysis

---

## 🧩 Requirements

- Python 3.x
- `dnspython` module  
  Install it using:
  ```bash
  pip install dnspython
  ```

---

## 🖥️ How to Run

1. Clone this repository or download the `.py` file.
2. Install the required module (`dnspython`) if not already installed.
3. Run the script:
   ```bash
   python dns_analyzer_gui.py
   ```
4. Enter a domain, choose a record type, optionally enter an expected IP, and click **Run Analysis**.

---

## 🔍 Sample Use Case

Let’s say you're debugging a slow-loading website. You can:

- Enter the domain to check if DNS is resolving correctly.
- Compare the returned IP against the one you expect (e.g., CDN).
- See how many hops it takes to reach the server.
- Use **Wireshark** in parallel to analyze DNS packets in detail.

Wireshark Tip:  
Filter DNS traffic in Wireshark using:
```
dns && ip.addr == YOUR_IP_ADDRESS
```

---

## 📦 Output Example

```
🔍 Resolving example.com (A)...
✅ A Records for example.com:
   → 93.184.216.34
⏱️ Response Time: 42.37 ms
📡 Estimated Hops to 93.184.216.34: 13
```

A log of this result will be saved to `dns_query_log.csv`.

---

## 🛠️ Platform Notes

- On **Windows**, `tracert` is used internally.
- On **Linux/macOS**, it uses `traceroute` or `traceroute6` for IPv6.

Ensure you have traceroute installed on your system:
```bash
sudo apt install traceroute    # Ubuntu/Debian
```

---

## 🧑‍💻 Author

Made with curiosity as a semester mini-project for learning DNS internals, Python GUIs, and basic network diagnostics.

