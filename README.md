# 🐾 BPFHound

**BPFHound** is a lightweight Linux hunting script to detect signs of the stealthy [BPFDoor](https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/) backdoor.

It scans for suspicious processes using raw sockets, traces specific kernel stack patterns, and checks for known BPFDoor artifact files.

---

## 🚀 Features

- Detects processes calling `packet_recvmsg` in the kernel stack
- Checks for BPFDoor-related artifacts such as:
  - `/dev/shm/kdmtmpflush`
  - `/var/run/haldrund.pid`
- Identifies abnormal processes using raw sockets
- Automatically generates a timestamped report

---

## 🔧 Installation & Usage

```bash
git clone https://github.com/devjanger/BPFHound.git
cd BPFHound
chmod +x BPFHound.sh
sudo ./BPFHound.sh
```

## 🖼️ Screenshot
![image](https://github.com/user-attachments/assets/befa08b0-ca90-472d-968e-95b5c25ff1b5)
