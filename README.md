# 🐾 BPFHound

**BPFHound** is a lightweight Linux hunting script to detect signs of the stealthy [BPFDoor](https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/) backdoor.

It scans for suspicious processes using raw sockets, traces specific kernel stack patterns, and checks for known BPFDoor artifact files.

---

## 🚀 Features

- Detects processes calling `packet_recvmsg` in the kernel stack
- Checks for BPFDoor-related artifacts such as:
  - `/dev/shm/kdmtmpflush`
  - Dropper-related PID files such as:
    - `/var/run/haldrund.pid`
    - `/var/run/hald-smartd.pid`
    - `/var/run/system.pid`
    - `/var/run/hp-health.pid`
    - `/var/run/hald-addon.pid`
- Identifies abnormal processes using raw sockets
- Performs MD5 hash comparisons of suspicious binaries to locate matching files across the system
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
![image](https://github.com/user-attachments/assets/34e35c3c-f93c-4e20-942d-b85be65b242e)
