# 🐾 BPFHound

**BPFHound** is a lightweight Linux hunting script to detect signs of the stealthy [BPFDoor](https://www.sandflysecurity.com/blog/bpfdoor-an-extremely-stealthy-linux-backdoor-using-bpf/) backdoor.

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
