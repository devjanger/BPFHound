#!/bin/bash

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[31mThis script must be run as root. Please use sudo.\033[0m"
    exit 1
fi

# Generate output filename with timestamp
output="report_bpfdoor_suspect_processes_$(date '+%Y%m%d_%H%M%S').txt"
> "$output"  # Initialize the report file

# Print banner
echo -e "\033[1;31m" >> "$output"
echo "██████╗ ██████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗" >> "$output"
echo "██╔══██╗██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗" >> "$output"
echo "██████╔╝██████╔╝█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║" >> "$output"
echo "██╔══██╗██╔═══╝ ██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║" >> "$output"
echo "██████╔╝██║     ██║     ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝" >> "$output"
echo "╚═════╝ ╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝"  >> "$output"
echo -e "\033[1;37m                                       BPFDoor Detection Tool"   >> "$output"
echo -e "                                             Version 0.1"  >> "$output"
echo -e "\033[0m"   >> "$output"

suspicious_found=0

# Check for processes using RAW sockets (packet_recvmsg in kernel stack)
echo -e "\033[0m[Scanning for processes using RAW sockets]\033[0m" >> "$output"

for pid in /proc/[0-9]*; do
    if egrep -q 'packet_recvmsg' "$pid/stack"; then
        suspicious_found=1
        echo -e "\033[31m[!] Suspicious process detected:\033[0m" >> "$output"
        echo -e "\033[31m[!] PID:\033[0m $(basename $pid)" >> "$output"
        echo -e "\033[31m[!] Stack trace:\033[0m" >> "$output"
        egrep 'packet_recvmsg' "$pid/stack" >> "$output"
        ps -ef | grep "$(basename $pid)" | grep -v grep >> "$output"
        echo "" >> "$output"
    fi
done

if [ $suspicious_found -eq 0 ]; then
    echo -e "[+] No suspicious processes found using RAW sockets.\033[0m" >> "$output"
fi

echo -e >> "$output"

# Check for binary artifact
echo -e "\033[0m[Checking for binary artifacts]\033[0m" >> "$output"
if [ -f /dev/shm/kdmtmpflush ]; then
    suspicious_found=1
    echo -e "\033[31m[!] /dev/shm/kdmtmpflush file found!\033[0m" >> "$output"
else
    echo "[+] /dev/shm/kdmtmpflush not found." >> "$output"
fi

echo -e >> "$output"

# Check for dropper artifact
echo -e "\033[0m[Checking for dropper artifacts]\033[0m" >> "$output"
if [ -f /var/run/haldrund.pid ]; then
    suspicious_found=1
    echo -e "\033[31m[!] /var/run/haldrund.pid file found!\033[0m" >> "$output"
else
    echo "[+] /var/run/haldrund.pid not found." >> "$output"
fi

echo -e >> "$output"

# Final result summary
echo -e "\033[0m[Result Summary]\033[0m" >> "$output"
if [ $suspicious_found -eq 1 ]; then
    echo -e "\033[31mSuspicious activity has been detected.\033[0m" >> "$output"
else
    echo -e "\033[32mNo suspicious activity detected.\033[0m" >> "$output"
fi

# Display result to screen
cat "$output"
echo -e "\033[0m[+] Scan complete. Results saved to: $output\033[0m"
