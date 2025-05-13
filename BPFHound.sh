#!/bin/bash

# Check if run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[31mThis script must be run as root. Please run with sudo.\033[0m"
    exit 1
fi

# Create output file with date and time
output="report_bpfdoor_suspect_processes_$(date '+%Y%m%d_%H%M%S').txt"
> "$output"

# Display banner
{
    echo -e "\033[1;31m"
    echo "██████╗ ██████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗"
    echo "██╔══██╗██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗"
    echo "██████╔╝██████╔╝█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║"
    echo "██╔══██╗██╔═══╝ ██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║"
    echo "██████╔╝██║     ██║     ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝"
    echo "╚═════╝ ╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝"
    echo -e "\033[1;37m                                       BPFDoor Detection Tool"
    echo "                                               Version 0.2"
    echo -e "\033[0m"
} | tee -a "$output"

echo -e "[Searching for processes using RAW sockets]" | tee -a "$output"

suspicious_process_found=0
suspicious_binary_found=0
suspicious_pidfile_found=0
suspicious_pids=()
suspicious_binaries=()
suspicious_pidfiles=()

for pid in /proc/[0-9]*; do
    if grep -q 'packet_recvmsg' "$pid/stack" 2>/dev/null; then
        pid_num=$(basename "$pid")
        suspicious_process_found=1
        suspicious_pids+=("$pid_num")

        echo -e "\033[31m[!] Suspicious process detected:\033[0m" | tee -a "$output"
        echo -e "\033[31m[!] Process ID:\033[0m $pid_num" | tee -a "$output"
        echo -e "\033[31m[!] Stack trace:\033[0m" | tee -a "$output"
        grep 'packet_recvmsg' "$pid/stack" | tee -a "$output"
        ps -ef | grep "$pid_num" | grep -v grep | tee -a "$output"
        ls -l "/proc/$pid_num/exe" | tee -a "$output"
        echo | tee -a "$output"
    fi
done

if [ $suspicious_process_found -eq 0 ]; then
    echo -e "[+] No suspicious processes found." | tee -a "$output"
fi

echo | tee -a "$output"
echo -e "[Searching binary files]" | tee -a "$output"

for pid in "${suspicious_pids[@]}"; do
    exe_path="/proc/$pid/exe"
    hash=$(md5sum "$exe_path" 2>/dev/null | awk '{print $1}')

    echo -e "[+] PID: $pid" | tee -a "$output"
    echo "    - MD5 Hash: $hash" | tee -a "$output"
    echo "    - Searching for matching binaries..." | tee -a "$output"

    match=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib /lib64 /opt /etc /home /root /tmp /var/tmp /var/run /run /dev/shm /boot -type f -exec md5sum {} \; 2>/dev/null | grep "^$hash" | awk '{print $2}')

    if [ -n "$match" ]; then
        suspicious_binary_found=1
        echo -e "\033[31m    => Matching binary path(s):\033[0m" | tee -a "$output"
        for path in $match; do
            echo "       $path" | tee -a "$output"
            suspicious_binaries+=("$path")
        done
    else
        echo "    => No matching binary found." | tee -a "$output"
    fi

done

echo | tee -a "$output"

if [ -f /dev/shm/kdmtmpflush ]; then
    echo -e "\033[31m[!] /dev/shm/kdmtmpflush file exists!\033[0m" | tee -a "$output"
    suspicious_binary_found=1
else
    echo "[+] /dev/shm/kdmtmpflush not found" | tee -a "$output"
fi

echo | tee -a "$output"
echo "[Checking for dropper traces]" | tee -a "$output"
dropper_paths=(
    /var/run/haldrund.pid
    /var/run/hald-smartd.pid
    /var/run/system.pid
    /var/run/hp-health.pid
    /var/run/hald-addon.pid
)

for file in "${dropper_paths[@]}"; do
    if [ -f "$file" ]; then
        echo -e "\033[31m[!] File exists: $file\033[0m" | tee -a "$output"
        suspicious_pidfile_found=1
        suspicious_pidfiles+=("$file")
    else
        echo "[+] $file not found" | tee -a "$output"
    fi

done

echo | tee -a "$output"
echo "[Result]" | tee -a "$output"

if [ $suspicious_process_found -eq 1 ]; then
    echo -e "\033[31m[!] Suspicious process detected\033[0m" | tee -a "$output"
    printf "\033[31m[!] PID: %s\033[0m\n" "${suspicious_pids[@]}" | tee -a "$output"
else
    echo -e "\033[32m[+] No suspicious process\033[0m" | tee -a "$output"
fi

echo | tee -a "$output"

if [ $suspicious_binary_found -eq 1 ]; then
    echo -e "\033[31m[!] Suspicious binary detected\033[0m" | tee -a "$output"
    for binary in "${suspicious_binaries[@]}"; do
        echo -e "\033[31m[!] Binary path: $binary\033[0m" | tee -a "$output"
    done
else
    echo -e "\033[32m[+] No suspicious binary\033[0m" | tee -a "$output"
fi

echo | tee -a "$output"

if [ $suspicious_pidfile_found -eq 1 ]; then
    echo -e "\033[31m[!] Suspicious PID file detected\033[0m" | tee -a "$output"
    for pidfile in "${suspicious_pidfiles[@]}"; do
        echo -e "\033[31m[!] PID file path: $pidfile\033[0m" | tee -a "$output"
    done
else
    echo -e "\033[32m[+] No suspicious PID file\033[0m" | tee -a "$output"
fi

echo

# Scan complete message
echo -e "\033[0mScan completed. Results saved to $output.\033[0m"
