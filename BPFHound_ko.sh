#!/bin/bash

# 루트 권한으로 실행되었는지 확인
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[31m이 스크립트는 루트 권한으로 실행되어야 합니다. sudo로 실행해주세요.\033[0m"
    exit 1
fi


# 출력 파일 이름 생성 (날짜와 시간 포함)
output="report_bpfdoor_suspect_processes_$(date '+%Y%m%d_%H%M%S').txt"
> "$output"  # 파일 초기화


# 배너 출력
echo -e "\033[1;31m" | tee -a "$output"
echo "██████╗ ██████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗" | tee -a "$output"
echo "██╔══██╗██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗" | tee -a "$output"
echo "██████╔╝██████╔╝█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║" | tee -a "$output"
echo "██╔══██╗██╔═══╝ ██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║" | tee -a "$output"
echo "██████╔╝██║     ██║     ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝" | tee -a "$output"
echo "╚═════╝ ╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝"  | tee -a "$output"
echo -e "\033[1;37m                                       BPFDoor Detection Tool"   | tee -a "$output"
echo -e "                                               Version 0.2"  | tee -a "$output"
echo -e "\033[0m"   | tee -a "$output"

suspicious_process_found=0
suspicious_binary_found=0
suspicious_pidfile_found=0

suspicious_pids=()
suspicious_binaries=()
suspicious_pidfiles=()


# RAW 소켓을 사용하는 프로세스 탐색
echo -e "\033[0m[RAW 소켓을 사용하는 프로세스 탐색]\033[0m" | tee -a "$output"

for pid in /proc/[0-9]*; do
    if egrep -q 'packet_recvmsg' "$pid/stack" 2>/dev/null; then
        suspicious_process_found=1
        pid_num=$(basename "$pid")
        suspicious_pids+=("$pid_num")

        echo -e "\033[31m[!] 의심스러운 프로세스 발견:\033[0m" | tee -a "$output"
        echo -e "\033[31m[!] 프로세스 ID:\033[0m $(basename $pid)" | tee -a "$output"
        echo -e "\033[31m[!] 스택 트레이스:\033[0m" | tee -a "$output"
        egrep 'packet_recvmsg' "$pid/stack" | tee -a "$output"
        ps -ef | grep "$(basename $pid)" | grep -v grep | tee -a "$output"
        ls -l /proc/$(basename $pid)/exe | tee -a "$output"
        echo "" | tee -a "$output"
    fi
done

if [ $suspicious_process_found -eq 0 ]; then
    echo -e "[+] 의심스러운 프로세스가 발견되지 않았습니다.\033[0m" | tee -a "$output"
fi

echo -e | tee -a "$output"

# 바이너리 파일 흔적 확인
echo -e "\033[0m[바이너리 파일 검색]\033[0m" | tee -a "$output"

for pid in "${suspicious_pids[@]}"; do
    exe_path="/proc/$pid/exe"
        
    hash=$(md5sum "$exe_path" 2>/dev/null | awk '{print $1}')
    echo -e "\n[+] PID: $pid" | tee -a "$output"
    echo "    - MD5 Hash: $hash" | tee -a "$output"

    echo "    - Searching for matching binaries..." | tee -a "$output"
    match=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib /lib64 /opt /etc /home /root /tmp /var/tmp /var/run /run /dev/shm /boot -type f -exec md5sum {} \; | grep "^$hash" | awk '{print $2}')

    if [ -n "$match" ]; then
        suspicious_binary_found=1
        echo -e "\033[31m    => Match found at: " | tee -a "$output"
        for path in $match; do
            echo -e "    => $path" | tee -a "$output"
            suspicious_binaries+=("$path")
        done
        echo -e "\033[0m" | tee -a "$output"
    else
        echo "    => No match found in known directories." | tee -a "$output"
    fi

done

echo -e | tee -a "$output"

if [ -f /dev/shm/kdmtmpflush ]; then
    suspicious_binary_found=1
    echo -e "\033[31m[!] /dev/shm/kdmtmpflush 파일 존재!\033[0m" | tee -a "$output"
else
    echo "[+] /dev/shm/kdmtmpflush 없음" | tee -a "$output"
fi

echo -e | tee -a "$output"

# Dropper 흔적 확인
echo -e "\033[0m[Dropper 흔적 확인]\033[0m" | tee -a "$output"
if [ -f /var/run/haldrund.pid ]; then
    suspicious_pidfile_found=1
    echo -e "\033[31m[!] /var/run/haldrund.pid 파일 존재!\033[0m" | tee -a "$output"
    suspicious_pidfiles+=("/var/run/haldrund.pid")
else
    echo "[+] /var/run/haldrund.pid 없음" | tee -a "$output"
fi

if [ -f /var/run/hald-smartd.pid ]; then
    suspicious_pidfile_found=1
    suspicious_pidfiles+=("/var/run/hald-smartd.pid")
    echo -e "\033[31m[!] /var/run/hald-smartd.pid 파일 존재!\033[0m" | tee -a "$output"
else
    echo "[+] /var/run/hald-smartd.pid 없음" | tee -a "$output"
fi

if [ -f /var/run/system.pid ]; then
    suspicious_pidfile_found=1
    suspicious_pidfiles+=("/var/run/system.pid")
    echo -e "\033[31m[!] /var/run/system.pid 파일 존재!\033[0m" | tee -a "$output"
else
    echo "[+] /var/run/system.pid 없음" | tee -a "$output"
fi

if [ -f /var/run/hp-health.pid ]; then
    suspicious_pidfile_found=1
    suspicious_pidfiles+=("/var/run/hp-health.pid")
    echo -e "\033[31m[!] /var/run/hp-health.pid 파일 존재!\033[0m" | tee -a "$output"
else
    echo "[+] /var/run/hp-health.pid 없음" | tee -a "$output"
fi

if [ -f /var/run/hald-addon.pid ]; then
    suspicious_pidfile_found=1
    suspicious_pidfiles+=("/var/run/hald-addon.pid")
    echo -e "\033[31m[!] /var/run/hald-addon.pid 파일 존재!\033[0m" | tee -a "$output"
else
    echo "[+] /var/run/hald-addon.pid 없음" | tee -a "$output"
fi

echo -e | tee -a "$output"


echo -e "\033[0m[결과]\033[0m" | tee -a "$output"
# 결과 출력 또는 없을 경우 메시지 출력
if [ $suspicious_process_found -eq 1 ]; then
    echo -e "\033[31m[!] 의심스러운 프로세스가 발견되었습니다.\033[0m" | tee -a "$output"

    echo -e "\033[31m[!] PID: ${suspicious_pids[*]}\033[0m" | tee -a "$output"
else
    echo -e "\033[32m[+] 의심스러운 프로세스가 발견되지 않았습니다.\033[0m" | tee -a "$output"
fi

echo -e | tee -a "$output"

if [ $suspicious_binary_found -eq 1 ]; then
    echo -e "\033[31m[!] 의심스러운 바이너리가 발견되었습니다.\033[0m" | tee -a "$output"

    for binary in "${suspicious_binaries[@]}"; do
        echo -e "\033[31m[!] 바이너리 경로: $binary\033[0m" | tee -a "$output"
    done

else
    echo -e "\033[32m[+] 의심스러운 바이너리가 발견되지 않았습니다.\033[0m" | tee -a "$output"
fi

echo -e | tee -a "$output"

if [ $suspicious_pidfile_found -eq 1 ]; then
    echo -e "\033[31m[!] 의심스러운 PID 파일이 발견되었습니다.\033[0m" | tee -a "$output"

    for pidfile in "${suspicious_pidfiles[@]}"; do
        echo -e "\033[31m[!] PID 파일 경로: $pidfile\033[0m" | tee -a "$output"
    done

else
    echo -e "\033[32m[+] 의심스러운 PID 파일이 발견되지 않았습니다.\033[0m" | tee -a "$output"
fi

echo -e
echo -e "\033[0m스캔이 완료되었습니다. 결과는 $output 파일에 저장되었습니다.\033[0m"
