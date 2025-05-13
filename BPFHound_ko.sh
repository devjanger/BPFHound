#!/bin/bash

# 루트 권한으로 실행되었는지 확인
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[31m이 스크립트는 루트 권한으로 실행되어야 합니다. sudo로 실행해주세요.\033[0m"
    exit 1
fi

# 출력 파일 이름 생성 (날짜와 시간 포함)
output="report_bpfdoor_suspect_processes_$(date '+%Y%m%d_%H%M%S').txt"
> "$output"

# 배너 출력
{
    echo -e "\033[1;31m"
    echo "██████╗ ██████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗"
    echo "██╔══██╗██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗"
    echo "██████╔╝██████╔╝█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║"
    echo "██╔══██╗██╔═══╝ ██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║"
    echo "██████╔╝██║     ██║     ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝"
    echo "╚═════╝ ╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝"
    echo -e "\033[1;37m                                       BPFDoor Detection Tool"
    echo "                                               Version 0.2.1"
    echo -e "\033[0m"
} | tee -a "$output"

suspicious_process_found=0
suspicious_binary_found=0
suspicious_pidfile_found=0
suspicious_pids=()
suspicious_binaries=()
suspicious_pidfiles=()

echo -e "[+] 스캔 시작..." | tee -a "$output"
echo | tee -a "$output"

echo -e "[RAW 소켓을 사용하는 프로세스 탐색]" | tee -a "$output"
for pid in /proc/[0-9]*; do
    if grep -q 'packet_recvmsg' "$pid/stack" 2>/dev/null; then
        pid_num=$(basename "$pid")
        suspicious_process_found=1
        suspicious_pids+=("$pid_num")

        echo -e "\033[31m[!] 의심스러운 프로세스 발견:\033[0m" | tee -a "$output"
        echo -e "\033[31m[!] 프로세스 ID:\033[0m $pid_num" | tee -a "$output"
        echo -e "\033[31m[!] 스택 트레이스:\033[0m" | tee -a "$output"
        grep 'packet_recvmsg' "$pid/stack" | tee -a "$output"
        ps -ef | grep "$pid_num" | grep -v grep | tee -a "$output"
        ls -l "/proc/$pid_num/exe" | tee -a "$output"
        echo | tee -a "$output"
    fi
done

if [ $suspicious_process_found -eq 0 ]; then
    echo -e "[+] 의심스러운 프로세스가 발견되지 않았습니다." | tee -a "$output"
fi

echo | tee -a "$output"
echo -e "[바이너리 파일 검색]" | tee -a "$output"

for pid in "${suspicious_pids[@]}"; do
    exe_path="/proc/$pid/exe"
    hash=$(md5sum "$exe_path" 2>/dev/null | awk '{print $1}')

    echo -e "[+] PID: $pid" | tee -a "$output"
    echo "    - MD5 Hash: $hash" | tee -a "$output"
    echo "    - Searching for matching binaries..." | tee -a "$output"

    match=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib /lib64 /opt /etc /home /root /tmp /var/tmp /var/run /run /dev/shm /boot -type f -exec md5sum {} \; 2>/dev/null | grep "^$hash" | awk '{print $2}')

    if [ -n "$match" ]; then
        suspicious_binary_found=1
        echo -e "\033[31m    => 일치하는 바이너리 경로:\033[0m" | tee -a "$output"
        for path in $match; do
            echo "       $path" | tee -a "$output"
            suspicious_binaries+=("$path")
        done
    else
        echo "    => 일치하는 바이너리가 발견되지 않았습니다." | tee -a "$output"
    fi

done

echo | tee -a "$output"

if [ -f /dev/shm/kdmtmpflush ]; then
    echo -e "\033[31m[!] /dev/shm/kdmtmpflush 파일 존재!\033[0m" | tee -a "$output"
    suspicious_binary_found=1
else
    echo "[+] /dev/shm/kdmtmpflush 없음" | tee -a "$output"
fi

echo | tee -a "$output"
echo "[Dropper 흔적 확인]" | tee -a "$output"
dropper_paths=(
    /var/run/haldrund.pid
    /var/run/hald-smartd.pid
    /var/run/system.pid
    /var/run/hp-health.pid
    /var/run/hald-addon.pid
)

for file in "${dropper_paths[@]}"; do
    if [ -f "$file" ]; then
        echo -e "\033[31m[!] $file 파일 존재!\033[0m" | tee -a "$output"
        suspicious_pidfile_found=1
        suspicious_pidfiles+=("$file")
    else
        echo "[+] $file 없음" | tee -a "$output"
    fi

done

echo | tee -a "$output"
echo "[결과]" | tee -a "$output"

if [ $suspicious_process_found -eq 1 ]; then
    echo -e "\033[31m[!] 의심스러운 프로세스 발견됨\033[0m" | tee -a "$output"
    printf "\033[31m[!] PID: %s\033[0m\n" "${suspicious_pids[@]}" | tee -a "$output"
else
    echo -e "\033[32m[+] 의심스러운 프로세스 없음\033[0m" | tee -a "$output"
fi

echo | tee -a "$output"

if [ $suspicious_binary_found -eq 1 ]; then
    echo -e "\033[31m[!] 의심스러운 바이너리 발견됨\033[0m" | tee -a "$output"
    for binary in "${suspicious_binaries[@]}"; do
        echo -e "\033[31m[!] 바이너리 경로: $binary\033[0m" | tee -a "$output"
    done
else
    echo -e "\033[32m[+] 의심스러운 바이너리 없음\033[0m" | tee -a "$output"
fi

echo | tee -a "$output"

if [ $suspicious_pidfile_found -eq 1 ]; then
    echo -e "\033[31m[!] 의심스러운 PID 파일 발견됨\033[0m" | tee -a "$output"
    for pidfile in "${suspicious_pidfiles[@]}"; do
        echo -e "\033[31m[!] PID 파일 경로: $pidfile\033[0m" | tee -a "$output"
    done
else
    echo -e "\033[32m[+] 의심스러운 PID 파일 없음\033[0m" | tee -a "$output"
fi

echo

# 출력 완료 메시지
echo -e "\033[0m스캔이 완료되었습니다. 결과는 $output 파일에 저장되었습니다.\033[0m"
