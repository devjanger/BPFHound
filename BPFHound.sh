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
echo -e "\033[1;31m" >> "$output"
echo "██████╗ ██████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗" >> "$output"
echo "██╔══██╗██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗" >> "$output"
echo "██████╔╝██████╔╝█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║" >> "$output"
echo "██╔══██╗██╔═══╝ ██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║" >> "$output"
echo "██████╔╝██║     ██║     ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝" >> "$output"
echo "╚═════╝ ╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝"  >> "$output"
echo -e "\033[1;37m                                         BPFDoor Detection Tool"   >> "$output"
echo -e "                                               Version 0.1"  >> "$output"
echo -e "\033[0m"   >> "$output"

suspicious_found=0

# RAW 소켓을 사용하는 프로세스 탐색
echo -e "\033[0m[RAW 소켓을 사용하는 프로세스 탐색]\033[0m" >> "$output"

for pid in /proc/[0-9]*; do
    if egrep -q 'packet_recvmsg' "$pid/stack"; then
        suspicious_found=1
        echo -e "\033[31m[!] 의심스러운 프로세스 발견:\033[0m" >> "$output"
        echo -e "\033[31m[!] 프로세스 ID:\033[0m $(basename $pid)" >> "$output"
        echo -e "\033[31m[!] 스택 트레이스:\033[0m" >> "$output"
        egrep 'packet_recvmsg' "$pid/stack" >> "$output"
        ps -ef | grep "$(basename $pid)" | grep -v grep >> "$output"
        echo "" >> "$output"
    fi
done

if [ $suspicious_found -eq 0 ]; then
    echo -e "[+] 의심스러운 프로세스가 발견되지 않았습니다.\033[0m" >> "$output"
fi

echo -e >> "$output"

# 바이너리 파일 흔적 확인
echo -e "\033[0m[바이너리 파일 흔적 확인]\033[0m" >> "$output"
if [ -f /dev/shm/kdmtmpflush ]; then
    suspicious_found=1
    echo -e "\033[31m[!] /dev/shm/kdmtmpflush 파일 존재!\033[0m" >> "$output"
else
    echo "[+] /dev/shm/kdmtmpflush 없음" >> "$output"
fi

echo -e >> "$output"

# Dropper 흔적 확인
echo -e "\033[0m[Dropper 흔적 확인]\033[0m" >> "$output"
if [ -f /var/run/haldrund.pid ]; then
    suspicious_found=1
    echo -e "\033[31m[!] /var/run/haldrund.pid 파일 존재!\033[0m" >> "$output"
else
    echo "[+] /var/run/haldrund.pid 없음" >> "$output"
fi

echo -e >> "$output"


echo -e "\033[0m[결과]\033[0m" >> "$output"
# 결과 출력 또는 없을 경우 메시지 출력
if [ $suspicious_found -eq 1 ]; then
    echo -e "\033[31m의심스러운 프로세스가 발견되었습니다.\033[0m" >> "$output"
else
    echo -e "\033[32m의심스러운 프로세스가 발견되지 않았습니다.\033[0m" >> "$output"
fi

# 출력 내용 화면에 표시
cat "$output"
echo -e "\033[0m[+] 스캔이 완료되었습니다. 결과는 $output 파일에 저장되었습니다.\033[0m"
