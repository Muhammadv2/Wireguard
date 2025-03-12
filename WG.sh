#!/bin/bash
echo "what do yo do?"
echo "1) OS and Optimize Setup"
echo "2) Tunnel Server side tunnel setup"
echo "3) Client Server side tunnel setup"
echo "4) Add CronJob Time"
echo "5) Add Port To Tunnel Server"
echo "6) Add Port To Client Server"
echo "7) Allow Port on Firewall"
echo "8) TUNNEL CHECKERF"
echo "9) UNISTALL"
echo "q) exit"
read -p "Enter number (1,2,3) " choice

case $choice in
    1)
function error_exit {
    echo "$1" 1>&2
    exit 1
}
read -p $'\e[37mSSHPORT\e[0m: ' ssh_port
read -p $'\e[37mAllow Port For UFW--> (example 2053,2052,2082)-->\e[0m: ' other_ports
echo -e "\e[1;36mPress Enter To Start\e[0m"
read
sudo sed -i "s/^#Port 22/Port $ssh_port/" /etc/ssh/sshd_config
sudo systemctl restart sshd
sh -c 'apt-get update; apt-get upgrade -y; apt-get dist-upgrade -y; apt-get autoremove -y; apt-get autoclean -y'
sudo apt-get install -y software-properties-common ufw wget curl git socat cron busybox bash-completion locales nano apt-utils make golang make git logrotate
sudo ufw enable
IFS=',' read -r -a ports <<< "$other_ports"
for port in "${ports[@]}"; do
    sudo ufw allow "$port"/tcp
done
sudo ufw allow "$ssh_port"/tcp
for ip in 200.0.0.0/8 102.0.0.0/8 100.64.0.0/10 169.254.0.0/16 \
           198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 \
           224.0.0.0/4 240.0.0.0/4 255.255.255.255/32 \
           192.0.0.0/24 192.0.2.0/24 127.0.0.0/8 \
           127.0.53.53 192.168.0.0/16 172.16.0.0/12 \
           10.0.0.0/8; do
    sudo ufw deny out from any to "$ip"
done
for ip in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 \
           169.254.0.0/16 172.16.0.0/12 \
           192.0.0.0/24 192.0.2.0/24 \
           192.168.0.0/16 198.18.0.0/15 \
           198.51.100.0/24 203.0.113.0/24 \
           224.0.0.0/4 240.0.0.0/4 \
           103.71.29.0/24; do
    sudo iptables -A OUTPUT -p tcp -s 0/0 -d "$ip" -j DROP
done
sudo ufw reload
sudo timedatectl set-timezone Asia/Tehran
sudo systemctl restart systemd-timesyncd
echo 'su root syslog
/var/log/syslog {
    size 1G
    rotate 1
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        /etc/init.d/rsyslog restart
    endscript
}' | sudo tee -a /etc/logrotate.d/syslog
echo 'su root syslog' | sudo tee -a /etc/init.d/rsyslog
echo 'su root syslog' | sudo tee -a /etc/logrotate.conf
sudo logrotate -f /etc/logrotate.d/syslog
sudo logrotate -f /etc/logrotate.d/syslog
clear
sudo swapoff -v /swapfile
sudo rm /swapfile
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
echo 'vm.swappiness=40' | sudo tee -a /etc/sysctl.conf
curl -Ls https://raw.githubusercontent.com/Naochen2799/Latest-Kernel-BBR3/main/bbr3.sh | bash
clear
sudo sysctl -p
 echo $'\e[33;40mEverything Done- RF CUSTOM SETUP- REBOOT AND Go To Tunneling\e[0m'  
;;
    2)
read -p $'\e[1;36mTunnel PORT\e[0m --> ' connect_port
read -p $'\e[1;36minput inbund+panel ports (example: 2052,2053,2082,2083) \e[0m --> ' tunnel_ports
read -p $'\e[1;36minput protocol(tcp or udp)\e[0m --> ' protocol
if [[ "$protocol" == "tcp" || "$protocol" == "udp" ]]; then
    ports_string=""
    IFS=',' read -ra ports <<< "$tunnel_ports"
    for port in "${ports[@]}"; do
        ports_string+="$port/$protocol, "
    done
    ports_string=${ports_string%, }
auth_key=$(openssl rand -hex 32)
    git clone https://github.com/snsinfu/reverse-tunnel
    cd reverse-tunnel || exit
    make
    echo "control_address: 0.0.0.0:$connect_port
agents:
- auth_key: $auth_key
  ports: [$ports_string]" | sudo tee /root/reverse-tunnel/rtun-server.yml
echo '#!/bin/bash
sudo systemctl restart rtun-server
sudo journalctl --vacuum-size=1M' | sudo tee -a /etc/reset.sh
sudo chmod +x /etc/reset.sh

    echo "[Unit]
Description=rtun server
[Service]
Type=simple
ExecStart=/root/reverse-tunnel/./rtun-server -f /root/reverse-tunnel/rtun-server.yml
Restart=always
RestartSec=5
LimitNOFILE=2084135
[Install]
WantedBy=default.target" | sudo tee /etc/systemd/system/rtun-server.service
    sudo systemctl enable rtun-server
    sudo systemctl start rtun-server
    sudo systemctl status rtun-server
	echo -e "\e[33;40mSERVER KEY : $auth_key\e[0m"
	echo -e "\e[32;40mTUNNEL Port : $connect_port\e[0m	"
	echo -e "\e[33;40mOPEN PORTS : [$ports_string]\e[0m"
else
    echo "invaild port/protocol"
fi
;;
    3)
read -p $'\e[1;36mTunnel PORT\e[0m--> ' connect_port
read -p $'\e[1;36minput inbound+panel ports (example: 2052,2053,2082,2083)\e[0m--> ' tunnel_ports
read -p $'\e[1;36minput protocol(tcp or udp)--> \e[0m ' protocol
read -p $'\e[1;36mSERVER IP\e[0m--> ' myservertip
read -p $'\e[1;36mSERVER KEY\e[0m--> ' myservertkey
clear
if [[ "$protocol" == "tcp" || "$protocol" == "udp" ]]; then
    ports_string=""
    IFS=',' read -ra ports <<< "$tunnel_ports"
    for port in "${ports[@]}"; do
        ports_string+="  - port: $port/$protocol\n    destination: 127.0.0.1:$port\n"
    done
    ports_string=${ports_string%\\n}
    git clone https://github.com/snsinfu/reverse-tunnel
    cd reverse-tunnel || exit
    make
clear
    echo -e "
gateway_url: ws://$myservertip:$connect_port
auth_key: $myservertkey
forwards:
$ports_string" | sudo tee /root/reverse-tunnel/rtun.yml
echo '#!/bin/bash
sudo systemctl daemon-reload
pids=$(pgrep rtun)
sudo kill -9 $pids
sudo systemctl restart rtun
sudo journalctl --vacuum-size=1M' | sudo tee -a /etc/reset.sh
sudo chmod +x /etc/reset.sh
clear
    echo "[Unit]
Description=rtun
[Service]
Type=simple
ExecStart=/root/reverse-tunnel/./rtun -f /root/reverse-tunnel/rtun.yml
Restart=always
RestartSec=5
LimitNOFILE=2084135
[Install]
WantedBy=default.target" | sudo tee /etc/systemd/system/rtun.service
clear
    sudo systemctl enable rtun
    sudo systemctl start rtun
clear
    sudo systemctl status rtun
    echo -e "\e[33;40mSERVER IP : $myservertip\e[0m"
    echo -e "\e[32;45mSERVER KEY : $myservertkey\e[0m"
    echo -e "\e[33;40mTUNNEL Port : $connect_port\e[0m"
    echo -e "\e[32;45mOPEN PORTS : [$ports_string]\e[0m"
else
    echo "invalid port/protocol"
fi
 ;;
    4)
times=()
while true; do
    read -p $'\e[33;40madd time to cron (Format 04:20)\e[0m --> ' time_input
    if [[ ! "$time_input" =~ ^[01][0-9]:[0-5][0-9]$ && ! "$time_input" =~ ^2[0-3]:[0-5][0-9]$ ]]; then
        echo -e "\e[31;40minvalid time\e[0m"
        continue
    fi
    times+=("$time_input")
    read -p $'\e[33;40miput Y for add new time to cron / S for created cronjob\e[0m --> ' answer
    if [[ "$answer" == "s" || "$answer" == "S" ]]; then
        break 
    fi
done
cron_jobs=""
for time in "${times[@]}"; do
    IFS=: read hour minute <<< "$time"
    cron_jobs+="${minute} ${hour} * * * /bin/bash /etc/reset.sh  > /dev/null 2>&1\n"
done
(crontab -l 2>/dev/null; echo -e "$cron_jobs") | crontab -
echo -e "$cron_jobs"
echo -e "\e[33;40mTIME Added to cron\e[0m"
        ;;
    5)
while true; do
    read -p $'\e[33;40mNEW PORT\e[0m --> ' new_port
    read -p $'\e[33;40mProtocol (udp or tcp)\e[0m --> ' protocol
    if [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; then
        echo -e "\e[31;40mInvalid protocol. Please enter 'tcp' or 'udp'.\e[0m"
        continue 
    fi
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "\e[31;40mInvalid port. Please enter a number between 1 and 65535.\e[0m"
        continue  
    fi
    file_path="/root/reverse-tunnel/rtun-server.yml"
    if grep -q "ports:" "$file_path"; then
        sed -i "/ports:/ s/\(\[.*\)\]/\1, $new_port\/$protocol]/" "$file_path"
    else
        echo "ports: [$new_port/$protocol]" >> "$file_path"
    fi
	sudo systemctl restart rtun-server
	echo -e "\e[32;40m$new_port/$protocol added successfully.\e[0m"
    break
done
        ;;
    6)
while true; do
    read -p $'\e[33;40mNEW PORT\e[0m --> ' new_port
    read -p $'\e[33;40mProtocol (udp or tcp)\e[0m --> ' protocol
    if [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; then
        echo -e "\e[31;40mInvalid protocol. Please enter 'tcp' or 'udp'.\e[0m"
        continue 
    fi
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "\e[31;40mInvalid port. Please enter a number between 1 and 65535.\e[0m"
        continue  
    fi
    new_entry="  - port: ${new_port}/${protocol}\n    destination: 127.0.0.1:${new_port}"
    echo -e "$new_entry" >> /root/reverse-tunnel/rtun.yml
sudo systemctl restart rtun

    echo -e "\e[32;40m$new_port/$protocol added successfully.\e[0m"   
    break
done
        ;;
    7)
if [ "$EUID" -ne 0 ]; then
  echo "RUN by ROOT user"
  exit
fi
while true; do
  read -p $'\e[33;40mNEW PORT(example 2052,2053)\e[0m --> ' ports
  IFS=',' read -r -a port_array <<< "$ports"
  valid_ports=true
  for port in "${port_array[@]}"; do
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
echo $'\e[33;40mPlease enter valid numeric ports.\e[0m --> '
      valid_ports=false
      break
    fi
  done
  if $valid_ports; then
    break
  fi
done
while true; do
  read -p $'\e[33;40mProtocol (udp or tcp)\e[0m --> ' protocol
  if [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; then
echo $'\e[33;40mInput tcp or udp\e[0m --> '
  else
    break
  fi
done
for port in "${port_array[@]}"; do
  ufw allow "$port/$protocol"
done
sudo ufw reload
clear
echo $'\e[33;40mFIREWALL(UFW) STATUS\e[0m --> '
ufw status
        ;;
    8)
#!/bin/bash
read -p $'\e[33;40mMAX Error For Reset Services\e[0m: ' maxerror
read -p $'\e[33;40mDomain Or IP\e[0m: ' mydomainorip
read -p $'\e[33;40mPORT\e[0m: ' myporting
read -p $'\e[33;40mRetry when faild(1-5)\e[0m: ' retryafter
read -p $'\e[33;40mRetry when OK(45-90)\e[0m: ' secafter
echo '#!/bin/bash
ERROR_COUNT=0
MAX_ERRORS='"$maxerror"'
LOG_FILE="/etc/checkerf.txt"
while true; do
    if ! nc -z -w 5 '"$mydomainorip"' '"$myporting"'; then
        ((ERROR_COUNT++))
        echo "Connection failed. Error count: $ERROR_COUNT"
        
        if [ "$ERROR_COUNT" -ge "$MAX_ERRORS" ]; then
            echo "Maximum error count reached. Executing reset.sh..."
            sudo /bin/bash /etc/reset.sh
            
            echo "reset.sh executed at: $(date)" >> "$LOG_FILE"
            
            ERROR_COUNT=0 # Reset error count after executing the script
        else
            sleep '"$retryafter"' # Wait for specified seconds before retrying
        fi
    else
        ERROR_COUNT=0
        echo "Connection successful."
        sleep '"$secafter"' # Wait for specified seconds before the next check
    fi
done
' | sudo tee /etc/checkerf.sh
sudo chmod +x /etc/checkerf.sh
echo '[Unit]
Description=checkerf
After=network.target

[Service]
ExecStart=/etc/checkerf.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
' | sudo tee /etc/systemd/system/checkerf.service

sudo systemctl daemon-reload
sudo systemctl enable checkerf.service
sudo systemctl start checkerf.service
sudo systemctl relaod checkerf.service
sudo systemctl restart checkerf.service
sudo systemctl status checkerf.service

echo $'\e[33;40mChekerF Runnig(45-90)\e[0m: '

        ;;
9)
remove_service() {
    local service_name=$1
    if systemctl is-active --quiet "$service_name"; then
        echo "unistall $service_name..."
        systemctl stop "$service_name"
        systemctl disable "$service_name"
    fi
    echo "unistall $service_name..."
    systemctl reset-failed "$service_name" 
    rm -f "/etc/systemd/system/$service_name.service"
    systemctl daemon-reload

}
clear
remove_service "rtun"
remove_service "rtun-server"
if [ -f "/root/reverse-tunnel/rtun.yml" ]; then
    echo "delete /root/reverse-tunnel/rtun.yml..."
    rm -f "/root/reverse-tunnel/rtun.yml"
fi
if [ -f "/root/reverse-tunnel/rtun-server.yml" ]; then
    echo "delete /root/reverse-tunnel/rtun-server.yml..."
    rm -f "/root/reverse-tunnel/rtun-server.yml"
fi
if [ -d "/root/reverse-tunnel/" ]; then
    echo "delete /root/reverse-tunnel/..."
    rm -rf "/root/reverse-tunnel/"
fi
    systemctl daemon-reload

    echo -e "\e[32;40mTunnel Service Unistall\e[0m"
        ;;
    q)
        echo "exit"
        ;;
    *)
        echo "invaild parametrs"
        ;;
esac
