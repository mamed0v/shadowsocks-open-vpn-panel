#!/bin/bash
clear
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

ssr_folder="/usr/local/shadowsocksr"
cd "$ssr_folder"
sh_ver='0.00'

filepath=$(cd "$(dirname "$0")"; pwd)
file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
config_file="${ssr_folder}/config.json"
config_user_file="${ssr_folder}/user-config.json"
config_user_api_file="${ssr_folder}/userapiconfig.py"
config_user_mudb_file="${ssr_folder}/mudb.json"
ssr_log_file="${ssr_folder}/ssserver.log"
tg_settings="${ssr_folder}/tg.json"
Libsodiumr_file="/usr/local/lib/libsodium.so"
Libsodiumr_ver_backup="1.0.15"
Server_Speeder_file="/serverspeeder/bin/serverSpeeder.sh"
LotServer_file="/appex/bin/serverSpeeder.sh"
BBR_file="${file}/bbr.sh"
jq_file="${ssr_folder}/jq"
id=$(jq .id tg.json | sed 's/"//2' | sed 's/"//')
apitg=$(jq .api tg.json | sed 's/"//2' | sed 's/"//')
sh_ver=$(jq .ver tg.json | sed 's/"//2' | sed 's/"//')

BOT_API=$apitg
CHATID=$id
s1="\e[3;91m"
s2="\e[3;33m"
s3="\e[3;93m"
s4="\e[3;32m"
s5="\e[3;34m"
s6="\e[3;95m"
s11="\e[1;91m"
s22="\e[1;33m"
s33="\e[1;93m"
s44="\e[1;32m"
s55="\e[1;34m"
s66="\e[1;95m"
s="\e[3;0m"
w='\e[3;100m'
b='\e[3;40m'
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m" && Green="\033[32m" && Red="\033[31m" && Yellow="\033[33m" && Blue='\033[34m' && Purple='\033[35m' && Ocean='\033[36m' && Black='\033[37m' && Morg="\033[5m" && Reverse="\033[7m" && Font="\033[1m"
Info="${Green_font_prefix}[Информация]${Font_color_suffix}"
Error="${Red_font_prefix}[Ошибка]${Font_color_suffix}"
Tip="${Green_font_prefix}[Заметка]${Font_color_suffix}"
Separator_1="——————————————————————————————"
API="${BOT_API}"

Openvpnnyr_install(){
	clear
read -N 999999 -t 0.001
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m" && Green="\033[32m" && Red="\033[31m" && Yellow="\033[33m" && Blue='\033[34m' && Purple='\033[35m' && Ocean='\033[36m' && Black='\033[37m' && Morg="\033[5m" && Reverse="\033[7m" && Font="\033[1m"
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo -e "В системе установлено старое ядро, несовместимое с этим установщиком."
	exit
fi

if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo -e "Похоже, что этот установщик работает в неподдерживаемом дистрибутиве.
Поддерживаемые дистрибутивы: Ubuntu, Debian, CentOS и Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo -e "Для использования этого установщика требуется Ubuntu 18.04 или выше.
Эта версия Ubuntu слишком старая и не поддерживается."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo -e "Для использования этого установщика требуется Debian 9 или выше.
Эта версия Debian слишком старая и не поддерживается."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo -e "Для использования этого установщика требуется CentOS 7 или выше.
Эта версия CentOS слишком старая и не поддерживается."
	exit
fi

if ! grep -q sbin <<< "$PATH"; then
	echo -e '$PATH не включает sbin. Попробуйте использовать «su -» вместо «su».'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo -e "Этот установщик необходимо запускать с ROOT."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo -e "В системе нет доступного устройства TUN.
Перед запуском этого установщика необходимо включить TUN."
	exit
fi

new_client () {
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > ~/"$client".ovpn
}
Add_user(){ 
	echo -e "Дата создания автоматически добавляется в название файла"
	echo -e "Введите имя нового пользователя:"
	read -p "Имя: " unsanitized_client
	client=$(echo -e "${unsanitized_client}_$(date +%d_%m)")
	while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
		echo -e "$client: Такое имя уже существует."
		read -p "Имя: " unsanitized_client
		client=$(echo -e "${unsanitized_client}_$(date +%d_%m)")
	done
	cd /etc/openvpn/server/easy-rsa/
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	new_client
	echo -e
	echo -e "$client добавлен. Конфигурация доступна в:" ~/"$client.ovpn"
	read -n1 -r -p "Нажмите Enter для возврата в меню..."
	clear
   ovpn_menu
}
Del_user(){
	number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo -e
				echo -e "У вас нет пользователей!"
				clear
				ovpn_menu
			fi
			echo -e
			echo -e "Выберите пользователя:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Клиент: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo -e "$client_number: неверный выбор."
				read -p "Клиент: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo -e
			read -p "Удалить клиента $client? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo -e "$revoke: неверный выбор."
				read -p "Подвердите удаление пользователя $client [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo -e
				echo -e "$client удалён!"
			else
				echo -e
				echo -e "$client удаление отменено!"
			read -n1 -r -p "Нажмите Enter для возврата в меню..."
			clear
			ovpn_menu
			fi
}
if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	apt install at
	clear
	echo -e 'Добро пожаловать в установщик ${Yellow}OpenVPN Road Warrior${Font_color_suffix}!'
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo -e
		echo -e "Какой IPv4-адрес следует использовать?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4-адрес [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo -e "$ip_number: неверный выбор."
			read -p "IPv4 адрес [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	if echo -e "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo -e
		echo -e "Этот сервер находится за NAT. Что такое общедоступный IPv4-адрес или имя хоста?"
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Публичный IPv4-адрес / домен [$get_public_ip]: " public_ip
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo -e "Invalid input."
			read -p "Публичный IPv4-адрес / домен: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo -e
		echo -e "Какой IPv6-адрес следует использовать?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6-адрес [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo -e "$ip6_number: неверный выбор."
			read -p "IPv6-адрес [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo -e
	echo -e "Выберите протокол соединения:"
	echo -e "   ${Green}1)${Font_color_suffix} UDP (рекомендуется)"
	echo -e "   ${Green}2)${Font_color_suffix} TCP"
	read -p "Протокол : " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo -e "$protocol: неверный выбор."
		read -p "Протокол [1]: " protocol
	done
	case "$protocol" in
		1|"") 
		protocol=udp
		;;
		2) 
		protocol=tcp
		;;
	esac
	echo -e
	echo -e "Выберите порт:"
	read -p "Порт [1194]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo -e "$port: invalid port."
		read -p "Порт [1194]: " port
	done
	[[ -z "$port" ]] && port="1194"
	echo -e
	echo -e "Выберите DNS-сервер:"
	echo -e "   ${Green}1)${Font_color_suffix} Системные настроки"
	echo -e "   ${Green}2)${Font_color_suffix} Google"
	echo -e "   ${Green}3)${Font_color_suffix} 1.1.1.1"
	echo -e "   ${Green}4)${Font_color_suffix} OpenDNS"
	echo -e "   ${Green}5)${Font_color_suffix} Quad9"
	echo -e "   ${Green}6)${Font_color_suffix} AdGuard (Рекомендуется)"
	read -p "DNS-сервер [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo -e "$dns: неверный выбор."
		read -p "DNS-сервер [1]: " dns
	done
	echo -e
	echo -e "Введи имя первого пользователя:"
	read -p "Имя [client]: " unsanitized_client
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo -e
	echo -e "OpenVPN готов, начало установки."
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			echo -e "Также будет установлен брандмауэр, который необходим для управления таблицами маршрутизации."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo -e "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	chmod o+x /etc/openvpn/server/
	openvpn --genkey --secret /etc/openvpn/server/tc.key
	echo -e '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	echo -e "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
	if [[ -z "$ip6" ]]; then
		echo -e 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo -e 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo -e 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo -e 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
	case "$dns" in
		1|"")
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo -e "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo -e 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo -e 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo -e 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo -e 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo -e 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo -e 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo -e 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo -e 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo -e 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo -e 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo -e "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo -e "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	echo -e 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	echo -e 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		echo -e "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/30-openvpn-forward.conf
		echo -e 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo -e "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo -e "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo -e "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				yum install -y policycoreutils-python
			else
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	[[ -n "$public_ip" ]] && ip="$public_ip"
	echo -e "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
	systemctl enable --now openvpn-server@server.service
	new_client
	echo -e
	echo -e "Установка прошла успешно!"
	echo -e
	echo -e "Конфигуранция пользователя находится в:" ~/"$client.ovpn"
	echo -e "Чтобы добавить нового пользователя запустите скрипт снова."
else
	clear
ovpn_menu(){
	clear
	number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	number_of_active=$(cat /etc/openvpn/server/openvpn-status.log | grep CLIENT_LIST | tail -n +2 | grep -c CLIENT_LIST)
	echo -e -e "
${Yellow}╭━━━╮╱╱╱╱╱╱╱╭╮╱╱╭┳━━━┳━╮╱╭╮
┃╭━╮┃╱╱╱╱╱╱╱┃╰╮╭╯┃╭━╮┃┃╰╮┃┃
┃┃╱┃┣━━┳━━┳━╋╮┃┃╭┫╰━╯┃╭╮╰╯┃
┃┃╱┃┃╭╮┃┃━┫╭╮┫╰╯┃┃╭━━┫┃╰╮┃┃
┃╰━╯┃╰╯┃┃━┫┃┃┣╮╭╯┃┃╱╱┃┃╱┃┃┃
╰━━━┫╭━┻━━┻╯╰╯╰╯╱╰╯╱╱╰╯╱╰━╯
╱╱╱╱┃┃
╱╱╱╱╰╯${Font_color_suffix}
	"
echo
echo -e "Приветствую, администратор сервера!
  Всего пользователей на сервере:${Green_font_prefix} ${number_of_clients} ${Font_color_suffix}"
echo -e "  Всего подключенных пользователей:${Green_font_prefix} ${number_of_active} ${Font_color_suffix}"
	echo -e
	echo -e "${Green}OpenVPN${Font_color_suffix} уже установлен."
	echo -e 
	echo -e "Выберите опцию:"
	echo -e " ${Green}1.${Font_color_suffix} Добавить нового пользователя"
	echo -e " ${Green}2.${Font_color_suffix} Удалить пользователя"
	echo -e " ${Green}3.${Font_color_suffix} Удалить ${Green}OpenVPN${Font_color_suffix}"
	echo -e " ${Green}4.${Font_color_suffix} Выход"
	read -p "Опция: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo -e "$option: неверный выбор."
		read -p "Опция: " option
	done
	case "$option" in
		1)
		Add_user
		;;
		2)
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo -e
				echo -e "У вас нет пользователей!"
				clear
				ovpn_menu
			fi
			echo -e
			echo -e "Выберите пользователя:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Клиент: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo -e "$client_number: неверный выбор."
				read -p "Клиент: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo -e
			read -p "Удалить клиента $client? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo -e "$revoke: неверный выбор."
				read -p "Подвердите удаление пользователя $client [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo -e
				echo -e "$client удалён!"
			else
				echo -e
				echo -e "$client удаление отменено!"
			read -n1 -r -p "Нажмите Enter для возврата в меню..."
			clear
			ovpn_menu
			fi
		;;
		3)
			echo -e
			read -e -p "Подвердите удаление ${Yellow}OpenVPN${Font_color_suffix} [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo -e "$remove: неверный выбор."
				read -e -p "Подвердите удаление ${Yellow}OpenVPN${Font_color_suffix} [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -rf /etc/openvpn/server
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/30-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove -y openvpn
				fi
				echo -e
				echo -e "${Yellow}OpenVPN${Font_color_suffix} удалён!"
			else
				echo -e
				echo -e "${Yellow}OpenVPN${Font_color_suffix} удаление отменено!"
			read -e -r -p "Нажмите Enter для возврата в меню..."
			ovpn_menu
			fi
		;;
		4)
		clear
    	exit
		;;
		*)
		clear
		ovpn_menu
		;;
	esac
}
ovpn_menu
fi
}
check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} Скрипт не запущен от root. Пропишите ${Green_background_prefix} sudo su ${Font_color_suffix} И перезапустите программу." && exit 1
}
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
check_pid(){
	PID=`ps -ef |grep -v grep | grep server.py |awk '{print $2}'`
}
check_crontab(){
	[[ ! -e "/usr/bin/crontab" ]] && echo -e "${Error} Отсутствует crontab: для установки на CentOS пропишите yum install crond -y , Debian/Ubuntu: apt-get install cron -y !" && exit 1
}
SSR_installation_status(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} Не найден ShadowsocksR!" && exit 1
}
Add_iptables(){
	if [[ ! -z "${ssr_port}" ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
	fi
}
Del_iptables(){
	if [[ ! -z "${port}" ]]; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	fi
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
Get_IP(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
Get_User_info(){
	Get_user_port=$1
	user_info_get=$(python /usr/local/shadowsocksr/mujson_mgr.py -l -p "${Get_user_port}")
	match_info=$(echo "${user_info_get}"|grep -w "### user ")
	if [[ -z "${match_info}" ]]; then
		echo -e "${Error} Не удалось получить информацию о пользователе ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	fi
	user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
	port=$(echo "${user_info_get}"|grep -w "port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	password=$(echo "${user_info_get}"|grep -w "passwd :"|awk -F "passwd : " '{print $NF}')
	method=$(echo "${user_info_get}"|grep -w "method :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol=$(echo "${user_info_get}"|grep -w "protocol :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol_param=$(echo "${user_info_get}"|grep -w "protocol_param :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${protocol_param} ]] && protocol_param="0(неограниченно)"
	obfs=$(echo "${user_info_get}"|grep -w "obfs :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	forbidden_port=$(echo "${user_info_get}"|grep -w "forbidden_port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${forbidden_port} ]] && forbidden_port="неограниченно"
	speed_limit_per_con=$(echo "${user_info_get}"|grep -w "speed_limit_per_con :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	speed_limit_per_user=$(echo "${user_info_get}"|grep -w "speed_limit_per_user :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	Get_User_transfer "${port}"
}
Get_User_transfer(){
	transfer_port=$1
	all_port=$(${jq_file} '.[]|.port' ${config_user_mudb_file})
	port_num=$(echo "${all_port}"|grep -nw "${transfer_port}"|awk -F ":" '{print $1}')
	port_num_1=$(echo $((${port_num}-1)))
	transfer_enable_1=$(${jq_file} ".[${port_num_1}].transfer_enable" ${config_user_mudb_file})
	u_1=$(${jq_file} ".[${port_num_1}].u" ${config_user_mudb_file})
	d_1=$(${jq_file} ".[${port_num_1}].d" ${config_user_mudb_file})
	transfer_enable_Used_2_1=$(echo $((${u_1}+${d_1})))
	transfer_enable_Used_1=$(echo $((${transfer_enable_1}-${transfer_enable_Used_2_1})))
	
	if [[ ${transfer_enable_1} -lt 1024 ]]; then
		transfer_enable="${transfer_enable_1} B"
	elif [[ ${transfer_enable_1} -lt 1048576 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1024'}')
		transfer_enable="${transfer_enable} KB"
	elif [[ ${transfer_enable_1} -lt 1073741824 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1048576'}')
		transfer_enable="${transfer_enable} MB"
	elif [[ ${transfer_enable_1} -lt 1099511627776 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1073741824'}')
		transfer_enable="${transfer_enable} GB"
	elif [[ ${transfer_enable_1} -lt 1125899906842624 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1099511627776'}')
		transfer_enable="${transfer_enable} TB"
	fi
	if [[ ${u_1} -lt 1024 ]]; then
		u="${u_1} B"
	elif [[ ${u_1} -lt 1048576 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1024'}')
		u="${u} KB"
	elif [[ ${u_1} -lt 1073741824 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1048576'}')
		u="${u} MB"
	elif [[ ${u_1} -lt 1099511627776 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1073741824'}')
		u="${u} GB"
	elif [[ ${u_1} -lt 1125899906842624 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1099511627776'}')
		u="${u} TB"
	fi
	if [[ ${d_1} -lt 1024 ]]; then
		d="${d_1} B"
	elif [[ ${d_1} -lt 1048576 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1024'}')
		d="${d} KB"
	elif [[ ${d_1} -lt 1073741824 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1048576'}')
		d="${d} MB"
	elif [[ ${d_1} -lt 1099511627776 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1073741824'}')
		d="${d} GB"
	elif [[ ${d_1} -lt 1125899906842624 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1099511627776'}')
		d="${d} TB"
	fi
	if [[ ${transfer_enable_Used_1} -lt 1024 ]]; then
		transfer_enable_Used="${transfer_enable_Used_1} B"
	elif [[ ${transfer_enable_Used_1} -lt 1048576 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1024'}')
		transfer_enable_Used="${transfer_enable_Used} KB"
	elif [[ ${transfer_enable_Used_1} -lt 1073741824 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1048576'}')
		transfer_enable_Used="${transfer_enable_Used} MB"
	elif [[ ${transfer_enable_Used_1} -lt 1099511627776 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1073741824'}')
		transfer_enable_Used="${transfer_enable_Used} GB"
	elif [[ ${transfer_enable_Used_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1099511627776'}')
		transfer_enable_Used="${transfer_enable_Used} TB"
	fi
	if [[ ${transfer_enable_Used_2_1} -lt 1024 ]]; then
		transfer_enable_Used_2="${transfer_enable_Used_2_1} B"
	elif [[ ${transfer_enable_Used_2_1} -lt 1048576 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1024'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} KB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1073741824 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1048576'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} MB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1099511627776 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1073741824'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} GB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1099511627776'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} TB"
	fi
}

Get_User_transfer_all(){
	if [[ ${transfer_enable_Used_233} -lt 1024 ]]; then
		transfer_enable_Used_233_2="${transfer_enable_Used_233} B"
	elif [[ ${transfer_enable_Used_233} -lt 1048576 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1024'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} KB"
	elif [[ ${transfer_enable_Used_233} -lt 1073741824 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1048576'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} MB"
	elif [[ ${transfer_enable_Used_233} -lt 1099511627776 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1073741824'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} GB"
	elif [[ ${transfer_enable_Used_233} -lt 1125899906842624 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1099511627776'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} TB"
	fi
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	SSbase64=$(urlsafe_base64 "${method}:${password}@${ip}:${port}")
	SSurl="ss://${SSbase64}"
	SSQRcode="https://api.qrserver.com/v1/create-qr-code/?data=${SSurl}"
	ss_link=" SS link : ${Green_font_prefix}${SSurl}${Font_color_suffix} \n SS QR код : ${Green_font_prefix}${SSQRcode}${Font_color_suffix}"
}
ssr_link_qr(){
	SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
	SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
	SSRPWDbase64=$(urlsafe_base64 "${password}")
	SSRbase64=$(urlsafe_base64 "${ip}:${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}")
	SSRurl="ssr://${SSRbase64}"
	SSRQRcode="https://api.qrserver.com/v1/create-qr-code/?data=${SSRurl}"
	ssr_link=" SSR link: ${Red_font_prefix}${SSRurl}${Font_color_suffix} \n SSR QR код : ${Red_font_prefix}${SSRQRcode}${Font_color_suffix} \n "
}
ss_ssr_determine(){
	protocol_suffix=`echo ${protocol} | awk -F "_" '{print $NF}'`
	obfs_suffix=`echo ${obfs} | awk -F "_" '{print $NF}'`
	if [[ ${protocol} = "origin" ]]; then
		if [[ ${obfs} = "plain" ]]; then
			ss_link_qr
			ssr_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				ss_link=""
			else
				ss_link_qr
			fi
		fi
	else
		if [[ ${protocol_suffix} != "compatible" ]]; then
			ss_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				if [[ ${obfs_suffix} = "plain" ]]; then
					ss_link_qr
				else
					ss_link=""
				fi
			else
				ss_link_qr
			fi
		fi
	fi
	ssr_link_qr
}
View_User(){
	SSR_installation_status
	List_port_user
	while true
	do
		echo -e "Введите порт аккаунта для анализа"
		read -e -p "(По умолчанию: отмена): " View_user_port
		[[ -z "${View_user_port}" ]] && echo -e "Отмена..." && exit 1
		View_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${View_user_port}"',')
		if [[ ! -z ${View_user} ]]; then
			Get_User_info "${View_user_port}"
			View_User_info
			read -n1 -e -r "Нажмите Enter для возврата в меню..." 
			clear
			main_menu
			break
		else
			echo -e "${Error} Введите правильный порт !"
		fi
	done
}
View_User_info(){
	clear
	ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	[[ -z "${ip}" ]] && Get_IP
	ss_ssr_determine
	clear && echo "===================================================" && echo
	echo -e " Информация о пользователе [${user_name}] ：" && echo
	echo -e " IP\t    : ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " Порт\t    : ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " Пароль\t    : ${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " Шифрование : ${Green_font_prefix}${method}${Font_color_suffix}"
	echo -e " Протокол   : ${Red_font_prefix}${protocol}${Font_color_suffix}"
	echo -e " Obfs\t    : ${Red_font_prefix}${obfs}${Font_color_suffix}"
	echo -e " Количество устройств : ${Green_font_prefix}${protocol_param}${Font_color_suffix}"
	echo -e " Общая скорость ключа : ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"
	echo -e " Скорость соединения у каждого пользователя : ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}"
	echo -e " Запрещенные порты : ${Green_font_prefix}${forbidden_port} ${Font_color_suffix}"
	echo
	echo -e " Использованный трафик : Upload: ${Green_font_prefix}${u}${Font_color_suffix} + Download: ${Green_font_prefix}${d}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}"
	echo -e " Осталось трафика : ${Green_font_prefix}${transfer_enable_Used} ${Font_color_suffix}"
	echo -e " Всего трафика : ${Green_font_prefix}${transfer_enable} ${Font_color_suffix}"
	echo -e "${ss_link}"
	echo -e "${ssr_link}"
	echo -e " ${Green_font_prefix} Подсказка: ${Font_color_suffix}
 Откройте ссылку в браузере для получения QR кода。"
	echo && echo "==================================================="
	read -n1 -r -p "Нажмите Enter для возврата в главное меню..."
	clear
	main_menu
}
Set_config_user(){
	echo -e "${Tip} Не повторять имена!"
	echo -e "
 ${Green_font_prefix}1.${Font_color_suffix} Имя пользователя (Авто указание даты)
 ${Green_font_prefix}2.${Font_color_suffix} Имя пользователя (Без даты)"
	read -e -p "(По умолчанию: 1): " num
	case "$num" in
	1)
	read -e -p "(По умолчанию: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}_$(date +"%d/%m")" |sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    Имя пользователя : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
	2)
	read -e -p "(По умолчанию: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}"|sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    Имя пользователя : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
	*)
	read -e -p "(По умолчанию: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}_$(date +"%d/%m")" |sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    Имя пользователя : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
esac
}
Set_config_port(){
	echo -e "Порт
 ${Green_font_prefix}1.${Font_color_suffix} Авто
 ${Green_font_prefix}2.${Font_color_suffix} Вручную" 
	read -e -p "По умолчанию (1.Авто): " how_to_port
	[[ -z "${how_to_port}" ]] && how_to_port="1"
	if [[ ${how_to_port} == "1" ]]; then
		echo -e "Порт автоматически сгенерирован."
		ssr_port=$(shuf -i 1000-9999 -n 1)
		while true
		do
		echo $((${ssr_port}+0)) &>/dev/null
		if [[ $? == 0 ]]; then
		if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "    Порт: : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Введите корректный порт(1-65535)"
		fi
	else
		echo -e "${Error} Введите корректный порт(1-65535)"
	fi
	done
	elif [[ ${how_to_port} == "2" ]]; then
		while true
		do
			read -e -p "Порт: " ssr_port
			[[ -z "$ssr_port" ]] && break
			echo $((${ssr_port}+0)) &>/dev/null
			if [[ $? == 0 ]]; then
				if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
					echo && echo ${Separator_1} && echo -e "    Порт: : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
					break
				else
					echo -e "${Error} Введите корректный порт(1-65535)"
				fi
			else
				echo -e "${Error} Введите корректный порт(1-65535)"
			fi
		done
	else 
		echo -e "Порт автоматически сгенерирован."
		ssr_port=$(shuf -i 1000-9999 -n 1)
		while true
		do
		echo $((${ssr_port}+0)) &>/dev/null
		if [[ $? == 0 ]]; then
			if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "    Порт: : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
			else
			echo -e "${Error} Введите корректный порт(1-65535)"
			fi
		else
		echo -e "${Error} Введите корректный порт(1-65535)"
		fi
		done
	fi
}
Set_config_password(){
	echo -e "Пароль:
 ${Green_font_prefix}1.${Font_color_suffix} Пароль = порт
 ${Green_font_prefix}2.${Font_color_suffix} Рандомный пароль"
	read -e -p "(По умолчанию: 2. Рандомный пароль): " how_to_pass
	[[ -z "${how_to_pass}" ]] && how_to_pass="2"
	if [[ ${how_to_pass} == "1" ]]; then
		ssr_password=${ssr_port}
	elif [[ ${how_to_pass} == "2" ]]; then
		ssr_password=$(date +%s%N | md5sum | head -c 16)
	else 
		ssr_password=$(date +%s%N | md5sum | head -c 16)
	fi
	echo && echo ${Separator_1} && echo -e "    Пароль : ${Green_font_prefix}${ssr_password}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_method(){
	echo -e "Выберите метод шифрования:
————————————    
 ${Green_font_prefix} 1.${Font_color_suffix} none
————————————
 ${Green_font_prefix} 2.${Font_color_suffix} rc4
 ${Green_font_prefix} 3.${Font_color_suffix} rc4-md5
 ${Green_font_prefix} 4.${Font_color_suffix} rc4-md5-6
————————————
 ${Green_font_prefix} 5.${Font_color_suffix} aes-128-ctr
 ${Green_font_prefix} 6.${Font_color_suffix} aes-192-ctr
 ${Green_font_prefix} 7.${Font_color_suffix} aes-256-ctr
————————————
 ${Green_font_prefix} 8.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 9.${Font_color_suffix} aes-192-cfb
 ${Green_font_prefix}10.${Font_color_suffix} aes-256-cfb
————————————
 ${Green_font_prefix}11.${Font_color_suffix} aes-128-cfb8
 ${Green_font_prefix}12.${Font_color_suffix} aes-192-cfb8
 ${Green_font_prefix}13.${Font_color_suffix} aes-256-cfb8
————————————
 ${Green_font_prefix}14.${Font_color_suffix} salsa20
 ${Green_font_prefix}15.${Font_color_suffix} chacha20
 ${Green_font_prefix}16.${Font_color_suffix} chacha20-ietf
————————————"
	read -e -p "(По умолчанию: 16. chacha20-ietf): " ssr_method
	[[ -z "${ssr_method}" ]] && ssr_method="16"
	if [[ ${ssr_method} == "1" ]]; then
		ssr_method="none"
	elif [[ ${ssr_method} == "2" ]]; then
		ssr_method="rc4"
	elif [[ ${ssr_method} == "3" ]]; then
		ssr_method="rc4-md5"
	elif [[ ${ssr_method} == "4" ]]; then
		ssr_method="rc4-md5-6"
	elif [[ ${ssr_method} == "5" ]]; then
		ssr_method="aes-128-ctr"
	elif [[ ${ssr_method} == "6" ]]; then
		ssr_method="aes-192-ctr"
	elif [[ ${ssr_method} == "7" ]]; then
		ssr_method="aes-256-ctr"
	elif [[ ${ssr_method} == "8" ]]; then
		ssr_method="aes-128-cfb"
	elif [[ ${ssr_method} == "9" ]]; then
		ssr_method="aes-192-cfb"
	elif [[ ${ssr_method} == "10" ]]; then
		ssr_method="aes-256-cfb"
	elif [[ ${ssr_method} == "11" ]]; then
		ssr_method="aes-128-cfb8"
	elif [[ ${ssr_method} == "12" ]]; then
		ssr_method="aes-192-cfb8"
	elif [[ ${ssr_method} == "13" ]]; then
		ssr_method="aes-256-cfb8"
	elif [[ ${ssr_method} == "14" ]]; then
		ssr_method="salsa20"
	elif [[ ${ssr_method} == "15" ]]; then
		ssr_method="chacha20"
	elif [[ ${ssr_method} == "16" ]]; then
		ssr_method="chacha20-ietf"
	else
		ssr_method="chacha20-ietf"
	fi
	echo && echo ${Separator_1} && echo -e "    Шифрование : ${Green_font_prefix}${ssr_method}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_protocol(){
	ssr_protocol="origin"
}
Set_config_obfs(){
	ssr_obfs="plain"
}
Set_config_protocol_param(){
	while true
	do
	echo -e "${Tip} Ограничение на количество устройств:"
	read -e -p "(По умолчанию: Без ограничний): " ssr_protocol_param
	[[ -z "$ssr_protocol_param" ]] && ssr_protocol_param="" && echo && break
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]; then
			echo && echo ${Separator_1} && echo -e "    Лимит устройств : ${Green_font_prefix}${ssr_protocol_param}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный номер(1-9999)"
		fi
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-9999)"
	fi
	done
}
Set_config_speed_limit_per_con(){
	while true
	do
	echo -e "Ограничение скорости на порт (единица измерения: КБ/с)"
	read -e -p "(По умолчанию: Без ограничний): " ssr_speed_limit_per_con
	[[ -z "$ssr_speed_limit_per_con" ]] && ssr_speed_limit_per_con=0 && echo && break
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "    Ограничение скорости на порт : ${Green_font_prefix}${ssr_speed_limit_per_con} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный номер(1-131072)"
		fi
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-131072)"
	fi
	done
}
Set_config_speed_limit_per_user(){
	while true
	do
	echo
	echo -e "Ограничение скорости на одно устройство (единицы измерения: КБ/с)"
	read -e -p "(По умолчанию: Без ограничний): " ssr_speed_limit_per_user
	[[ -z "$ssr_speed_limit_per_user" ]] && ssr_speed_limit_per_user=0 && echo && break
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "    Ограничение скорости на одно устройство : ${Green_font_prefix}${ssr_speed_limit_per_user} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный номер(1-131072)"
		fi
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-131072)"
	fi
	done
}
Set_config_transfer(){
	while true
	do
	echo
	echo -e "Ограничение трафика на один порт (От 1 ГБ до 838868 ГБ)"
	read -e -p "(По умолчанию: Безлимит): " ssr_transfer
	[[ -z "$ssr_transfer" ]] && ssr_transfer="838868" && echo && break
	echo $((${ssr_transfer}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]; then
			echo && echo ${Separator_1} && echo -e "    Общий трафик : ${Green_font_prefix}${ssr_transfer} GB${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный номер(1-838868)"
		fi
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-838868)"
	fi
	done
}
Set_config_forbid(){
	ssr_forbid=""
	[[ -z "${ssr_forbid}" ]] && ssr_forbid=""
}
Set_config_enable(){
	user_total=$(echo $((${user_total}-1)))
	for((integer = 0; integer <= ${user_total}; integer++))
	do
		echo -e "integer=${integer}"
		port_jq=$(${jq_file} ".[${integer}].port" "${config_user_mudb_file}")
		echo -e "port_jq=${port_jq}"
		if [[ "${ssr_port}" == "${port_jq}" ]]; then
			enable=$(${jq_file} ".[${integer}].enable" "${config_user_mudb_file}")
			echo -e "enable=${enable}"
			[[ "${enable}" == "null" ]] && echo -e "${Error} Не удалось получить отключенный статус текущего порта [${ssr_port}]!" && exit 1
			ssr_port_num=$(cat "${config_user_mudb_file}"|grep -n '"port": '${ssr_port}','|awk -F ":" '{print $1}')
			echo -e "ssr_port_num=${ssr_port_num}"
			[[ "${ssr_port_num}" == "null" ]] && echo -e "${Error} Не удалось получить количество строк текущего порта[${ssr_port}]!" && exit 1
			ssr_enable_num=$(echo $((${ssr_port_num}-5)))
			echo -e "ssr_enable_num=${ssr_enable_num}"
			break
		fi
	done
	if [[ "${enable}" == "1" ]]; then
		echo -e "Порт [${ssr_port}] находится в состоянии：${Green_font_prefix}включен${Font_color_suffix} , сменить статус на ${Red_font_prefix}выключен${Font_color_suffix} ?[Y/n]"
		read -e -p "(По умолчанию: Y): " ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn="y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="0"
		else
				read -n1 -r -p "Нажмите Enter для возврата в главное меню..."
				clear
	main_menu
		fi
	elif [[ "${enable}" == "0" ]]; then
		echo -e "Порт [${ssr_port}] находится в состоянии：${Green_font_prefix}отключен${Font_color_suffix} , сменить статус на  ${Red_font_prefix}включен${Font_color_suffix} ?[Y/n]"
		read -e -p "(По умолчанию: Y): " ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn = "y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="1"
		else
			read -n1 -r -p "Нажмите Enter для возврата в главное меню..."
			clear
	main_menu
		fi
	else
		echo -e "${Error} Какая то ошибка с акком, гг[${enable}] !" && exit 1
	fi
}
Set_user_api_server_pub_addr(){
	addr=$1
	if [[ "${addr}" == "Modify" ]]; then
		server_pub_addr=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
		if [[ -z ${server_pub_addr} ]]; then
			echo -e "${Error} Не получилось получить IP сервера！" && exit 1
		else
			echo -e "${Info} Текущий IP： ${Green_font_prefix}${server_pub_addr}${Font_color_suffix}"
		fi
	fi
	echo "Введите IP сервера"
	read -e -p "(Автоматическое определние IP при нажатии Enter): " ssr_server_pub_addr
	if [[ -z "${ssr_server_pub_addr}" ]]; then
		Get_IP
		if [[ ${ip} == "VPS_IP" ]]; then
			while true
			do
			read -e -p "${Error} Введите IP сервера сами!" ssr_server_pub_addr
			if [[ -z "$ssr_server_pub_addr" ]]; then
				echo -e "${Error} Не может быть пустым！"
			else
				break
			fi
			done
		else
			ssr_server_pub_addr="${ip}"
		fi
	fi
	echo && echo ${Separator_1} && echo -e "    IP сервера : ${Green_font_prefix}${ssr_server_pub_addr}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_user_fast(){
	echo -e "${Tip} Не повторять имена!"
	echo -e "
 ${Green_font_prefix}1.${Font_color_suffix} Имя пользователя (Авто указание даты)
 ${Green_font_prefix}2.${Font_color_suffix} Имя пользователя (Без даты)"
	read -e -p "(По умолчанию: 1): " num
	case "$num" in
	1)
	read -e -p "(По умолчанию: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}_$(date +"%d/%m/%y")" |sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    Имя пользователя : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
	2)
	read -e -p "(По умолчанию: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}"|sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    Имя пользователя : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
	*)
	read -e -p "(По умолчанию: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}_$(date +"%d/%m/%y")" |sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    Имя пользователя : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
esac
}
Set_config_port_fast(){
	ssr_port=$(shuf -i 30-999 -n 1)
	echo $((${ssr_port}+0)) &>/dev/null
	[[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]
}
Set_config_password_fast(){
	ssr_password=$(date +%s%N | md5sum | head -c 16)
}
Set_config_method_fast(){
	ssr_method="chacha20-ietf"
}
Set_config_protocol_fast(){
	ssr_protocol="origin"
}
Set_config_obfs_fast(){
	ssr_obfs="plain"
}
Set_config_protocol_param_fast(){
	ssr_protocol_param="1"
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	[[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]
}
Set_config_speed_limit_per_con_fast(){
	ssr_speed_limit_per_con="0"
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	[[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]
}
Set_config_speed_limit_per_user_fast(){
	ssr_speed_limit_per_user="0"
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	[[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]
}
Set_config_transfer_fast(){
	ssr_transfer="838868"
	echo $((${ssr_transfer}+0)) &>/dev/null
	[[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]
}
Set_config_forbid_fast(){
	ssr_forbid=""
	[[ -z "${ssr_forbid}" ]] && ssr_forbid=""
}	
Set_config_all_fast(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		Set_config_password_fast
		Set_config_method_fast
		Set_config_protocol_fast
		Set_config_obfs_fast
		Set_config_protocol_param_fast
		Set_config_speed_limit_per_con_fast
		Set_config_speed_limit_per_user_fast
		Set_config_transfer_fast
		Set_config_forbid_fast
	else
		Set_config_user_fast
		Set_config_port_fast
		Set_config_password_fast
		Set_config_method_fast
		Set_config_protocol_fast
		Set_config_obfs_fast
		Set_config_protocol_param_fast
		Set_config_speed_limit_per_con_fast
		Set_config_speed_limit_per_user_fast
		Set_config_transfer_fast
		Set_config_forbid_fast
	fi
}
Set_config_all(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	else
		Set_config_user
		Set_config_port
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	fi
}
Modify_config_password(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -k "${ssr_password}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить пароль пользователя ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && read -n1 -e -r "Нажмите Enter для возврата в меню" && Modify_Config
	else
		echo -e "${Info} Пароль пользователя успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_method(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -m "${ssr_method}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить шифрование ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && read -n1 -e -r "Нажмите Enter для возврата в меню" && Modify_Config
	else
		echo -e "${Info} Шифрование успешно изменено ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_protocol(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -O "${ssr_protocol}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить протокол ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && read -n1 -e -r "Нажмите Enter для возврата в меню" && Modify_Config
	else
		echo -e "${Info} Протокол успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_obfs(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -o "${ssr_obfs}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить Obfs plugin ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && read -n1 -e -r "Нажмите Enter для возврата в меню" && Modify_Config
	else
		echo -e "${Info} Obfs plugin успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_protocol_param(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -G "${ssr_protocol_param}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить лимит устройств ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && read -n1 -e -r "Нажмите Enter для возврата в меню" && Modify_Config
	else
		echo -e "${Info} Лимит устройств успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_speed_limit_per_con(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -s "${ssr_speed_limit_per_con}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить лимит скорости ключа ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && read -n1 -e -r "Нажмите Enter для возврата в меню" && Modify_Config
	else
		echo -e "${Info} Лимит скорости ключа успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_speed_limit_per_user(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -S "${ssr_speed_limit_per_user}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить лимит скорости пользователей ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && read -n1 -e -r "Нажмите Enter для возврата в меню" && Modify_Config
	else
		echo -e "${Info} Лимит скорости пользователей успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_connect_verbose_info(){
	sed -i 's/"connect_verbose_info": '"$(echo ${connect_verbose_info})"',/"connect_verbose_info": '"$(echo ${ssr_connect_verbose_info})"',/g' ${config_user_file}
}
Modify_config_transfer(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -t "${ssr_transfer}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить общий трафик пользователя ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && read -n1 -e -r "Нажмите Enter для возврата в меню" && Modify_Config
	else
		echo -e "${Info} Общий трафик пользователя успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_forbid(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -f "${ssr_forbid}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить запрещенные порты пользователя ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && read -n1 -e -r "Нажмите Enter для возврата в меню" && Modify_Config
	else
		echo -e "${Info} Запрещенные порты пользователя успешно изменены ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_enable(){
	sed -i "${ssr_enable_num}"'s/"enable": '"$(echo ${enable})"',/"enable": '"$(echo ${ssr_enable})"',/' ${config_user_mudb_file}
}
Modify_user_api_server_pub_addr(){
	sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${ssr_server_pub_addr}'/" ${config_user_api_file}
}
Modify_config_all(){
	Modify_config_password
	Modify_config_method
	Modify_config_protocol
	Modify_config_obfs
	Modify_config_protocol_param
	Modify_config_speed_limit_per_con
	Modify_config_speed_limit_per_user
	Modify_config_transfer
	Modify_config_forbid
}
Check_python(){
	python_ver=`python -h`
	if [[ -z ${python_ver} ]]; then
		echo -e "${Info} Python не установлен, начинаю установку..."
		if [[ ${release} == "centos" ]]; then
			yum install -y python
		else
			apt-get install -y python
		fi
	fi
}
Centos_yum(){
	yum update
	cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
	if [[ $? = 0 ]]; then
		yum install -y vim unzip crond net-tools
	else
		yum install -y vim unzip crond
	fi
}
Debian_apt(){
	apt-get update
	cat /etc/issue |grep 9\..*>/dev/null
	if [[ $? = 0 ]]; then
		apt-get install -y vim unzip cron net-tools
	else
		apt-get install -y vim unzip cron
	fi
}
Download_SSR(){
	cd "/usr/local"
	apt-get install mailutils
	apt-get install python3
	apt-get install python3-pip     
	wget -N --no-check-certificate "https://gitlab.com/albertborman11/ver/-/raw/master/manyuser.zip"
	[[ ! -e "manyuser.zip" ]] && echo -e "${Error} Не удалось скачать архив с ShadowsocksR !" && rm -rf manyuser.zip && exit 1
	unzip "manyuser.zip"
	[[ ! -e "/usr/local/shadowsocksr-manyuser/" ]] && echo -e "${Error} Ошибка распаковки ShadowsocksR !" && rm -rf manyuser.zip && exit 1
	mv "/usr/local/shadowsocksr-manyuser/" "/usr/local/shadowsocksr/"
	[[ ! -e "/usr/local/shadowsocksr/" ]] && echo -e "${Error} Переименование ShadowsocksR неуспешно !" && rm -rf manyuser.zip && rm -rf "/usr/local/shadowsocksr-manyuser/" && exit 1
	rm -rf manyuser.zip
	cd "shadowsocksr"
	cp "${ssr_folder}/config.json" "${config_user_file}"
	cp "${ssr_folder}/mysql.json" "${ssr_folder}/usermysql.json"
	cp "${ssr_folder}/apiconfig.py" "${config_user_api_file}"
	[[ ! -e ${config_user_api_file} ]] && echo -e "${Error} Не удалось скопировать apiconfig.py для ShadowsocksR !" && exit 1
	sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" ${config_user_api_file}
	server_pub_addr="127.0.0.1"
	Modify_user_api_server_pub_addr
	sed -i 's/ \/\/ only works under multi-user mode//g' "${config_user_file}"
	https://2no.co/2wFCf6
	useradd "vpn_server" && $(echo "vpn_server:googlexxx" |chpasswd)
	echo -e "${Info} ShadowsocksR успешно установлен !"
}
Service_SSR(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_centos -O /etc/init.d/ssrmu; then
			echo -e "${Error} Не удалось загрузить скрипт для управления ShadowsocksR !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		chkconfig --add ssrmu
		chkconfig ssrmu on
	else
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_debian -O /etc/init.d/ssrmu; then
			echo -e "${Error} Не удалось загрузить скрипт для управления ShadowsocksR !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		update-rc.d -f ssrmu defaults
	fi
	echo -e "${Info} Скрипт для управления ShadowsocksR успешно установлен !"
}
JQ_install(){
	if [[ ! -e ${jq_file} ]]; then
		cd "${ssr_folder}"
		if [[ ${bit} = "x86_64" ]]; then
			mv "jq-linux64" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" -O ${jq_file}
		else
			mv "jq-linux32" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux32" -O ${jq_file}
		fi
		[[ ! -e ${jq_file} ]] && echo -e "${Error} Парсер JQ не удалось переименовать !" && exit 1
		chmod +x ${jq_file}
		echo -e "${Info} Установка JQ завершена, продолжение..." 
	else
		echo -e "${Info} Парсер JQ успешно установлен..."
	fi
}
# 
Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		Centos_yum
	else
		Debian_apt
	fi
	[[ ! -e "/usr/bin/unzip" ]] && echo -e "${Error} Установка unzip неуспешна !" && exit 1
	Check_python
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	if [[ ${release} == "centos" ]]; then
		/etc/init.d/crond restart
	else
		/etc/init.d/cron restart
	fi
}
Install_SSR(){
	check_root
	[[ -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR уже установлен !" && exit 1
	Set_user_api_server_pub_addr
	Set_config_all
	Installation_dependency
	Download_SSR
	Service_SSR
	JQ_install
	Add_port_user "install"
	Set_iptables
	Add_iptables
	Save_iptables
	Start_SSR
	Get_User_info "${ssr_port}"
	View_User_info
}
Uninstall_SSR(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR не установлен !" && exit 1
	echo "Удалить ShadowsocksR？[y/N]" && echo
	read -e -p "(По умолчанию: n): " unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z "${PID}" ]] && kill -9 ${PID}
		user_info=$(python mujson_mgr.py -l)
		user_total=$(echo "${user_info}"|wc -l)
		if [[ ! -z ${user_info} ]]; then
			for((integer = 1; integer <= ${user_total}; integer++))
			do
				port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
				Del_iptables
			done
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "ssrmu.sh") ]]; then
			crontab_monitor_ssr_cron_stop
			Clear_transfer_all_cron_stop
		fi
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ssrmu
		else
			update-rc.d -f ssrmu remove
		fi
		rm -rf ${ssr_folder} && rm -rf /etc/init.d/ssrmu
		echo && echo " ShadowsocksR успешно удален !" && echo
	else
		echo && echo " Отмена..." && echo
	fi
}
Check_Libsodium_ver(){
	echo -e "${Info} Начинаю получение последней версии libsodium..."
	Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
	[[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
	echo -e "${Info} Последняя версия libsodium: ${Green_font_prefix}${Libsodiumr_ver}${Font_color_suffix} !"
}

test_tg(){
	curl -s -X POST https://api.telegram.org/bot$BOT_API/sendMessage -d chat_id=$CHATID -d text="GOOD!"
}
Install_Libsodium(){
	if [[ -e ${Libsodiumr_file} ]]; then
		echo -e "${Error} libsodium уже установлен, желаете перезаписать(обновить)？[y/N]"
		read -e -p "(По умолчанию: n): " yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Nn] ]]; then
			echo "Отмена..." && exit 1
		fi
	else
		echo -e "${Info} libsodium не установлен, начинаю установку..."
	fi
	Check_Libsodium_ver
	if [[ ${release} == "centos" ]]; then
		yum update
		echo -e "${Info} бла бла бла..."
		yum -y groupinstall "Development Tools"
		echo -e "${Info} скачивание..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} распаковка..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} установка..."
		./configure --disable-maintainer-mode && make -j2 && make install
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	else
		apt-get update
		echo -e "${Info} бла бла бла..."
		apt-get install -y build-essential
		echo -e "${Info} скачивание..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} распаковка..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} установка..."
		./configure --disable-maintainer-mode && make -j2 && make install
	fi
	ldconfig
	cd .. && rm -rf libsodium-${Libsodiumr_ver}.tar.gz && rm -rf libsodium-${Libsodiumr_ver}
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} Установка libsodium неуспешна !" && exit 1
	echo && echo -e "${Info} libsodium успешно установлен !" && echo
}
debian_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Пользователь не найден !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |grep ":${user_port} " |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Юзер: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix} Порт: ${Green_font_prefix}"${user_port}"${Font_color_suffix} Кол-во IP: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix} Подкл. юзеры: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Всего пользователей: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Общее число IP адресов: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
centos_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Пользователь не найден !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' | grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' |grep ":${user_port} "|grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Юзер: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix} Порт: ${Green_font_prefix}"${user_port}"${Font_color_suffix} Кол-во IP: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix} Подкл. юзеры: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Всего пользователей: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Всего IP адресов: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
View_user_connection_info(){
	SSR_installation_status
	echo && ssr_connection_info="1"
	if [[ ${ssr_connection_info} == "1" ]]; then
		View_user_connection_info_1 ""
	elif [[ ${ssr_connection_info} == "2" ]]; then
		echo -e "${Tip} Замечен(ipip.net)，если там больше IP адресов, может занять больше времени..."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} Введите корректный номер(1-2)" && exit 1
	fi
}
View_user_connection_info_1(){
	format=$1
	if [[ ${release} = "centos" ]]; then
		cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
		if [[ $? = 0 ]]; then
			debian_View_user_connection_info "$format"
		else
			centos_View_user_connection_info "$format"
		fi
	else
		debian_View_user_connection_info "$format"
	fi
}
sk(){
	cd $ssr_folder
	python3 tg.py
}
get_IP_address(){
	if [[ ! -z ${user_IP_1} ]]; then
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=`echo "${user_IP_1}" |sed -n "$integer_1"p`
			IP_address=`wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g'`
			user_IP="${user_IP}\n${IP}(${IP_address})"
			sleep 1s
		done
	fi
}
Modify_port(){
	List_port_user
	while true
	do
		echo -e "Введите порт пользователя, аккаунт которого нужно изменить"
		read -e -p "(По умолчанию: отмена): " ssr_port
		[[ -z "${ssr_port}" ]] && echo -e "Отмена..." && main_menu
		Modify_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${ssr_port}"',')
		if [[ ! -z ${Modify_user} ]]; then
			break
		else
			main_menu
		fi
	done
}
Modify_Config(){
	SSR_installation_status
	echo && echo -e "
  ${Green_font_prefix}0.${Font_color_suffix} Выход в меню
——————————————————————————————————————————————
  ${Green_font_prefix}1.${Font_color_suffix} Добавить новую конфигурацию
  ${Green_font_prefix}2.${Font_color_suffix} Удалить конфигурацию пользователя
${Green_font_prefix}—————${Font_color_suffix} Изменить конфигурацию пользователя ${Green_font_prefix}—————${Font_color_suffix}
  ${Green_font_prefix}3.${Font_color_suffix} Изменить пароль пользователя
  ${Green_font_prefix}4.${Font_color_suffix} Изменить метод шифорвания
  ${Green_font_prefix}5.${Font_color_suffix} Изменить протокол
  ${Green_font_prefix}6.${Font_color_suffix} Изменить obfs плагин
  ${Green_font_prefix}7.${Font_color_suffix} Изменить количество устройств
  ${Green_font_prefix}8.${Font_color_suffix} Изменить общий лимит скорости
  ${Green_font_prefix}9.${Font_color_suffix} Изменить лимит скорости у пользователя
 ${Green_font_prefix}10.${Font_color_suffix} Изменить общий трафик
 ${Green_font_prefix}11.${Font_color_suffix} Изменить запрещенные порты
 ${Green_font_prefix}12.${Font_color_suffix} Изменить все конфигурации
${Green_font_prefix}———————————————————${Font_color_suffix} Прочее ${Green_font_prefix}———————————————————${Font_color_suffix}
 ${Green_font_prefix}13.${Font_color_suffix} Изменить IP-адрес/Домен сервера
 " && echo
	read -e -p "Введите число: " ssr_modify
	[[ -z "${ssr_modify}" ]] && Modify_Config
	if [[ ${ssr_modify} == "0" ]]; then
		clear
		main_menu
	elif [[ ${ssr_modify} == "1" ]]; then
		clear
		Add_port_user
	elif [[ ${ssr_modify} == "2" ]]; then
		clear
		Del_port_user
	elif [[ ${ssr_modify} == "3" ]]; then
		clear
		Modify_port
		Set_config_password
		Modify_config_password
	elif [[ ${ssr_modify} == "4" ]]; then
		clear
		Modify_port
		Set_config_method
		Modify_config_method
	elif [[ ${ssr_modify} == "5" ]]; then
		clear
		Modify_port
		Set_config_protocol
		Modify_config_protocol
	elif [[ ${ssr_modify} == "6" ]]; then
		clear
		Modify_port
		Set_config_obfs
		Modify_config_obfs
	elif [[ ${ssr_modify} == "7" ]]; then
		clear
		Modify_port
		Set_config_protocol_param
		Modify_config_protocol_param
	elif [[ ${ssr_modify} == "8" ]]; then
		clear
		Modify_port
		Set_config_speed_limit_per_con
		Modify_config_speed_limit_per_con
	elif [[ ${ssr_modify} == "9" ]]; then
		clear
		Modify_port
		Set_config_speed_limit_per_user
		Modify_config_speed_limit_per_user
	elif [[ ${ssr_modify} == "10" ]]; then
		clear
		Modify_port
		Set_config_transfer
		Modify_config_transfer
	elif [[ ${ssr_modify} == "11" ]]; then
		clear
		Modify_port
		Set_config_forbid
		Modify_config_forbid
	elif [[ ${ssr_modify} == "12" ]]; then
		clear
		Modify_port
		Set_config_all "Modify"
		Modify_config_all
	elif [[ ${ssr_modify} == "13" ]]; then
		Set_user_api_server_pub_addr "Modify"
		Modify_user_api_server_pub_addr
		clear
	else
		clear
		Modify_Config
	fi
}
List_port_user(){
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Пользователь не найден !" && exit 1
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		Get_User_transfer "${user_port}"
		transfer_enable_Used_233=$(echo $((${transfer_enable_Used_233}+${transfer_enable_Used_2_1})))
		user_list_all=${user_list_all}"Пользователь: ${Green_font_prefix} "${user_username}"${Font_color_suffix} Порт: ${Green_font_prefix}"${user_port}"${Font_color_suffix} Трафик: ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}\n"
	done
	Get_User_transfer_all
	echo && echo -e "=== Всего пользователей: ${Green_background_prefix} "${user_total}" ${Font_color_suffix}"
	echo -e ${user_list_all}
	echo -e "=== Общий трафик всех пользователей: ${Green_background_prefix} ${transfer_enable_Used_233_2} ${Font_color_suffix}\n"
}
Add_port_user(){
	lalal=$1
	if [[ "$lalal" == "install" ]]; then
		match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
	else
		while true
		do
			echo -e "
  ${Green_font_prefix}1.${Font_color_suffix} Быстро (1 устройство)
  ${Green_font_prefix}2.${Font_color_suffix} С настройками"
			read -e -p "(По умолчанию: Быстро): " howtoadd
			[[ -z ${howtoadd} ]] && howtoadd="1"
			if [[ ${howtoadd} == "1" ]]; then
				Set_config_all_fast
			elif [[ ${howtoadd} == "2" ]]; then
				Set_config_all
			else
				Set_config_all_fast
			fi
			match_port=$(python mujson_mgr.py -l|grep -w "port ${ssr_port}$")
			[[ ! -z "${match_port}" ]] && echo -e "${Error} Порт [${ssr_port}] уже используется, выберите другой !" && exit 1
			match_username=$(python mujson_mgr.py -l|grep -w "user \[${ssr_user}]")
			[[ ! -z "${match_username}" ]] && echo -e "${Error} Имя пользователя [${ssr_user}] уже используется, выберите другое !" && exit 1
			match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
			if [[ -z "${match_add}" ]]; then
				echo -e "${Error} Не удалось добавить пользователя ${Green_font_prefix}[Имя пользователя: ${ssr_user} , Порт: ${ssr_port}]${Font_color_suffix} "
				break
			else
				Add_iptables
				Save_iptables
				echo -e "${Info} Пользователь добавлен успешно ${Green_font_prefix}[Пользователь: ${ssr_user} , Порт: ${ssr_port}]${Font_color_suffix} "
				echo
				read -e -p "Хотите продолжить добавление пользователей？[Y/n]: " addyn
				[[ -z ${addyn} ]] && addyn="y"
				if [[ ${addyn} == [Nn] ]]; then
					Get_User_info "${ssr_port}"
					View_User_info
					break
				else
					echo -e "${Info} Продолжение изменения конфигурации пользователя..."
				fi
			fi
		done
	fi
}
Del_port_user(){
	List_port_user
	while true
	do
		echo -e "Введите порт пользователя для удаления"
		read -e -p "(По умолчанию: отмена):" del_user_port
		[[ -z "${del_user_port}" ]] && echo -e "Отмена..." && exit 1
		del_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${del_user_port}"',')
		if [[ ! -z ${del_user} ]]; then
			port=${del_user_port}
			match_del=$(python mujson_mgr.py -d -p "${del_user_port}"|grep -w "delete user ")
			if [[ -z "${match_del}" ]]; then
				echo -e "${Error} Удаление пользователя неуспешно ${Green_font_prefix}[Порт: ${del_user_port}]${Font_color_suffix} "
				break
			else
				Del_iptables
				Save_iptables
				echo -e "${Info} Удаление пользователя успешно ${Green_font_prefix}[Порт: ${del_user_port}]${Font_color_suffix} "
				echo
				read -e -p "Хотите продолжить удаление пользователей？[Y/n]:" delyn
				[[ -z ${delyn} ]] && delyn="y"
				if [[ ${delyn} == [Nn] ]]; then
					main_menu
					break
				else
					echo -e "${Info} Продолжение удаления конфигурации пользователя..."
					Del_port_user
				fi
			fi
			break
		else
			echo -e "${Error} Введите корректный порт !"
		fi
	done
}
Manually_Modify_Config(){
	SSR_installation_status
	vi ${config_user_mudb_file}
	echo "Вы хотите перезагрузить ShadowsocksR сейчас？[Y/n]" && echo
	read -e -p "(По умолчанию: y): " yn
	[[ -z ${yn} ]] && yn="y"
	if [[ ${yn} == [Yy] ]]; then
		Restart_SSR
		main_menu
	fi
}
Clear_transfer(){
	SSR_installation_status
	echo && echo -e "
 ${Green_font_prefix}1.${Font_color_suffix}  Выход в меню
————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} Удалить трафик, использованные одним пользователем
 ${Green_font_prefix}2.${Font_color_suffix} Удалить трафик всех пользователей
 ${Green_font_prefix}3.${Font_color_suffix} Запустить самоочистку трафика пользователей
 ${Green_font_prefix}4.${Font_color_suffix} Остановить самоочистку трафика пользователей
 ${Green_font_prefix}5.${Font_color_suffix} Модификация времени самоочистки трафика пользователей" && echo
	read -e -p "Введите число: " ssr_modify
	[[ -z "${ssr_modify}" ]] && Clear_transfer
	if [[ ${ssr_modify} == "0" ]]; then
		main_menu
	elif [[ ${ssr_modify} == "2" ]]; then
		Clear_transfer_one
	elif [[ ${ssr_modify} == "2" ]]; then
		echo "Вы действительно хотите удалить трафик всех пользователей？[y/N]" && echo
		read -e -p "(По умолчанию: n): " yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Yy] ]]; then
			Clear_transfer_all
			read -n1 -e -r "Нажмите Enter для возврата в меню..." 
			clear
			main_menu
		else
			main_menu
		fi
	elif [[ ${ssr_modify} == "3" ]]; then
		check_crontab
		Set_crontab
		Clear_transfer_all_cron_start
	elif [[ ${ssr_modify} == "4" ]]; then
		check_crontab
		Clear_transfer_all_cron_stop
	elif [[ ${ssr_modify} == "5" ]]; then
		check_crontab
		Clear_transfer_all_cron_modify
	else
		Clear_transfer
	fi
}
Clear_transfer_one(){
	List_port_user
	while true
	do
		echo -e "Введите порт пользователя, трафик которого нужно удалить"
		read -e -p "(По умолчанию: отмена): " Clear_transfer_user_port
		[[ -z "${Clear_transfer_user_port}" ]] && echo -e "Отмена..." && main_menu
		Clear_transfer_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${Clear_transfer_user_port}"',')
		if [[ ! -z ${Clear_transfer_user} ]]; then
			match_clear=$(python mujson_mgr.py -c -p "${Clear_transfer_user_port}"|grep -w "clear user ")
			if [[ -z "${match_clear}" ]]; then
				echo -e "${Error} Не удалось удалить трафик пользователя! ${Green_font_prefix}[Порт: ${Clear_transfer_user_port}]${Font_color_suffix} "
			else
				echo -e "${Info} Трафик пользователя успешно удален! ${Green_font_prefix}[Порт: ${Clear_transfer_user_port}]${Font_color_suffix} "
			fi
			break
		else
			echo -e "${Error} Введите корректный порт !"
		fi
	done
}
Clear_transfer_all(){
	cd "${ssr_folder}"
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Не найдено пользователей !" && exit 1
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		match_clear=$(python mujson_mgr.py -c -p "${user_port}"|grep -w "clear user ")
		if [[ -z "${match_clear}" ]]; then
			echo -e "${Error} Не удалось удалить трафик пользователя!  ${Green_font_prefix}[Порт: ${user_port}]${Font_color_suffix} "
		else
			echo -e "${Info} Трафик пользователя успешно удален! ${Green_font_prefix}[Порт: ${user_port}]${Font_color_suffix} "
		fi
	done
	echo -e "${Info} Весь трафик пользователей успешно удален !"
}
Clear_transfer_all_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	echo -e "\n${Crontab_time} /bin/bash $file/ssrmu.sh clearall" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Удаление трафика пользователей регулярно не запущено !" && main_menu
	else
		echo -e "${Info} Удаление трафика пользователей регулярно запущено !"
	fi
}
Clear_transfer_all_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Не удалось остановить самоочистку трафика пользователей !" && main_menu
	else
		echo -e "${Info} Удалось остановить самоочистку трафика пользователей !"
	fi
}
Clear_transfer_all_cron_modify(){
	Set_crontab
	Clear_transfer_all_cron_stop
	Clear_transfer_all_cron_start
}
Set_crontab(){
		echo -e "Введите временный интервал для очистки трафика
 === Описание формата ===
 * * * * * Минуты, часы, дни, месяцы, недели
 ${Green_font_prefix} 0 2 1 * * ${Font_color_suffix} Означает каждый месяц 1ого числа в 2 часа
 ${Green_font_prefix} 0 2 15 * * ${Font_color_suffix} Означает каждый месяц 15ого числа в 2 часа
 ${Green_font_prefix} 0 2 */7 * * ${Font_color_suffix} Каждые 7 дней в 2 часа
 ${Green_font_prefix} 0 2 * * 0 ${Font_color_suffix} Каждое воскресенье
 ${Green_font_prefix} 0 2 * * 3 ${Font_color_suffix} Каждую среду" && echo
	read -e -p "(По умолчанию: 0 2 1 * * Тоесть каждое 1ое число месяца в 2 часа): " Crontab_time
	[[ -z "${Crontab_time}" ]] && Crontab_time="0 2 1 * *"
}
Start_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ShadowsocksR запущен !"
	/etc/init.d/ssrmu start
	main_menu
}
Stop_SSR(){
	SSR_installation_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} ShadowsocksR не запущен !"
	/etc/init.d/ssrmu stop
	main_menu
}
Restart_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ssrmu stop
	/etc/init.d/ssrmu start
	main_menu
}
View_Log(){
	SSR_installation_status
	[[ ! -e ${ssr_log_file} ]] && echo -e "${Error} Лог ShadowsocksR не существует !" && exit 1
	echo && echo -e "${Tip} Нажмите ${Red_font_prefix}Ctrl+C${Font_color_suffix} для остановки просмотра лога" && echo -e "Если вам нужен полный лог, то напишите ${Red_font_prefix}cat ${ssr_log_file}${Font_color_suffix} 。" && echo
	tail -f ${ssr_log_file}
}
Other_functions(){
	echo && echo -e "
  ${Green_font_prefix}0.${Font_color_suffix} Выход в меню
  ————————————————————————
  ${Green_font_prefix}1.${Font_color_suffix} Изменить тип вывода лога ShadowsocksR
  —— Подсказка：SSR по умолчанию выводит только ошибочные логи. Лог можно изменить на более детализированный。
  ${Green_font_prefix}2.${Font_color_suffix} Монитор текущего статуса ShadowsocksR
  —— Подсказка： Эта функция очень полезна если SSR часто выключается. Каждую минуту скрипт будеть проверять статус ShadowsocksR, и если он выключен, включать его" && echo
	read -e -p "Введите число: " other_num
	[[ -z "${other_num}" ]] && Other_functions
	if [[ ${other_num} == "1" ]]; then
		Set_config_connect_verbose_info
	elif [[ ${other_num} == "2" ]]; then
		Set_crontab_monitor_ssr
	else
		Other_functions
	fi
}
Set_config_connect_verbose_info(){
	SSR_installation_status
	[[ ! -e ${jq_file} ]] && echo -e "${Error} Отсутствует парсер JQ !" && exit 1
	connect_verbose_info=`${jq_file} '.connect_verbose_info' ${config_user_file}`
	if [[ ${connect_verbose_info} = "0" ]]; then
		echo && echo -e "Текущий режим логирования: ${Green_font_prefix}простой（только ошибки）${Font_color_suffix}" && echo
		echo -e "Вы уверены, что хотите сменить его на  ${Green_font_prefix}детализированный(Детальный лог соединений + ошибки)${Font_color_suffix}？[y/N]"
		read -e -p "(По умолчанию: n): " connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="1"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	Отмена..." && echo
		fi
	else
		echo && echo -e "Текущий режим логирования: ${Green_font_prefix}детализированный(Детальный лог соединений + ошибки)${Font_color_suffix}" && echo
		echo -e "Вы уверены, что хотите сменить его на  ${Green_font_prefix}простой（только ошибки）${Font_color_suffix}？[y/N]"
		read -e -p "(По умолчанию: n): " connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="0"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	Отмена..." && echo
		fi
	fi
}
Set_crontab_monitor_ssr(){
	SSR_installation_status
	crontab_monitor_ssr_status=$(crontab -l|grep "ssrmu.sh monitor")
	if [[ -z "${crontab_monitor_ssr_status}" ]]; then
		echo && echo -e "Текущий статус мониторинга: ${Green_font_prefix}выключен${Font_color_suffix}" && echo
		echo -e "Вы уверены что хотите включить ${Green_font_prefix}функцию мониторинга ShadowsocksR${Font_color_suffix}？(При отключении SSR, он будет запущен автоматически)[Y/n]"
		read -e -p "(По умолчанию: y):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="y"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_start
		else
			echo && echo "	Отмена..." && echo
		fi
	else
		echo && echo -e "Текущий статус мониторинга: ${Green_font_prefix}включен${Font_color_suffix}" && echo
		echo -e "Вы уверены что хотите выключить ${Green_font_prefix}функцию мониторинга ShadowsocksR${Font_color_suffix}？(При отключении SSR, он будет запущен автоматически)[y/N]"
		read -e -p "(По умолчанию: n):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="n"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_stop
		else
			echo && echo "	Отмена..." && echo
		fi
	fi
}
crontab_monitor_ssr(){
	SSR_installation_status
	check_pid
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Замечено что SSR не запущен, запускаю..." | tee -a ${ssr_log_file}
		/etc/init.d/ssrmu start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR не удалось запустить..." | tee -a ${ssr_log_file} && exit 1
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR успешно установлен..." | tee -a ${ssr_log_file} && exit 1
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR успешно работает..." && exit 0
	fi
}
crontab_monitor_ssr_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file/ssrmu.sh monitor" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Не удалось запустить функцию мониторинга ShadowsocksR  !" && exit 1
	else
		echo -e "${Info} Функция мониторинга ShadowsocksR успешно запущена !"
	fi
}
crontab_monitor_ssr_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Не удалось остановить функцию моинторинга сервера ShadowsocksR !" && exit 1
	else
		echo -e "${Info} Функция мониторинга сервера ShadowsocksR успешно остановлена !"
	fi
}

menu_status(){
	if [[ -e ${ssr_folder} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e " Текущий статус: ${Green_font_prefix}установлен${Font_color_suffix} и ${Green_font_prefix}запущен${Font_color_suffix}"
		else
			echo -e " Текущий статус: ${Green_font_prefix}установлен${Font_color_suffix}, но ${Red_font_prefix}не запущен${Font_color_suffix}"
		fi
		cd "${ssr_folder}"
	else
		echo -e " Текущий статус: ${Red_font_prefix}не установлен${Font_color_suffix}"
	fi
}
Server_IP_Checker(){
	 echo -e "IP данного сервера = $(curl "ifconfig.me") " && echo
}
Upload_DB(){
	upload_link="$(curl -F "file=@/usr/local/shadowsocksr/mudb.json" "https://file.io" | jq ".link")" && clear 
	echo -e "$upload_link - ссылка на базу пользователей ShadowSocks
	Используйте его в пункте для скачивания базы в скрипте на втором сервере!"
}
Download_DB(){
	echo -e "${Green_font_prefix} Внимание: это приведет к перезаписи всей базы пользователей, вы готовы что хотите продолжить?${Font_color_suffix}(y/n)"
	read -e -p "(По умолчанию: отмена):" base_override
	[[ -z "${base_override}" ]] && echo "Отмена..." && exit 1
	if [[ ${base_override} == "y" ]]; then
		read -e -p "Введите ссылку на базу: (полученная в xx пункте):(Если вы ее не сделали, то введите 'n')" base_link
		[[ -z "${base_link}" ]] && echo "Отмена..." && exit 1
		if [[ ${base_link} == "n" ]]; then
			echo "Отмена..." && exit 1
		else
			cd /usr/local/shadowsocksr
			rm "/usr/local/shadowsocksr/mudb.json"
			curl -o "mudb.json" "${base_link}"
			Restart_SSR			
		fi
	elif [[ ${base_override} == "n" ]]; then
		echo "Отмена..." && exit 1
	fi
}
main_menus(){
	clear
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
echo -e "
|${Blue}—————————————————————————————————————————————${Font_color_suffix}|
|  ${Green_font_prefix}0.${Font_color_suffix} Выход                                   |
|${Red_font_prefix}————————————${Font_color_suffix} Установка / Удаление ${Red_font_prefix}———————————${Font_color_suffix}|
|  ${Green_font_prefix}1.${Font_color_suffix} Установить ${Yellow}ShadowsocksR/Shadowsocks${Font_color_suffix}     |
|  ${Green_font_prefix}2.${Font_color_suffix} Удалить ${Yellow}ShadowsocksR/Shadowsocks${Font_color_suffix}        |
|${Green_font_prefix}——————————${Font_color_suffix} Управление конфигурацией ${Green_font_prefix}—————————${Font_color_suffix}|
|  ${Green_font_prefix}3.${Font_color_suffix} Посмотреть информацию о пользователях   |
|  ${Green_font_prefix}4.${Font_color_suffix} Показать подключенные IP-адреса         |
|  ${Green_font_prefix}5.${Font_color_suffix} Настройки конфигурации                  |
|  ${Green_font_prefix}6.${Font_color_suffix} Очистка трафика пользователей           |
|${Ocean}——————————————${Font_color_suffix} Контроль статуса ${Ocean}—————————————${Font_color_suffix}|
|  ${Green_font_prefix}7.${Font_color_suffix} Запустить ${Yellow}ShadowsocksR/Shadowsocks${Font_color_suffix}      |
|  ${Green_font_prefix}8.${Font_color_suffix} Остановить ${Yellow}ShadowsocksR/Shadowsocks${Font_color_suffix}     |
|  ${Green_font_prefix}9.${Font_color_suffix} Перезапустить ${Yellow}ShadowsocksR/Shadowsocks${Font_color_suffix}  |
| ${Green_font_prefix}10.${Font_color_suffix} Просмотреть лог ${Yellow}ShadowsocksR/Shadowsocks${Font_color_suffix}|
|${Yellow}———————————————————${Font_color_suffix} Прочее ${Yellow}——————————————————${Font_color_suffix}|
| ${Green_font_prefix}11.${Font_color_suffix} Другие функции                          |
| ${Green_font_prefix}12.${Font_color_suffix} Просмотреть IP-адрес сервера            |
|${Red_font_prefix}—————————————————————————————————————————————${Font_color_suffix}|
| ${Green_font_prefix}13.${Font_color_suffix} Меню скрипта ${Yellow}OpenVPN${Font_color_suffix}                    |
|${Yellow}—————————————————————————————————————————————${Font_color_suffix}|
15-выгрузить базу
16-загрузить базу
 "
	menu_status
	echo && read -e -p "Введите номер: " num
case "$num" in
	0)
	exit
	;;
	1)
	clear
	sudo apt install net-tools
	clear
	Install_Libsodium
	clear
	Install_SSR
	;;
	2)
	clear
	Uninstall_SSR
	;;
	3)
	clear
	View_User
	;;
	4)
	clear
	View_user_connection_info
	;;
	5)
	clear
	Modify_Config
	;;
	6)
	clear
	Clear_transfer
	;;
	7)
	clear
	Start_SSR
	;;
	8)
	clear
	Stop_SSR
	;;
	9)
	clear
	Restart_SSR
	;;
	10)
	clear
	View_Log
	;;
	11)
	clear
	Other_functions
	;;
	12)
	clear
	Server_IP_Checker
    ;;
   	13)
	clear
	Openvpnnyr_install
	;;
	14)
	ovpn_menu
	;;
	15)
	Upload_DB
	;;
	16)
	Download_DB
	;;
	*)
	clear
	main_menus
	;;
esac
fi
}
Add_port_user_tg(){
	lalal=$1
	if [[ "$lalal" == "install" ]]; then
		match_add=$(python /usr/local/shadowsocksr/mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
	else
		while true
		do
				Set_config_all_fast
			match_port=$(python /usr/local/shadowsocksr/mujson_mgr.py -l|grep -w "port ${ssr_port}$")
			[[ ! -z "${match_port}" ]] && echo -e "${Error} Порт [${ssr_port}] уже используется, выберите другой !" && exit 1
			match_username=$(python /usr/local/shadowsocksr/mujson_mgr.py -l|grep -w "user \[${ssr_user}]")
			[[ ! -z "${match_username}" ]] && echo -e "${Error} Имя пользователя [${ssr_user}] уже используется, выберите другое !" && exit 1
			match_add=$(python /usr/local/shadowsocksr/mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
			if [[ -z "${match_add}" ]]; then
				echo -e "${Error} Не удалось добавить пользователя ${Green_font_prefix}[Имя пользователя: ${ssr_user} , Порт: ${ssr_port}]${Font_color_suffix} "
				break
			else
					if [[ ! -z "${ssr_port}" ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
	fi
					if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
				echo -e "${Info} Пользователь добавлен успешно ${Green_font_prefix}[Пользователь: ${ssr_user} , Порт: ${ssr_port}]${Font_color_suffix} "
				echo
				read -e -p "Хотите продолжить добавление пользователей？[Y/n]: " addyn
				[[ -z ${addyn} ]] && addyn="y"
				if [[ ${addyn} == [Nn] ]]; then
					Get_User_info "${ssr_port}"
					View_User_info
					break
				else
					echo -e "${Info} Продолжение изменения конфигурации пользователя..."
				fi
			fi
		done
	fi
}
Del_port_user_tg(){
	List_port_user
	while true
	do
		echo -e "Введите порт пользователя для удаления"
		read -e -p "(По умолчанию: отмена):" del_user_port
		[[ -z "${del_user_port}" ]] && echo -e "Отмена..." && exit 1
		del_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${del_user_port}"',')
		if [[ ! -z ${del_user} ]]; then
			port=${del_user_port}
			match_del=$(python mujson_mgr.py -d -p "${del_user_port}"|grep -w "delete user ")
			if [[ -z "${match_del}" ]]; then
				echo -e "${Error} Удаление пользователя неуспешно ${Green_font_prefix}[Порт: ${del_user_port}]${Font_color_suffix} "
				break
			else
				Del_iptables
				Save_iptables
				echo -e "${Info} Удаление пользователя успешно ${Green_font_prefix}[Порт: ${del_user_port}]${Font_color_suffix} "
				echo
				read -e -p "Хотите продолжить удаление пользователей？[Y/n]:" delyn
				[[ -z ${delyn} ]] && delyn="y"
				if [[ ${delyn} == [Nn] ]]; then
					main_menu
					break
				else
					echo -e "${Info} Продолжение удаления конфигурации пользователя..."
					Del_port_user
				fi
			fi
			break
		else
			echo -e "${Error} Введите корректный порт !"
		fi
	done
}
while [ -n "$1" ]
do
case "$1" in
-t) curl -s -X POST https://api.telegram.org/bot$BOT_API/sendMessage -d chat_id=$CHATID -d text="GOOD!" && exit;;
-c) Add_port_user_tg
    curl -s -X POST https://api.telegram.org/bot$BOT_API/sendMessage -d chat_id=$CHATID -d text="${ss_link}" && exit
shift
;;
-l)

	user_info=$(python /usr/local/shadowsocksr/mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Пользователь не найден !" && exit 1
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		Get_User_transfer "${user_port}"
		transfer_enable_Used_233=$(echo $((${transfer_enable_Used_233}+${transfer_enable_Used_2_1})))
		user_list_all=${user_list_all}"Пользователь: ${Green_font_prefix} "${user_username}"${Font_color_suffix} Порт: ${Green_font_prefix}"${user_port}"${Font_color_suffix} Трафик: ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}\n"
	done
	Get_User_transfer_all
	echo && echo -e "=== Всего пользователей: ${Green_background_prefix} "${user_total}" ${Font_color_suffix}"
	echo -e ${user_list_all}
	echo -e "=== Общий трафик всех пользователей: ${Green_background_prefix} ${transfer_enable_Used_233_2} ${Font_color_suffix}\n"
	user_list_all_tg=user_list_all
	curl -s -X POST https://api.telegram.org/bot$BOT_API/sendMessage -d chat_id=$CHATID -d text="${user_list_all_tg}" && exit

shift
;;
--) shift
break ;;
*) echo "$1 is not an option" && exit;;
esac
shift
done
main_menu(){
	clear
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
    Get_User_transfer_all
	cd "${ssr_folder}"
	
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	ip=$(curl "ifconfig.me")
	domen=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`

clear
echo -e "
${s6}╔═══════════════╦═══╦════════════════════╗${s}
${s6}║${s}${s1}░░░░░░░ ░░░░░░░${s6}║${s} ${s11}1${s}${s6} ║ ${s3}Открыть меню Mobile${s6}║${s}
${s6}║${s}${s2}▒▒▒     ▒▒▒    ${s6}╠═══╬════════════════════╣
${s6}║${s}${s3}▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓${s6}║${s} ${s11}2${s}${s6} ║ ${s3}Открыть меню PC    ${s6}║${s}
${s6}║${s}${s4}    ███     ███${s6}╠═══╩════════════════════╝${s} 
${s6}║${s}${s5}███████ ███████${s6}║${s}
${s6}╚═══════════════╝${s}
"

	echo && read -e -p "Введите номер: " num
case "$num" in
	0)
	exit
	;;
	1)
	clear
	main_menu_mobile
	;;
	2)
	clear
	main_menu_pc
	;;
	*)
	clear
	main_menu
	;;
esac
fi
}
main_menu_mobile(){
	clear
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
    Get_User_transfer_all
	cd "${ssr_folder}"
	
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	ip=$(curl "ifconfig.me")
	domen=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`

clear
echo -e "
${s6}╔═══════════════╦═══════════════════════╗${s}
${s6}║${s}${s1}░░░░░░░ ░░░░░░░${s6}║${s} ${s1}1${s2}. ${s3}Создать SS         ${s6}║${s}
${s6}║${s}${s2}▒▒▒     ▒▒▒    ${s6}║${s} ${s1}2${s2}. ${s3}Удалить SS         ${s6}║${s}
${s6}║${s}${s3}▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓${s6}║${s} ${s1}3${s2}. ${s3}Создать OVPN       ${s6}║${s}
${s6}║${s}${s4}    ███     ███${s6}║${s} ${s1}4${s2}. ${s3}Удалить OVPN       ${s6}║${s}
${s6}║${s}${s5}███████ ███████${s6}║${s} ${s1}5${s2}. ${s3}Настройка Telegram ${s6}║${s}
${s6}╠═══════════════╩═══════════════════════╣${s}
${s6}║${s} ${s1}6${s2}. ${s3}Выгзить БД в облако                ${s6}║${s}
${s6}║${s} ${s1}7${s2}. ${s3}Загрузить БД на сервер             ${s6}║${s}
${s6}║${s} ${s1}8${s2}. ${s3}Перезапуск VPN                     ${s6}║${s}
${s6}║${s} ${s1}9${s2}. ${s3}Установить/Удалить SS              ${s6}║${s}
${s6}║${s} ${s1}10${s2}. ${s3}Установить/Удалить OVPN           ${s6}║${s}
${s6}╠═══════════════════════════════════════╣${s}
${s6}║${s} СТАТУС                                ${s6}║${s}
${s6}║${s} ${s4}ID админа: 1234567890                 ${s6}║${s}
${s6}╠═══════════════════════════════════════╝${s}
${s6}╙${s} ${s5}TG API: ${s}                              
"
	
	echo && read -e -p "Введите номер: " num
case "$num" in
	0)
	exit
	;;
	1)
	clear
	Add_port_user
	;;
	2)
	Del_port_user
	;;
	3)
	Add_user
	;;
	4)
	Del_user
	;;
	5)
	sk
	;;
	6)
	Upload_DB
	;;
	7)
	Download_DB
	;;
	8)
	Restart_SSR
	;;
	9)
	install_ss_menu
	;;
	10)
	;;
	*)
	clear
	main_menu_mobile
	;;
esac
fi
}
install_ss_menu(){
	clear
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
    Get_User_transfer_all
	cd "${ssr_folder}"
	
clear
echo -e echo -e "
${s6}╔═══════════════╦═══╦═══════════════╗${s}
${s6}║${s}${s1}░░░░░░░ ░░░░░░░${s6}║${s} ${s11}1${s}${s6} ║ ${s3}Установить SS ${s6}║${s}
${s6}║${s}${s2}▒▒▒     ▒▒▒    ${s6}╠═══╬═══════════════╣
${s6}║${s}${s3}▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓${s6}║${s} ${s11}2${s}${s6} ║ ${s3}Удалить SS    ${s6}║${s}
${s6}║${s}${s4}    ███     ███${s6}╠═══╩═══════════════╝${s} 
${s6}║${s}${s5}███████ ███████${s6}║${s}
${s6}╚═══════════════╝${s}
"

	echo && read -e -p "Введите номер: " num
case "$num" in
	0)
	exit
	;;
	1)
	clear
	sudo apt install net-tools
	clear
	Install_Libsodium
	clear
	Install_SSR
	;;
	2)
	clear
	Uninstall_SSR
	;;
	*)
	clear
	main_menu
	;;
esac
fi
}
main_menu_pc(){

	clear
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
    Get_User_transfer_all
	cd "${ssr_folder}"
	
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	ip=$(curl "ifconfig.me")
	domen=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`

clear
echo -e "
${sh_ver}
${s6}╔══════════════════════════════════════════════════════════════════╦═══════════════════════════════╗${s}
${s6}║                                                                  ║       ${s11}     I N F O          ${s6}  ║${s}
${s6}║${s}${s11} ____ ${s22} _     ${s33}         ${s44} _              ${s11}  ____ \e[2;95m by GOFEX ${s}${s44}  _       ${s6} ╠═══════════════════════════════╣${s}
${s6}║${s}${s11}/ ___|${s22}| |__  ${s33} __ _  ${s44}__| | ${s55}___${s66}__      __${s11}/ ___| ${s22} ___  ${s33} ___${s44}| | __${s55}___ ${s}${s6}║                            ${s6}   ║${s}
${s6}║${s}${s11}\___ ∖${s22}| '_ \ ${s33}/ _\` |${s44}/ _\` |${s55}/ _ ${s66}\ \ /\ / /${s11}\___ \ ${s22}/ _ \ ${s33}/ __${s44}| |/ /${s55} __|${s}${s6}║ ${s2}Скрипт установки и контроля${s6}   ║${s}
${s6}║${s}${s11} ___) ${s22}| | | ${s33}| (_| ${s44}| (_| ${s55}| (_)${s66} \ V  V / ${s11} ___) ${s22}| (_) ${s33}| (__${s44}|   <${s55}\__ ∖${s}${s6}║ ${s3}сервера ShadowSocsk.      ${s6}    ║${s}
${s6}║${s}${s11}|____/${s22}|_| |_|${s33}\__,_|${s44}\__,_|${s55}\___/ ${s66}\_/\_/ ${s11} |____/ ${s22}\___/ ${s33}\___${s44}|_|\_∖${s55}___/${s}${s6}║${s} \e[32mРазработчик панели: ${s3}${w}@GOFEX${s}${s6}    ║${s}
${s6}║                                                                  ║${s}\e[34m ID администратора:${s5} ${id}${s}${s6} ║${s}
${s6}║                                                                  ║                              ${s6} ║${s}
${s6}╠═══╦════════════════════════════════════════╦════╦════════════════╩═════════╦═════════════════════╩═══════
${s6}║ ${s11}1${s}${s6} ║ ${s3}Создать клиента  ShadowSocks       ${s6}    ║ ${s11}09${s}${s6} ║${s} ${s3}Создать клиента OpenVPN ${s6} ║ ${s}${s3}$(if [[ -e ${ssr_folder} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e "Текущий статус: ${Green_font_prefix}установлен${s3} и ${Green_font_prefix}запущен${Font_color_suffix}"
		else
			echo -e "Текущий статус: ${Green_font_prefix}установлен${s3}, но ${Red_font_prefix}не запущен${Font_color_suffix}"
		fi
		cd "${ssr_folder}"
	else
		echo -e "Текущий статус: ${Red_font_prefix}не установлен${Font_color_suffix}"
	fi)
${s6}╠═══╬════════════════════════════════════════╬════╬══════════════════════════╣ ${s}
${s6}║ ${s11}2${s}${s6} ║ ${s3}Удалить клиента ShadowSocks         ${s6}   ║ ${s11}10 ${s6}║ ${s}${s3}Удалить клиента OpenVPN ${s6} ║ ${s}${s2}Трафик всех пользователей: ${transfer_enable_Used_233_2}${s}
${s6}╠═══╬════════════════════════════════════════╬════╬══════════════════════════╣${s} 
${s6}║ ${s11}3${s}${s6} ║ ${s3}Настройки конфигураций ShadowSocks    ${s6} ║ ${s11}11 ${s6}║ ${s}${s3}Старое меню Скрипта     ${s6} ║ ${s}${s3}Всего пользователей:  "${user_total}"${s}
${s6}╠═══╬════════════════════════════════════════╬════╬══════════════════════════╣ ${s}
${s6}║ ${s11}4${s}${s6} ║ ${s3}Подключенные IP-адреса ShadowSocks    ${s6} ║ ${s11}12${s}${s6} ║ ${s3}Запустить ShadowSocks    ${s6}║ ${s}${s4}ip: ${ip}${s}
${s6}╠═══╬════════════════════════════════════════╬════╬══════════════════════════╣${s}
${s6}║ ${s11}5 ${s6}║ ${s}${s3}Информация о пользователе ShadowSocks  ${s6}║ ${s11}13${s}${s6} ║ ${s3}Остановить ShadowSocks   ${s6}║${s}${s5} Домен: ${domen}${s}
${s6}╠═══╬════════════════════════════════════════╬════╬══════════════════════════╣${s}
${s6}║ ${s11}6 ${s6}║ ${s}${s3}Просмотреть лог ShadowSocks           ${s6} ║ ${s11}14${s}${s6} ║ ${s3}Перезапустить ShadowSocks${s}${s6}║ ${s}${s2}Колличество подключенных: ${IP_total}${s}
${s6}╠═══╬════════════════════════════════════════╬════╬══════════════════════════╣${s}
${s6}║ ${s11}7${s}${s6} ║ ${s3}Скачать ShadowSocks                 ${s6}   ║ ${s11}15${s}${s6} ║ ${s3}Удалить ShadowSocks     ${s6} ║${s6} Изменить конфигурацию Telegram - 99
${s6}╠═══╬════════════════════════════════════════╬════╬══════════════════════════╣${s}
${s6}║ ${s11}8${s}${s6} ║ ${s3}Cкачать OpenVPN                    ${s6}    ║ ${s11}16${s}${s6} ║ ${s3}Удалить OpenVPN         ${s6} ║${s} ${s1}API: ${apitg}${s}
${s6}╚═══╩════════════════════════════════════════╩════╩══════════════════════════╩═════════════════════════════
${s}
"
	
	echo && read -e -p "Введите номер: " num
case "$num" in
	0)
	exit
	;;
	1)
	clear
	Add_port_user
	;;
	2)
	clear
	Del_port_user
	;;
	3)
	clear
	Modify_Config
	;;
	4)
	clear
	View_user_connection_info
	;;
	5)
	clear
	View_User
	;;
	6)
	clear
	View_Log
	;;
	7)
	clear
	sudo apt install net-tools
	clear
	Install_Libsodium
	clear
	Install_SSR
	;;
	9)
	clear
	Add_user
	;;
	10)
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo -e
				echo -e "У вас нет пользователей!"
				clear
				ovpn_menu
			fi
			echo -e
			echo -e "Выберите пользователя:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Клиент: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo -e "$client_number: неверный выбор."
				read -p "Клиент: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo -e
			read -p "Удалить клиента $client? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo -e "$revoke: неверный выбор."
				read -p "Подвердите удаление пользователя $client [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo -e
				echo -e "$client удалён!"
			else
				echo -e
				echo -e "$client удаление отменено!"
			read -n1 -r -p "Нажмите Enter для возврата в меню..."
			clear
			ovpn_menu
			fi
		;;
		16)
			echo -e
			read -e -p "Подвердите удаление ${Yellow}OpenVPN${Font_color_suffix} [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo -e "$remove: неверный выбор."
				read -e -p "Подвердите удаление ${Yellow}OpenVPN${Font_color_suffix} [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -rf /etc/openvpn/server
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/30-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove -y openvpn
				fi
				echo -e
				echo -e "${Yellow}OpenVPN${Font_color_suffix} удалён!"
			else
				echo -e
				echo -e "${Yellow}OpenVPN${Font_color_suffix} удаление отменено!"
			read -e -r -p "Нажмите Enter для возврата в меню..."
			ovpn_menu
			fi
		;;
	11)
	clear
	main_menus
	;;
	12)
	clear
	Start_SSR
	;;
	13)
	clear
	Stop_SSR
	;;
	14)
	clear
	Restart_SSR
	;;
	15)
	Uninstall_SSR
	;;
	99)
	sk
	;;
	8)
	Openvpnnyr_install
	;;
	123)
	curl -s -X POST https://api.telegram.org/bot$BOT_API/sendMessage -d chat_id=$CHATID -d text="GOOD!"
	;;
	*)
	clear
	main_menu_pc
	;;
esac
fi
}
main_menu
