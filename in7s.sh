#!/bin/bash
IP_VPS=$(curl -sS ipv4.icanhazip.com)

# // BANDUNG BARAT , jawa barat , saguling
# // Authorized || Lunatic Tunneling ( dP )
# // Verif tools || LT Managers || Shell Programing
# // whatsapp || +6285955333616 || +6283189774145
# // telegram || @ian_khvicha || TunnelingLunatic
# // Created in scripts || 14 oct 2020
# // Updated in scripts || 10 dec 2024
# // ====================================
# // scripts universal || ubuntu 20,22,24
# // scripts universal || debian 10,11,12
# // ====================================

function install_curl_jq() {
    clear
    echo -e "\e[36;1m Install Jq,curl and wget.... \e[0m"
    apt install wget curl jq -y
    echo -e "\e[32;1m install jq,curl,wget succes.. \e[0m" 
}
install_curl_jq


log_message() {
    local message=$1
    echo -e "$(date +'%Y-%m-%d %H:%M:%S') - $message"
}

check_root_user() {
    if [ "${EUID}" -ne 0 ]; then
        log_message "\e[92;1mError: This script must be run as root user.\e[0m"
        exit 1
    else
        log_message "Root user verified successfully."
    fi
}

check_openvz_support() {
    if [ "$(systemd-detect-virt)" == "openvz" ]; then
        log_message "Error: OpenVZ is not supported. Exiting script."
        exit 1
    else
        log_message "OpenVZ check passed. Proceeding with the script."
    fi
}

get_public_ip() {
    export IP=$(curl -sS icanhazip.com)
    log_message "Public IP obtained: $IP"
}

# Clear screen dan melakukan pemeriksaan
clear
get_public_ip
check_root_user
check_openvz_support

# Fungsi untuk membuat direktori dengan izin yang benar
create_dir() {
    local dir=$1
    local owner=$2
    local permissions=$3

    if [ ! -d "$dir" ]; then
        mkdir -p "$dir" && log_message "Directory $dir created successfully." || log_message "Failed to create directory $dir."
    else
        log_message "Directory $dir already exists."
    fi

    chown "$owner" "$dir" && log_message "Ownership of $dir set to $owner." || log_message "Failed to set ownership for $dir."
    chmod "$permissions" "$dir" && log_message "Permissions for $dir set to $permissions." || log_message "Failed to set permissions for $dir."
}

# Fungsi untuk membuat file log dengan izin yang benar
create_log_file() {
    local log_file=$1
    if [ ! -f "$log_file" ]; then
        touch "$log_file" && log_message "Log file $log_file created successfully." || log_message "Failed to create log file $log_file."
    else
        log_message "Log file $log_file already exists."
    fi
}

# Mulai proses pembuatan direktori dan log
log_message "Starting directory and log file creation process."

# Membuat direktori untuk xray dan LT
create_dir "/etc/xray" "www-data:www-data" "755"
create_dir "/var/lib/LT" "www-data:www-data" "755"
create_dir "/var/log/xray" "www-data:www-data" "755"

# Membuat file log untuk xray
create_log_file "/var/log/xray/access.log"
create_log_file "/var/log/xray/error.log"

# Memberikan izin eksekusi pada direktori log xray
chmod +x /var/log/xray && log_message "Executed chmod +x on /var/log/xray." || log_message "Failed to execute chmod +x on /var/log/xray."

# Menunggu sejenak sebelum melanjutkan
sleep 2
log_message "Directory and log file creation process completed."

# Membersihkan layar setelah operasi
clear

function addon_domain() {
    clear
    echo -e "   \033[38;5;197m ===========================================\e[0m"
    echo -e "   \033[38;5;227m    Please Select a Domain bellow type.     \e[0m"
    echo -e "   \033[38;5;197m ===========================================\e[0m"
    echo -e "   \033[38;5;197m  1). \e[97;1m Domain Pribadi   \e[0m"
    echo -e "   \033[38;5;197m  2). \e[97;1m Domain Random  \e[0m"
    echo -e "   \033[38;5;197m ===========================================\e[0m"
    echo -e ""
    read -p "   Just Input a number [1-2]:   " host
    echo ""
    if [[ $host == "1" ]]; then
        clear
        IP=$(wget -qO- icanhazip.com);
        echo -e "   \033[38;5;197m ===========================================\e[0m"
        echo -e "   \033[38;5;227m             INPUT YOUR DOMAIN              \e[0m"
        echo -e "   \033[38;5;197m ===========================================\e[0m"
        echo -e ""
        read -p "   input your domain   :   " host1
        echo "IP=" > /var/lib/LT/ipvps.conf
        echo $host1 > /etc/xray/domain
        echo $host1 > /root/domain
        echo "IP=$host1" > /var/lib/LT/ipvps.conf
    elif [[ $host == "2" ]]; then
        clear
        echo -e ""
        echo -e "   \033[38;5;197m ===========================================\e[0m"
        echo -e "   \033[38;5;227m            INPUT YOUR SUBDOMAIN            \e[0m"
        echo -e "   \033[38;5;197m ===========================================\e[0m"
        echo -e ""
        echo -e "   \033[96;1m EXAMPLE :\033[0m"
        echo -e "   \033[97;1m  vpnqu , kontolvpn ,bebas = ini subdomain BENAR ✓\033[0m"
        echo -e "   \033[97;1m  vpnqu.my.id , komtolvpn.com ,bebas.net = ini SALAH x\033[0m"
        echo -e "   \033[38;5;197m ===========================================\e[0m"
        echo -e ""
        read -p "   input your subdomain :   " SUBDOMAIN

        # cloudflare value
        API_TOKEN="LBZrKgFI9_UBRGo6x8ZUEmO1NzbfQXPTxb-70zw9"          # API Token Cloudflare
        ZONE_ID="1411ad8a55b429280a52f741550d2e46"                    # Zone ID domain
        DOMAIN_NAME="lunatictunnel.buzz"                              # Nama domain

        # Validasi apakah subdomain diisi
        if [ -z "$SUBDOMAIN" ]; then
            echo "Subdomain tidak boleh kosong. Skrip akan berhenti."
            exit 1
        fi

        # Menambahkan A Record untuk domain utama
        echo "Menambahkan A Record untuk domain utama: $DOMAIN_NAME"
        curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            --data '{
            "type": "A",
            "name": "'$DOMAIN_NAME'",
            "content": "'$IP_VPS'",
            "ttl": 120,
            "proxied": false
        }'

        # Menambahkan A Record untuk subdomain yang dimasukkan pengguna
        echo "Menambahkan A Record untuk subdomain: $SUBDOMAIN.$DOMAIN_NAME"
        curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            --data '{
            "type": "A",
            "name": "'$SUBDOMAIN'",
            "content": "'$IP_VPS'",
            "ttl": 120,
            "proxied": false
        }'

        # Menambahkan wildcard A Record untuk semua subdomain di bawah domain
        echo "Menambahkan A Record wildcard untuk *. $DOMAIN_NAME"
        curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            --data '{
            "type": "A",
            "name": "*'.$SUBDOMAIN'",
            "content": "'$IP_VPS'",
            "ttl": 120,
            "proxied": false
        }'

        # dapatkan inpo ipvps
        IP=$(wget -qO- icanhazip.com);
        # Menyimpan domain/subdomain ke /etc/xray/domain
        echo "$SUBDOMAIN.$DOMAIN_NAME" > /etc/xray/domain
        echo "$SUBDOMAIN.$DOMAIN_NAME" > /root/domain
        echo "IP=$SUBDOMAIN.$DOMAIN_NAME" > /var/lib/LT/ipvps.conf
        echo "IP=" > /var/lib/LT/ipvps.conf
        # Menyimpan wildcard ke /etc/xray/wildcard
        echo "bug.com.$SUBDOMAIN.$DOMAIN_NAME" > /etc/xray/wildcard
    fi
}

addon_domain
clear



# data Telegram
TIMES="10"
CHATID="5970831071"
KEY="7633327456:AAGE7JigJpWbJyVly-fcQ8B3S1ctqq-qYOM"
URL="https://api.telegram.org/bot$KEY/sendMessage"
TIME=$(date '+%d %b %Y')

# repo
GIT_USER="scriptsvpnlt"
GIT_REPO="Mamardashvili"
GIT_BRANCH="main"
REPO="https://raw.githubusercontent.com/${GIT_USER}/${GIT_REPO}/${GIT_BRANCH}/"

# Save Name in github to /usr/bin/user
rm -f /usr/bin/user
username=$(curl https://raw.githubusercontent.com/${GIT_USER}/vps_access/main/ip | grep $IP_VPS | awk '{print $2}')
echo "$username" >/usr/bin/user

# Save Expired Detail in github to /usr/bin/e
expx=$(curl https://raw.githubusercontent.com/${GIT_USER}/vps_access/main/ip | grep $IP_VPS | awk '{print $3}')
echo "$expx" >/usr/bin/e

# Calculated expired Y+M+T to dayLEFT
username=$(cat /usr/bin/user)
exp=$(cat /usr/bin/e)
clear

# Current Date
DATE=$(date +'%Y-%m-%d')
today=$(date -d "0 days" +"%Y-%m-%d")

# Function to calculate the date difference
datediff() {
    d1=$(date -d "$1" +%s)
    d2=$(date -d "$2" +%s)
    echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}

# Call the datediff function to calculate expiry
datediff "$exp" "$DATE"

function gasgas() {
# Status Check
Exp1=$(curl https://raw.githubusercontent.com/${GIT_USER}/vps_access/main/ip | grep $IP_VPS | awk '{print $4}')
if [[ $(date -d "$today" +%s) -lt $(date -d "$Exp1" +%s) ]]; then
    sts="${Info}"
else
    sts="${Error}"
fi

clear
start=$(date +%s)
secs_to_human() {
     echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

curl -s ifconfig.me > /etc/xray/ipvps
# var lib LT
mkdir -p /var/lib/LT >/dev/null 2>&1
while IFS=":" read -r a b; do
case $a in
"MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
"Shmem") ((mem_used+=${b/kB}))  ;;
"MemFree" | "Buffers" | "Cached" | "SReclaimable")
mem_used="$((mem_used-=${b/kB}))"
;;
esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=`date -d "0 days" +"%d-%m-%Y - %X" `
export OS_Name=$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g' )
export Kernel=$( uname -r )
export Arch=$( uname -m )
export IP=$( curl -s https://ipinfo.io/ip/ )
}

gasgas

# Fungsi untuk mencetak pesan dengan format tertentu
print_message() {
    local message=$1
    echo -e "$message"
}

base_package() {
    # Menampilkan pesan sebelum memulai proses
    echo "Memulai pembaruan dan instalasi paket dasar..."

    # Mendeteksi OS yang digunakan
    OS_NAME=$(lsb_release -si)
    OS_VERSION=$(lsb_release -sr)

    echo "Deteksi sistem: $OS_NAME $OS_VERSION"

    # Daftar paket dasar yang diperlukan
    local packages=(
        build-essential libc6 libssl-dev zlib1g-dev libcurl4-openssl-dev libsqlite3-dev 
        libpng-dev libjpeg-dev haproxy ubuntu-release-upgrader-core libgif-dev libxml2-dev libxslt1-dev zip pwgen openssl 
        netcat socat cron bash-completion bmon ntpdate sudo debconf-utils
        software-properties-common speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config 
        libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex 
        bison make libnss3-tools libevent-dev bc rsyslog dos2unix sed dirmngr 
        libxml-parser-perl gcc g++ python3 htop lsof tar ruby unzip p7zip-full 
        python3-pip libc6 util-linux msmtp-mta ca-certificates bsd-mailx iptables 
        iptables-persistent netfilter-persistent net-tools gnupg gnupg2 lsb-release 
        shc make cmake git screen xz-utils apt-transport-https gnupg1 dnsutils
        easy-rsa
    )

    # Cek jika OS adalah Debian atau Ubuntu
    if [[ "$OS_NAME" == "Debian" || "$OS_NAME" == "Ubuntu" ]]; then
        echo "Mengupdate dan mengupgrade sistem..."
        apt update -y && apt upgrade -y
    else
        echo "Distribusi ini tidak didukung. Hanya Debian dan Ubuntu yang didukung."
        exit 1
    fi

    # Instalasi paket dasar
    echo "Menginstal paket-paket dasar..."
    apt install -y "${packages[@]}"

    # Membersihkan cache apt untuk menghemat ruang disk
    echo "Membersihkan cache apt..."
    apt clean

    # Menghapus paket yang tidak diperlukan
    echo "Menghapus paket yang tidak diperlukan..."
    apt autoremove -y

    # Menghapus layanan yang tidak diperlukan (seperti exim4 dan firewall)
    echo "Menghapus layanan yang tidak diperlukan..."
    apt remove --purge exim4 ufw firewalld -y

    # Menyiapkan iptables-persistent untuk menyimpan aturan firewall
    echo "Mengonfigurasi iptables-persistent..."
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # Mengaktifkan dan memulai layanan waktu (chrony dan NTP)
    echo "Mengaktifkan dan memulai layanan waktu..."
    if [[ "$OS_NAME" == "Debian" && "$OS_VERSION" == "10" ]]; then
        echo "Menggunakan NTPdate untuk Debian 10..."
        systemctl stop ntp
        systemctl disable ntp
        ntpdate pool.ntp.org
    elif [[ "$OS_NAME" == "Ubuntu" && "$OS_VERSION" == "20.04" ]]; then
        echo "Menggunakan NTPdate untuk Ubuntu 20.04..."
        systemctl stop ntp
        systemctl disable ntp
        ntpdate pool.ntp.org
    elif [[ "$OS_NAME" == "Debian" && "$OS_VERSION" == "11" || "$OS_NAME" == "Debian" && "$OS_VERSION" == "12" || "$OS_NAME" == "Ubuntu" && "$OS_VERSION" == "22.04" || "$OS_NAME" == "Ubuntu" && "$OS_VERSION" == "24.04" ]]; then
        echo "Menggunakan chrony untuk sistem lebih baru (Debian 11/12, Ubuntu 22.04/24.04)..."
        systemctl enable chrony
        systemctl restart chrony
    else
        echo "Versi sistem tidak dikenal, melakukan sinkronisasi waktu secara manual."
        ntpdate pool.ntp.org
    fi

    # Menyinkronkan waktu dengan NTP server
    echo "Menyinkronkan waktu dengan server NTP..."
    ntpdate pool.ntp.org

    # Menampilkan pesan selesai
    echo "Instalasi dan konfigurasi selesai."
}

# Fungsi untuk menginstal NGINX tergantung pada distribusi OS
nginx_install() {
    # Mendapatkan nama sistem operasi
    local os_name
    os_name=$(awk -F= '/^ID=/ { print $2 }' /etc/os-release | tr -d '"')

    # Mendapatkan nama sistem operasi yang lebih lengkap (untuk menampilkan pesan)
    local os_pretty_name
    os_pretty_name=$(awk -F= '/^PRETTY_NAME=/ { print $2 }' /etc/os-release | tr -d '"')

    # Menampilkan pesan yang sesuai berdasarkan sistem operasi
    case "$os_name" in
        ubuntu)
            print_message "Setup nginx for OS: $os_pretty_name"
            sudo apt-get install nginx -y
            ;;
        debian)
            print_message "Setup nginx for OS: $os_pretty_name"
            sudo apt install nginx -y
            ;;
        *)
            print_message "Your OS ($os_pretty_name) is not supported."
            ;;
    esac
}

# Fungsi untuk memasang SSL menggunakan acme.sh
install_sslcert() {
    # Membersihkan file SSL lama
    echo "Menghapus file SSL lama..."
    rm -f /etc/xray/xray.key /etc/xray/xray.crt
    
    # install socat
    sudo apt install socat
    
    # Mendapatkan domain dari file
    local domain
    domain=$(cat /etc/xray/domain)

    # Menemukan dan menghentikan web server yang menggunakan port 80
    local stop_webserver
    stop_webserver=$(lsof -i:80 | awk 'NR==2 {print $1}')
    echo "Menghentikan server web di port 80..."
    systemctl stop "$stop_webserver" || true
    systemctl stop nginx || true

    # Menghapus dan membuat ulang direktori .acme.sh
    echo "Menghapus direktori .acme.sh dan membuat ulang..."
    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    # Mengunduh dan menginstal acme.sh
    echo "Mengunduh acme.sh..."
    curl -sS https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh

    # Memperbarui acme.sh
    echo "Memperbarui acme.sh..."
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # Meminta sertifikat SSL menggunakan acme.sh
    echo "Mengajukan sertifikat SSL untuk domain $domain..."
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256

    # Memasang sertifikat SSL ke direktori xray
    echo "Memasang sertifikat SSL..."
    /root/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc

    # Menyesuaikan izin file kunci SSL
    echo "Mengatur izin file kunci SSL..."
    chmod 600 /etc/xray/xray.key
     
     # restart xray
    systemctl restart xray
    
    echo "Sertifikat SSL berhasil dipasang untuk domain $domain."
}

# Fungsi untuk setup pertama (timezone, iptables, dan haproxy)
install_haproxy() {
    # Set timezone
    timedatectl set-timezone Asia/Jakarta
    echo "Timezone set to Asia/Jakarta."

    # Konfigurasi iptables-persistent
    echo "Configuring iptables-persistent..."
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get update
    apt-get install -y iptables-persistent

    # Mengambil nama distribusi OS
    local os_name
    os_name=$(awk -F= '/^ID=/ { print $2 }' /etc/os-release | tr -d '"')

    # Mengambil versi distribusi OS
    local os_version
    os_version=$(awk -F= '/^VERSION_ID=/ { print $2 }' /etc/os-release | tr -d '"')

    # Menentukan codename Ubuntu
    local ubuntu_codename
    if [[ "$os_name" == "ubuntu" ]]; then
        ubuntu_codename=$(lsb_release -cs)
        if [[ "$ubuntu_codename" == "noble" ]]; then
            echo "Codename 'noble' detected, using 'jammy' as fallback."
            ubuntu_codename="jammy"
        fi
    fi

    # Melakukan setup tergantung pada distribusi
    case "$os_name" in
        ubuntu)
            echo "Setting up dependencies for Ubuntu $os_version ($ubuntu_codename)"
            apt-get update
            apt-get install -y software-properties-common

            # Tambahkan repository dengan codename yang benar
            add-apt-repository -y ppa:vbernat/haproxy-2.0
            sed -i "s|noble|$ubuntu_codename|g" /etc/apt/sources.list.d/vbernat-ubuntu-haproxy-2_0-*.list
            apt-get update

            # Instalasi HAProxy
            apt-get install -y haproxy
            ;;
        debian)
            echo "Setting up dependencies for Debian $os_version"
            curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor > /usr/share/keyrings/haproxy.debian.net.gpg
            case "$os_version" in
                "10")
                    echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net buster-backports main" | \
                        tee /etc/apt/sources.list.d/haproxy.list > /dev/null
                    ;;
                "11")
                    echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bullseye-backports main" | \
                        tee /etc/apt/sources.list.d/haproxy.list > /dev/null
                    ;;
                "12")
                    echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bookworm-backports main" | \
                        tee /etc/apt/sources.list.d/haproxy.list > /dev/null
                    ;;
                *)
                    echo "Unsupported Debian version ($os_version). Exiting..."
                    exit 1
                    ;;
            esac
            apt-get update
            apt-get install -y haproxy
            ;;
        *)
            echo "Your OS ($os_name $os_version) is not supported. Exiting..."
            exit 1
            ;;
    esac

    echo "Setup completed successfully."
}

make_folder_xray() {
    # Direktori utama untuk aplikasi Lunatic
    local base_dir="/etc/lunatic"
    
    # Daftar direktori yang perlu dibuat
    local directories=(
        "$base_dir"
        "$base_dir/vmess/ip"
        "$base_dir/vless/ip"
        "$base_dir/trojan/ip"
        "$base_dir/ssh/ip"
        "$base_dir/vmess/detail"
        "$base_dir/vless/detail"
        "$base_dir/trojan/detail"
        "$base_dir/shadowsocks/detail"
        "$base_dir/ssh/detail"
        "$base_dir/noobzvpns/detail"
        "$base_dir/vmess/usage"
        "$base_dir/vless/usage"
        "$base_dir/shadowsocks/usage"
        "$base_dir/trojan/usage"
        "$base_dir/bot"
        "$base_dir/bot/telegram"
        "$base_dir/bot/notif"
        "/usr/bin/xray"
        "/var/log/xray"
        "/var/www/html"
        "/usr/sbin/local"
    )

    # Membuat direktori yang diperlukan
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done

    # Menyiapkan file yang diperlukan
    local files=(
        "/etc/xray/domain"
        "/var/log/xray/access.log"
        "/var/log/xray/error.log"
        "$base_dir/vmess/.vmess.db"
        "$base_dir/vless/.vless.db"
        "$base_dir/trojan/.trojan.db"
        "$base_dir/ssh/.ssh.db"
        "$base_dir/bot/.bot.db"
        "$base_dir/bot/notif/key"
        "$base_dir/bot/notif/id"
    )

    # Membuat file jika belum ada
    for file in "${files[@]}"; do
        touch "$file"
    done

    # Menambahkan konten default pada file .db
    echo "& plugin Account" >> "$base_dir/vmess/.vmess.db"
    echo "& plugin Account" >> "$base_dir/vless/.vless.db"
    echo "& plugin Account" >> "$base_dir/trojan/.trojan.db"
    echo "& plugin Account" >> "$base_dir/ssh/.ssh.db"

    # Memberikan izin eksekusi pada direktori log xray
    chmod +x "/var/log/xray"
}

function install_xray() {
# Direktori untuk domain socket
domainSock_dir="/run/xray"
if [ ! -d "$domainSock_dir" ]; then
    print_message "Creating domain socket directory: $domainSock_dir"
    mkdir -p "$domainSock_dir"
    chown www-data:www-data "$domainSock_dir"
else
    print_message "Domain socket directory already exists: $domainSock_dir"
fi

# Mendapatkan versi terbaru Xray dari GitHub
latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | \
    grep tag_name | \
    sed -E 's/.*"v(.*)".*/\1/' | \
    head -n 1)

# Instalasi Xray dengan versi terbaru
print_message "Installing Xray version $latest_version"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version"

# Mengunduh konfigurasi dan file layanan
print_message "Downloading configuration and service files"
wget -O /etc/xray/config.json "${REPO}cfg_conf_js/config.json" >/dev/null 2>&1
wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1

# Mengambil domain dan IP VPS dari file konfigurasi
domain=$(cat /etc/xray/domain)
IPVS=$(cat /etc/xray/ipvps)

# Mengunduh data lokasi dan ISP
print_message "Fetching city and ISP information"
curl -s ipinfo.io/city >>/etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp

# Mengunduh konfigurasi untuk HAProxy dan Nginx
print_message "Downloading HAProxy and Nginx configurations"
wget -O /etc/haproxy/haproxy.cfg "${REPO}cfg_conf_js/haproxy.cfg" >/dev/null 2>&1
wget -O /etc/nginx/conf.d/xray.conf "${REPO}cfg_conf_js/xray.conf" >/dev/null 2>&1

# Mengganti placeholder dengan domain di file konfigurasi
print_message "Updating configuration files with domain"
sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf

# Mengunduh dan mengonfigurasi nginx.conf
curl ${REPO}cfg_conf_js/nginx.conf > /etc/nginx/nginx.conf

# Menggabungkan sertifikat dan kunci Xray untuk digunakan dengan HAProxy
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

# Menyiapkan hak akses pada file runn.service
chmod +x /etc/systemd/system/runn.service

# Menghapus layanan Xray lama
rm -rf /etc/systemd/system/xray.service.d

# Membuat file layanan systemd untuk Xray
print_message "Creating systemd service for Xray"
cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNOFILE=1000000
LimitNPROC=10000

[Install]
WantedBy=multi-user.target
EOF

# Memuat ulang systemd untuk membaca konfigurasi layanan baru
print_message "Reloading systemd and enabling services"
systemctl daemon-reload
systemctl enable xray
systemctl enable runn
systemctl start xray
systemctl start runn

print_message "Xray installation and configuration completed successfully."

}

function install_password(){
clear
wget -O /etc/pam.d/common-password "${REPO}files/password"
chmod +x /etc/pam.d/common-password
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "
cd
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END
cat > /etc/rc.local <<-END
exit 0
END
chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
}

function install_badvpn(){
# Fungsi untuk mengunduh dan mengonfigurasi file
download_and_configure() {
    local file_url=$1
    local destination=$2
    local file_name=$(basename "$file_url")

    print_message "Downloading $file_name to $destination"
    wget -q -O "$destination" "$file_url"
    chmod +x "$destination"
}

# Fungsi untuk membuat dan mengonfigurasi layanan systemd
create_systemd_service() {
    local service_name=$1
    local exec_start=$2
    local description=$3

    print_message "Creating systemd service: $service_name"
    cat >"/etc/systemd/system/$service_name.service" <<EOF
[Unit]
Description=$description
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=$exec_start
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$service_name"
    systemctl restart "$service_name"
}
# Direktori untuk menyimpan file yang diunduh
mkdir -p /usr/bin/limit-ip
mkdir -p /usr/lunatic/

# Mengunduh file limit-quota.sh dan lock-service.sh
download_and_configure "https://raw.githubusercontent.com/${GIT_USER}/${GIT_REPO}/${GIT_BRANCH}/files/limit-quota.sh" "/usr/bin/limit-quota.sh"
download_and_configure "https://raw.githubusercontent.com/${GIT_USER}/${GIT_REPO}/${GIT_BRANCH}/files/lock-service.sh" "/usr/bin/lock-service.sh"

# Menjalankan script yang diunduh
print_message "Running limit-quota.sh and lock-service.sh"
./usr/bin/limit-quota.sh
./usr/bin/lock-service.sh

# Mengunduh dan mengonfigurasi file limit-ip
download_and_configure "${REPO}files/limit-ip" "/usr/bin/limit-ip"

# Menghapus karakter carriage return yang mungkin ada dalam file
sed -i 's/\r//' /usr/bin/limit-ip

# Membuat dan mengonfigurasi layanan systemd untuk berbagai layanan
create_systemd_service "vmip" "/usr/bin/limit-ip vmip" "VMIP Service"
create_systemd_service "vlip" "/usr/bin/limit-ip vlip" "VLIP Service"
create_systemd_service "trip" "/usr/bin/limit-ip trip" "TRIP Service"
create_systemd_service "ssip" "/usr/bin/limit-ip ssip" "SSIP Service"

# Mengunduh file untuk udp-mini dan layanan terkait
download_and_configure "${REPO}files/udp-mini" "/usr/lunatic/udp-mini"
download_and_configure "${REPO}files/udp-mini-1.service" "/etc/systemd/system/udp-mini-1.service"
download_and_configure "${REPO}files/udp-mini-2.service" "/etc/systemd/system/udp-mini-2.service"
download_and_configure "${REPO}files/udp-mini-3.service" "/etc/systemd/system/udp-mini-3.service"

# Mengelola layanan udp-mini
for service in udp-mini-1 udp-mini-2 udp-mini-3; do
    print_message "Enabling and starting service: $service"
    systemctl disable "$service"
    systemctl stop "$service"
    systemctl enable "$service"
    systemctl start "$service"
done

print_message "UDP Mini setup completed successfully."

}

# Fungsi untuk mengunduh dan mengonfigurasi SSHD
install_sshd() {
    log_message "Starting SSHD installation"

    # Mengunduh file konfigurasi SSH
    log_message "Downloading SSHD configuration"
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to download SSHD configuration file."
        exit 1
    fi

    # Mengatur izin akses file konfigurasi
    log_message "Setting permissions for SSHD configuration"
    chmod 700 /etc/ssh/sshd_config
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to set permissions for SSHD configuration file."
        exit 1
    fi

    # Restart SSH service
    log_message "Restarting SSH service"
    systemctl restart ssh
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to restart SSH service."
        exit 1
    fi

}

# Fungsi untuk mengunduh dan mengonfigurasi Dropbear
install_dropbear() {
    log_message "Starting Dropbear installation"

    # Install Dropbear
    log_message "Installing Dropbear"
    apt-get install dropbear -y >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to install Dropbear."
        exit 1
    fi

    # Mengunduh file konfigurasi Dropbear
    log_message "Downloading Dropbear configuration"
    wget -q -O /etc/default/dropbear "${REPO}cfg_conf_js/dropbear.conf"
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to download Dropbear configuration file."
        exit 1
    fi

    # Mengatur izin file konfigurasi
    log_message "Setting permissions for Dropbear configuration"
    chmod +x /etc/default/dropbear
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to set permissions for Dropbear configuration file."
        exit 1
    fi
}

# Fungsi untuk menginstal dan mengonfigurasi vnStat
install_vnstat() {
    log_message "Starting vnStat installation"

    apt -y install vnstat > /dev/null 2>&1
    /etc/init.d/vnstat restart
    apt -y install libsqlite3-dev > /dev/null 2>&1
    wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
}

# Fungsi untuk menginstal dan mengonfigurasi OpenVPN
install_openvpn() {
    log_message "Starting OpenVPN installation"

    # Download dan pasang OpenVPN
    log_message "Downloading OpenVPN installer"
    wget ${REPO}ovpn/openvpn && chmod +x openvpn && ./openvpn
    
    log_message "OpenVPN installation completed successfully."
}

# Fungsi untuk menginstal dan mengonfigurasi cadangan
install_backup() {
    log_message "Starting backup installation"

    # Install rclone
    log_message "Installing rclone"
    apt install -y rclone
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to install rclone."
        exit 1
    fi

    # Konfigurasi rclone
    log_message "Configuring rclone"
    printf "q\n" | rclone config
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to configure rclone."
        exit 1
    fi

    # Download konfigurasi rclone
    log_message "Downloading rclone configuration file"
    wget -O /root/.config/rclone/rclone.conf "${REPO}cfg_conf_js/rclone.conf"
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to download rclone configuration file."
        exit 1
    fi

    # Install wondershaper
    log_message "Cloning and installing wondershaper"
    cd /bin
    git clone https://github.com/LunaticTunnel/wondershaper.git
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to clone wondershaper repository."
        exit 1
    fi
    cd wondershaper
    make install
    cd
    rm -rf /bin/wondershaper

    # Create files directory
    log_message "Creating files directory"
    echo > /home/files

    # Install msmtp and dependencies
    log_message "Installing msmtp and dependencies"
    apt install -y msmtp-mta ca-certificates bsd-mailx

    # Configure msmtp
    log_message "Configuring msmtp"
    cat <<EOF > /etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile ~/.msmtp.log
EOF
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to write msmtp configuration."
        exit 1
    fi

    # Set proper permissions for msmtp configuration
    log_message "Setting correct permissions for msmtp configuration"
    chown -R www-data:www-data /etc/msmtprc
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to set permissions for /etc/msmtprc."
        exit 1
    fi

    # Run ipserver script
    log_message "Running ipserver script"
    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to run ipserver script."
        exit 1
    fi

    log_message "Backup installation completed successfully."
}

# Fungsi untuk menginstal dan mengonfigurasi swap dan gotop
install_swab() {
    log_message "Starting installation of gotop and swap configuration"

gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v
chronyc tracking -v
wget ${REPO}files/bbr.sh &&  chmod +x bbr.sh && ./bbr.sh
    log_message "Swap and gotop installation completed successfully."
}

# Fungsi untuk menginstal Fail2ban
install_Fail2ban() {
    log_message "Starting Fail2ban installation"

        mkdir -p /usr/local/ddos

    # Menambahkan banner ke ssh dan dropbear
    log_message "Configuring banner for SSH and Dropbear"
    echo "Banner /etc/banner.txt" >> /etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to update Dropbear configuration."
        exit 1
    fi

    # Mengunduh banner untuk SSH dan Dropbear
    log_message "Downloading banner for SSH and Dropbear"
    wget -O /etc/banner.txt "${REPO}banner/lunatic.site"
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to download banner."
        exit 1
    fi

    log_message "Fail2ban installation and configuration completed successfully."
}

# Fungsi untuk menginstal dan mengonfigurasi Epro
install_epro() {
    log_message "Starting installation of ws and associated configurations"

    # Mengunduh file yang diperlukan
    log_message "Downloading ws executable"
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to download ws executable."
        exit 1
    fi

    log_message "Downloading tun.conf configuration"
    wget -O /usr/bin/tun.conf "${REPO}cfg_conf_js/tun.conf" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to download tun.conf."
        exit 1
    fi

    log_message "Downloading ws.service systemd service file"
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to download ws.service."
        exit 1
    fi

    # Menyiapkan file dan memberikan izin yang sesuai
    log_message "Setting file permissions"
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    chmod +x /etc/systemd/system/ws.service

    # Mengelola systemd service ws
    log_message "Configuring systemd service for ws"
    systemctl disable ws
    systemctl stop ws
    systemctl enable ws
    systemctl start ws
    systemctl restart ws

    # Mengunduh geosite dan geoip untuk Xray
    log_message "Downloading geosite.dat and geoip.dat"
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1

    # Mengunduh dan mengonfigurasi ftvpn
    log_message "Downloading and configuring lttunnel"
    wget -O /usr/sbin/ftvpn "${REPO}files/lttunnel" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn

    # Menambahkan aturan iptables untuk memblokir trafik torrent
    log_message "Configuring iptables to block torrent traffic"
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

    # Menyimpan dan me-reload aturan iptables
    log_message "Saving and reloading iptables rules"
    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload

    # Melakukan pembersihan otomatis
    log_message "Cleaning up unnecessary packages"
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1

    log_message "Epro installation and configuration completed successfully."
}

# Fungsi untuk merestart layanan dan melakukan pembersihan
restart_services() {
    log_message "Starting to restart services..."

    # Daftar layanan yang akan direstart
    services=(
        "nginx"
        "openvpn"
        "ssh"
        "dropbear"
        "fail2ban"
        "vnstat"
        "haproxy"
        "cron"
        "xray"
        "rc-local"
        "ws"
    )

    # Melakukan restart untuk setiap layanan
    for service in "${services[@]}"; do
        log_message "Restarting service: $service"
        if systemctl is-active --quiet $service; then
            systemctl restart $service
            log_message "Service $service restarted successfully."
        else
            log_message "Service $service is not active, attempting to start."
            systemctl start $service
            log_message "Service $service started successfully."
        fi
    done

    # Menyusun perintah systemctl untuk enable semua layanan
    log_message "Enabling services to start on boot"
    for service in "${services[@]}"; do
        systemctl enable --now $service
        log_message "Service $service enabled to start on boot."
    done

    # Reloading systemd daemon
    log_message "Reloading systemd daemon"
    systemctl daemon-reload

    # Pembersihan file tidak diperlukan
    log_message "Cleaning up unnecessary files"
    rm -f /root/openvpn /root/key.pem /root/cert.pem

    # Membersihkan riwayat bash dan menonaktifkan pencatatan historinya
    log_message "Clearing bash history"
    history -c
    echo "unset HISTFILE" >> /etc/profile

    log_message "All services restarted and unnecessary files cleaned up successfully."
}

# Fungsi untuk mengunduh dan mengekstrak file
download_and_extract() {
    local url=$1
    local destination=$2
    local file_name=$(basename $url)

    log_message "Downloading $file_name..."
    wget -q $url -O /tmp/$file_name

    if [[ $? -ne 0 ]]; then
        log_message "Failed to download $file_name. Exiting."
        exit 1
    fi

    log_message "Extracting $file_name..."
    unzip -q /tmp/$file_name -d /tmp/

    if [[ $? -ne 0 ]]; then
        log_message "Failed to extract $file_name. Exiting."
        exit 1
    fi

    # Move files to the destination
    log_message "Moving extracted files to $destination..."
    mv /tmp/menu/* $destination

    if [[ $? -ne 0 ]]; then
        log_message "Failed to move files to $destination. Exiting."
        exit 1
    fi

    log_message "Cleaning up temporary files..."
    rm -rf /tmp/menu
    rm -f /tmp/$file_name
}

# Fungsi utama untuk menginstall menu
install_menu() {
    log_message "Starting menu installation..."

    # Install menu shell
    log_message "Installing shell menu..."
    download_and_extract "${REPO}feature/LunatiX2" "/usr/local/sbin"

    # Install menu python
    log_message "Installing Python menu..."
    download_and_extract "${REPO}feature/LunatiX_py" "/usr/bin"

    log_message "Menu installation completed successfully."
}

# Fungsi untuk membuat file .profile untuk root
create_root_profile() {
    log_message "Creating /root/.profile..."

    cat >/root/.profile <<EOF
if [ "\$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
python3 /usr/bin/menu
EOF

    chmod 644 /root/.profile
    log_message "/root/.profile created and permissions set."
}

# Fungsi untuk membuat cron jobs
create_cron_jobs() {
    log_message "Setting up cron jobs..."

    # Create cron jobs for various tasks
    cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

    cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/local/sbin/clearlog
END

    cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

    # Clear logs for nginx and xray every minute
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray

    log_message "Cron jobs created successfully."
}

# Fungsi untuk membuat daily reboot script
create_daily_reboot_script() {
    log_message "Creating daily reboot script..."

    cat >/home/daily_reboot <<-END
5
END

    log_message "Daily reboot script created at /home/daily_reboot."
}

# Fungsi untuk setup rc.local service
setup_rc_local_service() {
    log_message "Setting up rc-local service..."

    cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF

    log_message "rc-local service set up."
}

# Fungsi untuk setup /etc/rc.local
setup_rc_local() {
    log_message "Configuring /etc/rc.local..."

    cat >/etc/rc.local <<EOF
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local
    log_message "/etc/rc.local configured and made executable."
}

# Fungsi untuk handle shell configuration
configure_shells() {
    log_message "Configuring shells..."

    echo "/bin/false" >>/etc/shells
    echo "/usr/sbin/nologin" >>/etc/shells

    log_message "Shells configured."
}

# Fungsi utama untuk melakukan semua konfigurasi
configure_system() {
    log_message "Starting system configuration..."

    create_root_profile
    create_cron_jobs
    create_daily_reboot_script
    setup_rc_local_service
    setup_rc_local
    configure_shells

    log_message "System configuration completed successfully."

    # Handling auto-reboot time configuration
    local AUTOREB=$(cat /home/daily_reboot)
    local SETT=11
    local TIME_DATE=""

    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi

    log_message "Auto reboot set to $TIME_DATE based on current value of daily reboot."
}


function install_udp() {
cd
rm -rf /root/udp
mkdir -p /etc/udp
# change to time GMT+7
echo "change to time GMT+7"
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# install udp-custom
echo downloading udp-custom
wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1ixz82G_ruRBnEEp4vLPNF2KZ1k8UfrkV' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1ixz82G_ruRBnEEp4vLPNF2KZ1k8UfrkV" -O /etc/udp/udp-custom && rm -rf /tmp/cookies.txt
chmod +x /etc/udp/udp-custom

echo downloading default config
wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf" -O /etc/udp/config.json && rm -rf /tmp/cookies.txt
chmod 644 /etc/udp/config.json

if [ -z "$1" ]; then
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/etc/udp/udp-custom server
WorkingDirectory=/etc/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
else
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/etc/udp/udp-custom server -exclude $1
WorkingDirectory=/etc/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
fi
echo start service udp-custom
systemctl start udp-custom &>/dev/null
echo enable service udp-custom
systemctl enable udp-custom &>/dev/null
clear
}

# Fungsi untuk memastikan bahwa service berjalan dengan benar
start_service() {
    local service=$1
    systemctl restart "$service" && log_message "Successfully restarted $service" || log_message "Failed to restart $service"
}

# Fungsi untuk mengaktifkan semua layanan yang diperlukan
enable_services() {
    log_message "Enabling and starting services..."

    # Reload daemon
    systemctl daemon-reload && log_message "Systemd daemon reloaded successfully" || log_message "Failed to reload systemd daemon"
    service cron restart
    # Start and enable services
    systemctl start netfilter-persistent && log_message "netfilter-persistent started" || log_message "Failed to start netfilter-persistent"
    systemctl enable --now rc-local && log_message "rc-local enabled and started" || log_message "Failed to enable rc-local"
    systemctl enable --now cron && log_message "cron enabled and started" || log_message "Failed to enable cron"
    systemctl enable --now netfilter-persistent && log_message "netfilter-persistent enabled" || log_message "Failed to enable netfilter-persistent"
    
    # Restart specific services
    for service in nginx xray haproxy lock-vme lock-vle lock-ssr lock-ssh lock-tro kill-vme kill-vle kill-ssr dropbear nginx  kill-ssh kill-tro; do
        start_service "$service"
    done

    log_message "All services enabled and started."
}

# Fungsi untuk menghapus file dan log yang tidak perlu
clear_all() {
    log_message "Cleaning up temporary and unnecessary files..."

    # Hapus berbagai file dan direktori sementara
    rm -rf /root/menu /root/*.zip /root/*.sh /root/LICENSE /root/README.md /etc/xray/domain /root/LunatiX2 /root/LunatiX_py /root/UDP /root/udp /root/install.log /root/snap /root/nsdomain /root/domain

    # Clear shell history
    history -c && log_message "Shell history cleared" || log_message "Failed to clear shell history"

    # Set hostname
    sudo hostnamectl set-hostname "$username" && log_message "Hostname set to $username" || log_message "Failed to set hostname"

    log_message "Cleanup complete."
}
restart_system() {
USRSC=$(wget -qO- https://raw.githubusercontent.com/${GIT_USER}/vps_access/main/ip | grep $IP_VPS | awk '{print $2}')
EXPSC=$(wget -qO- https://raw.githubusercontent.com/${GIT_USER}/vps_access/main/ip | grep $IP_VPS | awk '{print $3}')
TIMEZONE=$(printf '%(%H:%M:%S)T')
domain=$(cat /etc/xray/domain)
TEXT="
<code>────────────────────</code>
<b> 🟢 NOTIFICATIONS INSTALL 🟢</b>
<code>────────────────────</code>
<code>ID     : </code><code>$USRSC</code>
<code>Domain : </code><code>$domain</code>
<code>Date   : </code><code>$TIME</code>
<code>Time   : </code><code>$TIMEZONE</code>
<code>Ip vps : </code><code>$IP_VPS</code>
<code>Exp Sc : </code><code>$EXPSC</code>
<code>────────────────────</code>
<i>Automatic Notification from Github</i>
"'&reply_markup={"inline_keyboard":[[{"text":"⭐ᴏʀᴅᴇʀ⭐","url":"https://t.me/ian_khvicha"},{"text":"⭐ɪɴꜱᴛᴀʟʟ⭐","url":"https://wa.me/6283189774145"}]]}'
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}

# Main execution
start=$(date +%s)  # Start timestamp for cleanup duration


function install_scripts() {
base_package
nginx_install
install_sslcert
install_haproxy
make_folder_xray
install_password
install_xray
install_badvpn
install_sshd
install_dropbear
install_vnstat
install_openvpn
install_backup
install_swab
install_Fail2ban
install_epro
restart_services
install_menu
configure_system
install_udp
enable_services
clear_all
}


install_scripts

# Fungsi untuk menampilkan pesan sukses
show_success_message() {
    clear
    echo -e "   \e[97;1m ===========================================\e[0m"
    echo -e "   \e[92;1m     Install Succesfully bro! Good Job!     \e[0m"
    echo -e "   \e[97;1m ===========================================\e[0m"
    echo ""
}

# Fungsi untuk menangani pilihan reboot atau menu
handle_user_choice() {
    read -p "$(echo -e "Press ${YELLOW}[y${NC}]${NC} to reboot or ${YELLOW}[t${NC}]${NC} to go to menu: ")" choice
    case "$choice" in
        [Yy]* )
            log_message "Rebooting the system..."
            reboot
            ;;
        [Tt]* )
            log_message "Opening the menu..."
            # Panggil fungsi menu atau ganti dengan perintah lain untuk membuka menu
            menu
            ;;
        * )
            log_message "Invalid choice. Please press 'y' to reboot or 't' to go to the menu."
            handle_user_choice
            ;;
    esac
}

# Menampilkan pesan sukses dan meminta pilihan
show_success_message
handle_user_choice
