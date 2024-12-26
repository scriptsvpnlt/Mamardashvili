#!/bin/bash

# Warna dan format
Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"

# Variabel lain
TIME=$(date '+%d %b %Y')
ipsaya=$(wget -qO- ipinfo.io/ip)

# Data Telegram
CHATID="5970831071"
KEY="7633327456:AAGE7JpWbJyVly-fcQ8B3S1ctqq-qYOM"
URL="https://api.telegram.org/bot$KEY/sendMessage"

# Repositori
REPO="https://raw.githubusercontent.com/scriptsvpnlt/Mamardashvili/main/"

# Persiapan direktori
mkdir -p /etc/xray
mkdir -p /var/lib/LT
mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log

# Fungsi validasi OS
function check_os() {
    OS=$(lsb_release -is)
    VERSION=$(lsb_release -rs | cut -d. -f1)

    if [[ "$OS" == "Ubuntu" && "$VERSION" =~ ^(20|22|24)$ ]] || \
       [[ "$OS" == "Debian" && "$VERSION" =~ ^(10|11|12)$ ]]; then
        echo -e "${OK} OS Supported: $OS $VERSION"
    else
        echo -e "${ERROR} OS Not Supported: $OS $VERSION"
        echo -e "${YELLOW}This script only supports Ubuntu 20/22/24 and Debian 10/11/12.${FONT}"
        exit 1
    fi
}

# Fungsi memasang domain
function pasang_domain() {
    clear
    echo -e "   \e[97;1m ===========================================\e[0m"
    echo -e "   \e[1;32m    Please Select a Domain below type.      \e[0m"
    echo -e "   \e[97;1m ===========================================\e[0m"
    echo -e "   \e[1;32m  1). \e[97;1m Domain Pribadi \e[0m"
    echo -e "   \e[1;32m  2). \e[97;1m Domain Random  \e[0m"
    echo -e "   \e[97;1m ===========================================\e[0m"
    echo -e ""
    read -p "   Just Input a number [1-2]:   " host
    echo ""
    if [[ $host == "1" ]]; then
        clear
        echo -e "   \e[97;1m ===========================================\e[0m"
        echo -e "   \e[97;1m             INPUT YOUR DOMAIN              \e[0m"
        echo -e "   \e[97;1m ===========================================\e[0m"
        echo -e ""
        read -p "   Input your domain :   " host1

        if [[ -z "$host1" ]]; then
            echo -e "${ERROR} Domain cannot be empty!"
            exit 1
        fi

        echo "$host1" > /etc/xray/domain
        echo "$host1" > /root/domain
        echo "IP=$host1" > /var/lib/LT/ipvps.conf
        echo -e "${OK} Domain saved: $host1"
    elif [[ $host == "2" ]]; then
        wget ${REPO}files/cf.sh -O /root/cf.sh
        chmod +x /root/cf.sh
        ./root/cf.sh
        rm -f /root/cf.sh
    else
        echo -e "${ERROR} Invalid selection. Exiting."
        exit 1
    fi
}

# Fungsi utama instalasi
function main() {
    echo -e "${OK} Checking OS compatibility..."
    check_os

    echo -e "${OK} Updating system packages..."
    apt update -y && apt upgrade -y

    echo -e "${OK} Installing dependencies..."
    apt install -y curl wondershaper lsb-release jq curl wget

    echo -e "${OK} Setting up directories..."
    chmod +x /var/log/xray
    chmod +x /etc/xray

    echo -e "${OK} Configuring domain..."
    pasang_domain

    echo -e "${OK} Setup completed successfully!"
}

# Jalankan fungsi utama
main

# Menyimpan alamat IP VPS dari icanhazip.com
Ip_Vps=$(curl -sS ipv4.icanhazip.com)
clear

# Mengecek apakah skrip dijalankan dengan hak akses root
if [ "${EUID}" -ne 0 ]; then
    echo -e "\e[92;1m Checking root user \e[0m"
    exit 1
fi

# Mengecek apakah VPS menggunakan OpenVZ
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# Warna teks untuk output terminal
RED='\e[1;31m'
GREEN='\e[0;32m'
NC='\e[0m'  # No color

# Mendapatkan username dan tanggal expired dari GitHub
username=$(curl -s https://raw.githubusercontent.com/scriptsvpnlt/vps_access/main/ip | grep "$Ip_Vps" | awk '{print $2}')
echo "$username" > /usr/bin/user

expx=$(curl -s https://raw.githubusercontent.com/scriptsvpnlt/vps_access/main/ip | grep "$Ip_Vps" | awk '{print $3}')
echo "$expx" > /usr/bin/e

# Mendapatkan username dan expired date
username=$(cat /usr/bin/user)
oid=$(cat /usr/bin/ver)
exp=$(cat /usr/bin/e)
clear

# Menghitung selisih tanggal untuk menentukan masa berlaku
d1=$(date -d "$exp" +%s)
d2=$(date -d "$(date +"%Y-%m-%d")" +%s)
certifacate=$(((d1 - d2) / 86400))

# Fungsi untuk menghitung dan menampilkan perbedaan tanggal
datediff() {
    d1=$(date -d "$1" +%s)
    d2=$(date -d "$2" +%s)
    echo -e "$COLOR1 $NC Expiry In : $(((d1 - d2) / 86400)) Days"
}

# Menentukan status apakah expired atau aktif
today=$(date -d "0 days" +"%Y-%m-%d")
Exp1=$(curl -s https://raw.githubusercontent.com/scriptsvpnlt/vps_access/main/ip | grep "$Ip_Vps" | awk '{print $4}')
if [[ "$today" < "$Exp1" ]]; then
    sts="${GREEN}Active${NC}"
else
    sts="${RED}Expired${NC}"
fi

# Menampilkan status dan waktu installasi
echo -e "\e[32mloading...\e[0m"
clear
start=$(date +%s)

# Fungsi untuk mengubah detik ke format waktu
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

# Fungsi untuk menampilkan pesan sukses
function print_ok() {
    echo -e "${GREEN} ${1} ${NC}"
}

# Fungsi untuk menampilkan pesan instalasi
function print_install() {
    echo -e "${GREEN} ==================================== ${NC}"
    echo -e "${YELLOW} # $1 ${NC}"
    echo -e "${GREEN} ==================================== ${NC}"
    sleep 1
}

# Fungsi untuk menampilkan pesan error
function print_error() {
    echo -e "${RED} ${1} ${NC}"
}

# Fungsi untuk menampilkan pesan sukses ketika instalasi berhasil
function print_success() {
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN} ==================================== ${NC}"
        echo -e "${GREEN} # $1 berhasil dipasang ${NC}"
        echo -e "${GREEN} ==================================== ${NC}"
    fi
}

# Fungsi untuk mengecek apakah script dijalankan oleh root
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
    fi
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


function first_setup() {
mkdir -p /etc/haproxy
 
    # Atur zona waktu
    timedatectl set-timezone Asia/Jakarta

    # Konfigurasi iptables-persistent
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # Buat direktori jika diperlukan
    echo "Membuat direktori untuk Xray..."
    mkdir -p /etc/xray
    mkdir -p /var/lib/LT
    
    # install haproxy.cfg
    wget "${REPO}cfg_haproxy.sh"
    bash cfg_haproxy.sh
    rm -rf /root/cfg_haproxy.sh
    
    # Identifikasi OS dan versinya
    OS=$(grep -w ID /etc/os-release | cut -d= -f2 | tr -d '"')
    VERSION=$(grep -w VERSION_ID /etc/os-release | cut -d= -f2 | tr -d '"')
    
    # Haproxy Versi Ubuntu
    FocalVersi="2.0" # Ubuntu 20.04 FOCAL FOSSA
    JammyVersi="2.4" # Ubuntu 22.04 JAMMY JELLYFISH
    NobleVersi="2.9" # Ubuntu 24.04 NOBLE NUMBAT
    OracularVersi="2.9.9" # Ubuntu 24.10 Oracular Oriole
    
        
    echo "Sistem Operasi terdeteksi: ${OS} ${VERSION}"

    # Update dan instal dependensi dasar
    apt update -y
    apt upgrade -y
    apt install --no-install-recommends software-properties-common -y

    # Konfigurasi instalasi HAProxy berdasarkan OS dan versi
    if [[ "$OS" == "ubuntu" ]]; then
        case $VERSION in
        "20.04")
            echo " install haproxy versi ${FocalVersi} untuk Ubuntu 20.04"
            add-apt-repository ppa:vbernat/haproxy-${FocalVersi} -yes
            sudo apt update
            apt-get install haproxy=${FocalVersi}.\* -y
            ;;
        "22.04")
            echo " install haproxy versi ${JammyVersi} untuk Ubuntu 22.04"
            sudo add-apt-repository ppa:vbernat/haproxy-${JammyVersi} --yes
            sudo apt update
            apt-get install haproxy=${JammyVersi}.\* -y
            ;;            
        "24.04" | "24.04.1")
            echo " install haproxy versi ${NobleVersi} untuk Ubuntu 24.04"
            sudo add-apt-repository ppa:vbernat/haproxy-${NobleVersi} --yes
            sudo apt update
            apt-get install haproxy=${NobleVersi}.\* -y
            ;;
        "24.10")
            echo " install haproxy versi ${OracularVersi} untuk Ubuntu 24.10"
            sudo add-apt-repository ppa:vbernat/haproxy-${OracularVersi} --yes
            sudo apt update
            apt-get install haproxy=${OracularVersi}\* -y
            ;;            
        *)
            echo -e "OS Ubuntu ${VERSION} tidak didukung."
            exit 1
            ;;
        esac

    elif [[ "$OS" == "debian" ]]; then
        case $VERSION in
        "10")
            echo "Menambahkan repository untuk Debian 10 (Buster)..."
            curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
            echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net buster-backports-2.0 main" >/etc/apt/sources.list.d/haproxy.list
            apt-get update
            apt-get install haproxy=2.0.\* -y
            ;;
        "11")
            echo "Menambahkan repository untuk Debian 11 (Bullseye)..."
            curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
            echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bullseye-backports-2.4 main" >/etc/apt/sources.list.d/haproxy.list
            apt-get update
            apt-get install haproxy=2.4.\* -y
            ;;
        "12")
            echo "Menambahkan repository untuk Debian 12 (Bookworm)..."
            curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
            echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bookworm-backports-2.6 main" >/etc/apt/sources.list.d/haproxy.list
            apt-get update
            apt-get install haproxy=2.6.\* -y
            ;;
        *)
            echo -e "OS Debian ${VERSION} tidak didukung."
            exit 1
            ;;
        esac

    else
        echo -e "Sistem Operasi Anda (${OS}) tidak didukung."
        exit 1
    fi

    echo -e "Instalasi selesai untuk ${OS} ${VERSION}."
}

clear

function base_package() {
    clear
    echo -e "\033[1;32m[INFO]\033[0m Menginstall Paket yang Dibutuhkan..."
    
    # restart 
    restart_paket() {
        # Konfigurasi tambahan
    systemctl enable chronyd
    systemctl restart chronyd
    systemctl enable chrony
    systemctl restart chrony
    chronyc sourcestats -v
    chronyc tracking -v
    ntpdate pool.ntp.org
    sudo apt-get clean all
    sudo apt-get autoremove -y
    }
   
    # Periksa OS dan versi
    OS=$(lsb_release -is)
    VERSION=$(lsb_release -rs | cut -d. -f1)

    # Paket khusus berdasarkan versi OS
    if [[ "$OS" == "Debian" ]]; then
        case $VERSION in
        10)
            echo -e "\033[1;32m[INFO]\033[0m Debian 10 detected. Installing additional packages..."
        apt install zip pwgen openssl netcat socat cron bash-completion -y
        apt install figlet -y
        apt update -y
        apt upgrade -y
        apt install bmon -y
        apt dist-upgrade -y
        apt install nginx -y
        systemctl enable chronyd
        systemctl restart chronyd
        systemctl enable chrony
        systemctl restart chrony
        chronyc sourcestats -v
        chronyc tracking -v
        apt install ntpdate -y
        ntpdate pool.ntp.org
        apt install sudo -y
        sudo apt-get clean all
        sudo apt-get autoremove -y
        sudo apt-get install -y debconf-utils
        sudo apt-get remove --purge exim4 -y
        sudo apt-get remove --purge ufw firewalld -y
        sudo apt-get install -y --no-install-recommends software-properties-common
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa
        restart_paket
            ;;
        11)
            echo -e "\033[1;32m[INFO]\033[0m Debian 11 detected. Installing additional packages..."
        apt install -y python-is-python3
        apt install zip pwgen openssl netcat socat cron bash-completion -y
        apt install figlet -y
        apt update -y
        apt upgrade -y
        apt install bmon -y
        apt dist-upgrade -y
        apt install nginx -y        
        systemctl enable chronyd
        systemctl restart chronyd
        systemctl enable chrony
        systemctl restart chrony
        chronyc sourcestats -v
        chronyc tracking -v
        apt install ntpdate -y
        ntpdate pool.ntp.org
        apt install sudo -y
        sudo apt-get clean all
        sudo apt-get autoremove -y
        sudo apt-get install -y debconf-utils
        sudo apt-get remove --purge exim4 -y
        sudo apt-get remove --purge ufw firewalld -y
        sudo apt-get install -y --no-install-recommends software-properties-common
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa            
        
        restart_paket
            ;;
        12)
            echo -e "\033[1;32m[INFO]\033[0m Debian 12 detected. Installing additional packages..."
            apt install -y python3-venv
            ;;
        esac
    elif [[ "$OS" == "Ubuntu" ]]; then
        case $VERSION in
        20)
            echo -e "\033[1;32m[INFO]\033[0m Ubuntu 20.04 detected. Installing additional packages..."
        apt install zip pwgen openssl netcat socat cron bash-completion -y
        apt install figlet -y
        apt update -y
        apt upgrade -y
        apt install bmon -y
        apt dist-upgrade -y
        apt install nginx -y        
        systemctl enable chronyd
        systemctl restart chronyd
        systemctl enable chrony
        systemctl restart chrony
        chronyc sourcestats -v
        chronyc tracking -v
        apt install ntpdate -y
        ntpdate pool.ntp.org
        apt install sudo -y
        sudo apt-get clean all
        sudo apt-get autoremove -y
        sudo apt-get install -y debconf-utils
        sudo apt-get remove --purge exim4 -y
        sudo apt-get remove --purge ufw firewalld -y
        sudo apt-get install -y --no-install-recommends software-properties-common
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa            
        restart_paket
            ;;
        22)
            echo -e "\033[1;32m[INFO]\033[0m Ubuntu 22.04 detected. Installing additional packages..."
        apt update -y
        apt upgrade -y        
        apt install -y zip pwgen openssl netcat socat cron bash-completion \
        figlet bmon ntpdate sudo debconf-utils iptables-persistent \
        speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
        libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev \
        flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix \
        zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl \
        build-essential gcc g++ python htop lsof sudo tar wget curl ruby zip unzip \
        p7zip-full python3-pip libc6 util-linux msmtp-mta ca-certificates \
        bsd-mailx iptables iptables-persistent netfilter-persistent net-tools \
        openssl gnupg gnupg2 python3-venv lsb-release shc make cmake git screen socat \
        xz-utils apt-transport-https gnupg1 dnsutils ntpdate chrony jq \
        openvpn easy-rsa
        apt-get install openvpn -y
        apt-get install nginx -y        
        sudo apt-get install -y --no-install-recommends software-properties-common
        
        # echo iptables
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        
        # paket restart
        restart_paket
            ;;
        24)
            echo -e "\033[1;32m[INFO]\033[0m Ubuntu 24.04 detected. Installing additional packages..."
                # Dependencies ubuntu 24.04
    apt update -y
    apt install -y zip pwgen openssl netcat socat cron bash-completion \
        figlet bmon ntpdate sudo debconf-utils iptables-persistent \
        speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
        libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev \
        flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix \
        zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl \
        build-essential gcc g++ python htop lsof sudo tar wget curl ruby zip unzip \
        p7zip-full python3-pip libc6 util-linux msmtp-mta ca-certificates \
        bsd-mailx iptables iptables-persistent netfilter-persistent net-tools \
        openssl gnupg gnupg2 lsb-release shc make cmake git screen socat \
        xz-utils apt-transport-https gnupg1 dnsutils ntpdate chrony jq \
        openvpn easy-rsa
        sudo apt-get install -y --no-install-recommends software-properties-common
        apt-get install openvpn -y 
        apt-get install nginx -y                      
        # echo iptables
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        
        # paket restart
        restart_paket        
            ;;
        esac
    else
        echo -e "\033[1;31m[ERROR]\033[0m Unsupported OS: $OS $VERSION"
        exit 1
    fi

    # print sukses
    echo -e "\033[1;32m[INFO]\033[0m Semua paket yang dibutuhkan telah diinstal."
}

function pasang_ssl() {
    clear
    print_install "Memasang Sertifikat SSL Pada Domain"

    # Hapus file SSL lama
    rm -rf /etc/xray/xray.key /etc/xray/xray.crt

    # Ambil nama domain dari file
    domain=$(cat /root/domain)

    # Hentikan server web yang berjalan di port 80
    STOPWEBSERVER=$(lsof -i:80 | awk 'NR==2 {print $1}')
    systemctl stop $STOPWEBSERVER
    systemctl stop nginx

    # Siapkan direktori acme.sh
    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    # Unduh acme.sh dan beri izin eksekusi
    curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh

    # Perbarui acme.sh dan tetapkan Let's Encrypt sebagai server CA
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # Terbitkan sertifikat SSL menggunakan metode standalone
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256

    # Pasang sertifikat SSL
    /root/.acme.sh/acme.sh --installcert -d $domain \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key \
        --ecc

    # Atur izin untuk file kunci
    chmod 777 /etc/xray/xray.key

    # Tampilkan pesan sukses
    print_success "SSL Certificate telah berhasil dipasang"
}

clear
function restart_system() {
    # Mendapatkan informasi IP dan Expiry dari sumber yang sudah ditentukan
    local USRSC=$(wget -qO- https://raw.githubusercontent.com/scriptsvpnlt/vps_access/main/ip | grep "$ipsaya" | awk '{print $2}')
    local EXPSC=$(wget -qO- https://raw.githubusercontent.com/scriptsvpnlt/vps_access/main/ip | grep "$ipsaya" | awk '{print $3}')

    # Mendapatkan timezone dan domain
    local TIMEZONE=$(printf '%(%H:%M:%S)T')
    local domain=$(cat /root/domain)

    # Menyusun pesan yang akan dikirim melalui Telegram
    local TEXT="
<code>────────────────────</code>
<b> 🟢 NOTIFICATIONS INSTALL 🟢</b>
<code>────────────────────</code>
<code>ID     : </code><code>$USRSC</code>
<code>Domain : </code><code>$domain</code>
<code>Date   : </code><code>$TIME</code>
<code>Time   : </code><code>$TIMEZONE</code>
<code>Ip vps : </code><code>$ipsaya</code>
<code>Exp Sc : </code><code>$EXPSC</code>
<code>────────────────────</code>
<i>Automatic Notification from Github</i>
"'&reply_markup={"inline_keyboard":[[{"text":"⭐ᴏʀᴅᴇʀ⭐","url":"https://t.me/ian_khvicha"},{"text":"⭐ɪɴꜱᴛᴀʟʟ⭐","url":"https://wa.me/6283189774145"}]]}'

    # Mengirim pesan ke Telegram
    curl -s --max-time "$TIMES" -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" "$URL" >/dev/null
}


function make_folder_xray() {
    # Hapus database lama jika ada
    rm -rf /etc/lunatic/vmess/.vmess.db
    rm -rf /etc/lunatic/vless/.vless.db
    rm -rf /etc/lunatic/trojan/.trojan.db
    rm -rf /etc/lunatic/ssh/.ssh.db
    rm -rf /etc/lunatic/bot/.bot.db

    # Buat struktur direktori utama
    mkdir -p /etc/lunatic
    mkdir -p /etc/limit
    mkdir -p /usr/bin/xray
    mkdir -p /var/log/xray
    mkdir -p /var/www/html
    mkdir -p /usr/sbin/local

    # Buat direktori layanan dan subdirektorinya
    for service in vmess vless trojan ssh; do
        mkdir -p /etc/lunatic/$service/ip
        mkdir -p /etc/lunatic/$service/detail
        mkdir -p /etc/lunatic/$service/usage
    done

    # Buat direktori khusus untuk bot
    mkdir -p /etc/lunatic/bot
    mkdir -p /etc/lunatic/bot/notif

    # Beri izin eksekusi untuk log xray
    chmod +x /var/log/xray

    # Buat file penting
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log

    # Buat file database untuk masing-masing layanan
    for service in vmess vless trojan ssh; do
        touch /etc/lunatic/$service/.$service.db
        echo "& plugin Account" >> /etc/lunatic/$service/.$service.db
    done

    # Buat file untuk bot
    touch /etc/lunatic/bot/.bot.db
    touch /etc/lunatic/bot/notif/key
    touch /etc/lunatic/bot/notif/id

    # Tambahkan plugin ke database bot
    echo "& plugin Account" >> /etc/lunatic/bot/.bot.db
}

function install_xray() {
    clear

    # Get IP and domain info
    domain=$(< /root/domain)
    IPVS=$(< /etc/xray/ipvps)
    print_install "Core Xray 1.8.1 Latest Version"
    
    # Adjust directory path to /run/xray
    domainSock_dir="/run/xray"; ! [ -d $domainSock_dir ] && mkdir $domainSock_dir
    chown www-data:www-data $domainSock_dir
    
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version

    wget "${REPO}conf_xray_nginx.sh && bash conf_xray_nginx.sh && rm -rf conf_xray_nginx.sh" >/dev/null 2>&1
    wget -O /etc/xray/config.json "${REPO}cfg_conf_js/config.json" >/dev/null 2>&1
    print_success "Core Xray 1.8.1 Latest Version"
    clear
    
    curl -s ipinfo.io/city >> /etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /etc/xray/isp

    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf

    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem
    chmod +x /etc/systemd/system/run_xray.service
    rm -rf /etc/systemd/system/xray.service.d

    # Xray service configuration
    cat >/etc/systemd/system/xray.service <<EOF
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
[Install]
WantedBy=multi-user.target
EOF

    # Run_xray service configuration
    cat >/etc/systemd/system/run_xray.service <<-END
[Unit]
Description=Automatically Start Xray
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/mkdir -p /run/xray
ExecStartPre=-/usr/bin/chown www-data:www-data /run/xray
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

    print_success "Konfigurasi Paket"
}

function ssh(){
clear
print_install "Memasang Password SSH"
mkdir -p /etc/pam.d
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

cat > /etc/rc.local<<-END
exit 0
END

chmod +x /etc/rc.local

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

systemctl enable rc-local
systemctl start rc-local.service
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "Password SSH"
}
function udp_mini() {
    clear
    print_install "Installing Service Limit Quota"
    
    # Mengunduh dan mengeksekusi script limit-quota
    wget -q https://raw.githubusercontent.com/scriptsvpnlt/Mamardashvili/main/files/limit-quota.sh -O /root/limit-quota.sh
    chmod +x /root/limit-quota.sh
    /root/limit-quota.sh

    print_install "Installing Locked xray Service"
    
    # Mengunduh dan mengeksekusi script lock-service
    wget -q https://raw.githubusercontent.com/scriptsvpnlt/Mamardashvili/main/lock-service.sh -O /root/lock-service.sh
    chmod +x /root/lock-service.sh
    /root/lock-service.sh

    # Mengonfigurasi limit-ip
    mkdir -p /usr/bin/limit-ip
    wget -q -O /usr/bin/limit-ip "${REPO}files/limit-ip"
    chmod +x /usr/bin/limit-ip

    # Menghapus karakter carriage return yang mungkin ada
    sed -i 's/\r//' /usr/bin/limit-ip

    # Membuat dan mengonfigurasi service untuk limit-ip
    configure_systemd_service "vmip"
    configure_systemd_service "vlip"
    configure_systemd_service "trip"
    configure_systemd_service "ssip"

    # Menginstal dan mengonfigurasi udp-mini
    mkdir -p /usr/lunatic/
    wget -q -O /usr/lunatic/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/lunatic/udp-mini

    # Mengunduh dan mengonfigurasi service udp-mini
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"

    # Mengelola dan memulai udp-mini services
    manage_udp_mini_service "udp-mini-1"
    manage_udp_mini_service "udp-mini-2"
    manage_udp_mini_service "udp-mini-3"

    print_success "Quota Service Files Installed"
}

# Fungsi untuk mengonfigurasi service systemd
function configure_systemd_service() {
    local service_name=$1
    cat > /etc/systemd/system/${service_name}.service <<EOF
[Unit]
Description=Limit IP ${service_name}
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip ${service_name}
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd, restart dan enable service
    systemctl daemon-reload
    systemctl restart ${service_name}
    systemctl enable ${service_name}
}

# Fungsi untuk mengelola udp-mini service
function manage_udp_mini_service() {
    local service_name=$1
    systemctl disable ${service_name}
    systemctl stop ${service_name}
    systemctl enable ${service_name}
    systemctl start ${service_name}
}



function ins_SSHD() {
    clear
    print_install "Installing SSHD"

    # Mengunduh file konfigurasi SSHD dan menyimpannya ke direktori yang tepat
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1

    # Menetapkan izin yang aman untuk file konfigurasi
    chmod 700 /etc/ssh/sshd_config

    # Merestart layanan SSH dan memeriksa statusnya
    /etc/init.d/ssh restart
    systemctl restart ssh

    # Memastikan layanan SSH berjalan dengan baik
    /etc/init.d/ssh status

    # Menampilkan pesan sukses setelah instalasi selesai
    print_success "SSHD Installed Successfully"
}


function ins_dropbear() {
    clear
    print_install "Installing Dropbear"

    # Instalasi Dropbear
    apt-get install dropbear -y > /dev/null 2>&1

    # Mengunduh dan menimpa file konfigurasi Dropbear
    wget -q -O /etc/default/dropbear "${REPO}cfg_conf_js/dropbear.conf"

    # Memberikan izin eksekusi pada file konfigurasi
    chmod +x /etc/default/dropbear

    # Restart layanan Dropbear dan memeriksa statusnya
    /etc/init.d/dropbear restart
    /etc/init.d/dropbear status

    # Menampilkan pesan sukses setelah instalasi
    print_success "Dropbear Installed Successfully"
}



function ins_vnstat(){
clear
print_install "Menginstall Vnstat"
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
print_success "Vnstat"
}

function ins_openvpn() {
    clear
    print_install "Installing OpenVPN"

    # Mengunduh skrip OpenVPN dan memberi izin eksekusi
    wget -q "${REPO}ovpn/openvpn" -O /tmp/openvpn.sh
    chmod +x /tmp/openvpn.sh

    # Menjalankan skrip untuk menginstal OpenVPN
    /tmp/openvpn.sh

    # Restart layanan OpenVPN untuk memastikan konfigurasi diterapkan
    /etc/init.d/openvpn restart

    # Menampilkan pesan sukses setelah instalasi
    print_success "OpenVPN Installed Successfully"
    
    # Menghapus file skrip sementara setelah instalasi selesai
    rm -f /tmp/openvpn.sh
}



function ins_backup() {
    clear
    print_install "Installing Backup Server"

    # Instalasi rclone dan konfigurasi
    apt install rclone -y

    # Otomatis konfigurasi rclone dengan memberikan 'q' untuk keluar
    printf "q\n" | rclone config

    # Mengunduh konfigurasi rclone dari repositori
    wget -O /root/.config/rclone/rclone.conf "${REPO}cfg_conf_js/rclone.conf"

    # Instalasi Wondershaper untuk pengelolaan bandwidth
    cd /bin || exit
    git clone https://github.com/LunaticTunnel/wondershaper.git
    cd wondershaper || exit
    sudo make install
    cd || exit
    rm -rf wondershaper

    # Membuat file kosong untuk penggunaan berikutnya
    echo > /home/files

    # Instalasi msmtp dan dependensi
    apt install msmtp-mta ca-certificates bsd-mailx -y

    # Mengonfigurasi msmtp untuk menggunakan SMTP Gmail
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

    # Mengatur hak akses file msmtprc agar dapat diakses oleh pengguna yang tepat
    chown -R www-data:www-data /etc/msmtprc

    # Mengunduh dan menjalankan skrip untuk mengonfigurasi server IP
    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver

    # Menampilkan pesan sukses setelah instalasi
    print_success "Backup Server Installed Successfully"
}



function ins_swap() {
    clear
    print_install "Installing 1GB Swap and Gotop"

    # Mendapatkan versi terbaru dari Gotop di GitHub
    local gotop_latest
    gotop_latest=$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)
    
    # Menentukan URL untuk mengunduh file Gotop terbaru
    local gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v$gotop_latest_linux_amd64.deb"
    
    # Mengunduh dan memasang Gotop
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1

    # Membuat swap 1GB
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile

    # Mengaktifkan swap
    swapon /swapfile

    # Menambahkan entri swap ke /etc/fstab
    echo '/swapfile      swap swap   defaults    0 0' >> /etc/fstab

    # Sinkronisasi waktu dengan server NTP
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v

    # Mengunduh dan menjalankan skrip BBR
    wget "${REPO}files/bbr.sh" -O /tmp/bbr.sh
    chmod +x /tmp/bbr.sh
    /tmp/bbr.sh

    # Menampilkan pesan sukses
    print_success "1GB Swap and Gotop Installed Successfully"
}

function ins_Fail2ban() {
    clear
    print_install "Installing Fail2ban"

    # Pastikan direktori ddos belum ada, jika ada tampilkan peringatan dan hentikan eksekusi
    if [ -d '/usr/local/ddos' ]; then
        echo "Please uninstall the previous version of ddos first."
        exit 1
    else
        # Buat direktori ddos jika tidak ada
        mkdir -p /usr/local/ddos
    fi

    clear

    # Menambahkan banner ke konfigurasi SSH
    echo "Banner /etc/banner.txt" >> /etc/ssh/sshd_config

    # Mengatur banner untuk Dropbear
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear

    # Unduh banner dari repositori
    wget -O /etc/banner.txt "${REPO}banner/lunatic.site" >/dev/null 2>&1

    # Menampilkan pesan sukses
    print_success "Fail2ban and Banner Setup Completed Successfully"
}

function ins_epro() {
    clear
    print_install "Menginstall ePro WebSocket Proxy"

    # URL repository
    local ws_url="${REPO}files/ws"
    local tun_conf_url="${REPO}cfg_conf_js/tun.conf"
    local ws_service_url="${REPO}files/ws.service"
    local geosite_url="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    local geoip_url="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    local lttunnel_url="${REPO}files/lttunnel"

    # Unduh file utama
    wget -q -O /usr/bin/ws "$ws_url"
    wget -q -O /usr/bin/tun.conf "$tun_conf_url"
    wget -q -O /etc/systemd/system/ws.service "$ws_service_url"

    # Atur izin file
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf

    # Konfigurasi layanan ws
    systemctl disable ws >/dev/null 2>&1
    systemctl stop ws >/dev/null 2>&1
    systemctl enable ws >/dev/null 2>&1
    systemctl start ws >/dev/null 2>&1
    systemctl restart ws >/dev/null 2>&1

    # Unduh file geo untuk Xray
    wget -q -O /usr/local/share/xray/geosite.dat "$geosite_url"
    wget -q -O /usr/local/share/xray/geoip.dat "$geoip_url"

    # Unduh dan atur layanan tambahan
    wget -q -O /usr/sbin/ftvpn "$lttunnel_url"
    chmod +x /usr/sbin/ftvpn
    chmod +x /usr/sbin/lttunnel

    # Atur aturan firewall menggunakan iptables
    local block_strings=(
        "get_peers" "announce_peer" "find_node"
        "BitTorrent" "BitTorrent protocol" "peer_id="
        ".torrent" "announce.php?passkey=" "torrent"
        "announce" "info_hash"
    )

    for string in "${block_strings[@]}"; do
        iptables -A FORWARD -m string --string "$string" --algo bm -j DROP
    done

    # Simpan aturan iptables
    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save >/dev/null 2>&1
    netfilter-persistent reload >/dev/null 2>&1

    # Bersihkan paket yang tidak diperlukan
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1

    # Tampilkan pesan sukses
    print_success "ePro WebSocket Proxy berhasil diinstal"
}

function ins_restart() {
    clear
    print_install "Restarting All Services and Configurations"

    # Restart layanan menggunakan init.d
    for service in nginx openvpn ssh dropbear fail2ban vnstat cron; do
        /etc/init.d/$service restart >/dev/null 2>&1
    done

    # Restart layanan menggunakan systemd
    systemctl restart haproxy >/dev/null 2>&1
    systemctl daemon-reload >/dev/null 2>&1
    systemctl start netfilter-persistent >/dev/null 2>&1

    # Aktifkan dan mulai layanan dengan systemd
    local services=(nginx xray rc-local dropbear openvpn cron haproxy netfilter-persistent ws fail2ban)
    for service in "${services[@]}"; do
        systemctl enable --now $service >/dev/null 2>&1
    done

    # Hapus riwayat shell untuk keamanan
    history -c
    echo "unset HISTFILE" >> /etc/profile

    # Hapus file sementara di root
    rm -f /root/openvpn /root/key.pem /root/cert.pem

    # Tampilkan pesan sukses
    print_success "All Services Restarted and Configured Successfully"
}

function menu(){
clear
print_install "Memasang Menu Packet"

# install menu shell
wget ${REPO}feature/LunatiX2
unzip LunatiX2
chmod +x menu/*
mv menu/* /usr/local/sbin
rm -rf menu

# install menu py
wget ${REPO}feature/LunatiX_py
unzip LunatiX_py
chmod +x menu/*
mv menu/* /usr/bin
rm -rf menu
}

function profile() {
    # Konfigurasi file .profile untuk menjalankan menu
    cat >/root/.profile <<EOF
if [ "\$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
python3 /usr/bin/menu
EOF

    # Atur cron job untuk mengelola berbagai tugas
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

    chmod 644 /root/.profile

    cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

    # Buat cron job untuk membersihkan log
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >/etc/cron.d/log.xray

    # Restart layanan cron
    service cron restart >/dev/null 2>&1

    # Atur waktu reboot harian
    cat >/home/daily_reboot <<-END
5
END

    # Tambahkan shell non-login untuk keamanan
    echo "/bin/false" >>/etc/shells
    echo "/usr/sbin/nologin" >>/etc/shells

    # Konfigurasi file rc.local untuk iptables dan aturan NAT
    cat >/etc/rc.local <<EOF
#!/bin/sh -e
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    # Pastikan rc.local dapat dieksekusi
    chmod +x /etc/rc.local

    # Tentukan format waktu (AM/PM) untuk reboot otomatis
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ \$AUTOREB -gt \$SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi

    # Tampilkan pesan sukses
    print_success "Profile Configured Successfully"
}

function enable_services() {
    clear
    print_install "Enabling and Starting Services"

    # Reload systemd daemon to ensure changes are applied
    systemctl daemon-reload

    # Start and enable essential services
    local services=(netfilter-persistent rc-local cron)
    for service in "${services[@]}"; do
        systemctl enable --now $service >/dev/null 2>&1
    done

    # Restart critical services
    local restart_services=(nginx xray cron haproxy openvpn)
    for service in "${restart_services[@]}"; do
        systemctl restart $service >/dev/null 2>&1
    done

    # Display success message
    print_success "All Services Enabled and Restarted Successfully"
    clear
}

function clear_all() {
    # Bersihkan riwayat terminal
    history -c

    # Hapus file dan direktori sementara di direktori root
    local files_to_remove=(
        "/root/menu"
        "/root/*.zip"
        "/root/*.sh"
        "/root/LICENSE"
        "/root/README.md"
        "/root/domain"
        "/root/LunatiX2"
        "/root/LunatiX_py"
        "/root/snap"
    )
    for file in "${files_to_remove[@]}"; do
        rm -rf $file
    done

    # Hitung waktu eksekusi dan konversikan ke format manusia
    local elapsed_time=$(($(date +%s) - ${start}))
    secs_to_human "$elapsed_time"

    # Atur hostname ke nilai yang diberikan
    sudo hostnamectl set-hostname "$username"

    # Tampilkan pesan sukses
    print_success "System Cleaned and Hostname Updated Successfully"
}
function all_res() {
systemctl restart nginx
systemctl restart haproxy
systemctl restart xray
systemctl restart run_xray
systemctl restart ws
systemctl restart openvpn
systemctl restart ssh
systemctl restart rc-local
systemctl restart dropbear
}

function install_scripts() {
base_package
first_setup
nginx_install
make_folder_xray
password_default
pasang_ssl
install_xray
ssh
udp_mini
ssh_slow
ins_SSHD
ins_dropbear
ins_vnstat
ins_openvpn
ins_backup
ins_swab
ins_Fail2ban
ins_epro
ins_restart
menu
profile
enable_services
restart_system
clear_all
}


install_scripts

clear
echo -e ""
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e "   \e[92;1m     Install Succesfully bro! Good Job!     \e[0m"
echo -e "   \e[97;1m ===========================================\e[0m"
echo ""
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} TO REBOOT") "
reboot
