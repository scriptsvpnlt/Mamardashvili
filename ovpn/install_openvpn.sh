#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
OS=$(uname -m)
MYIP=$(wget -qO- ipinfo.io/ip)
domain=$(cat /root/domain || echo "$MYIP")
MYIP2="s/xxxxxxxxx/$domain/g"

function ovpn_install() {
    echo "Menghapus direktori OpenVPN lama dan membuat direktori baru..."
    rm -rf /etc/openvpn
    mkdir -p /etc/openvpn
    echo "Mengunduh file konfigurasi VPN..."
    wget -O /etc/openvpn/vpn.zip "https://raw.githubusercontent.com/scriptsvpnlt/Mamardashvili/main/ovpn/vpn.zip" >/dev/null 2>&1
    echo "Ekstrak file konfigurasi..."
    unzip -d /etc/openvpn/ /etc/openvpn/vpn.zip
    rm -f /etc/openvpn/vpn.zip
    chown -R root:root /etc/openvpn/server/easy-rsa/
}

function config_easy() {
    echo "Menyiapkan plugin PAM untuk OpenVPN..."
    mkdir -p /usr/lib/openvpn/
    cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so
    sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn
    echo "Mengaktifkan layanan OpenVPN..."
    systemctl enable --now openvpn-server@server-tcp
    systemctl enable --now openvpn-server@server-udp
    systemctl restart openvpn
}

function make_follow() {
    echo "Mengaktifkan IP forwarding..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

    echo "Membuat konfigurasi klien OpenVPN..."
    for proto in tcp udp; do
        cat > /etc/openvpn/${proto}.ovpn <<-END
client
dev tun
proto ${proto}
remote xxxxxxxxx 1194
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
        sed -i $MYIP2 /etc/openvpn/${proto}.ovpn
    done
}

function cert_ovpn() {
    echo "Menambahkan sertifikat CA ke file konfigurasi klien..."
    for proto in tcp udp; do
        echo '<ca>' >> /etc/openvpn/${proto}.ovpn
        cat /etc/openvpn/server/ca.crt >> /etc/openvpn/${proto}.ovpn
        echo '</ca>' >> /etc/openvpn/${proto}.ovpn
        cp /etc/openvpn/${proto}.ovpn /var/www/html/${proto}.ovpn
    done

    echo "Membuat arsip konfigurasi klien..."
    cd /var/www/html/
    zip ovpn-config.zip tcp.ovpn udp.ovpn >/dev/null 2>&1
    cd
}

function install_ovpn() {
    ovpn_install
    config_easy
    make_follow
    cert_ovpn
    echo "Memulai ulang layanan OpenVPN..."
    systemctl enable openvpn
    systemctl start openvpn
    systemctl restart openvpn
}

# Jalankan instalasi
install_ovpn
