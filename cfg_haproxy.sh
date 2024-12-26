#!/bin/bash

clear
rm -rf /etc/haproxy/haproxy.cfg
mkdir -p /etc/haproxy
    OS_UBU=$(lsb_release -is)
    VERSION_UBU=$(lsb_release -rs | cut -d. -f1)    
    if [[ "$OS_UBU" == "ubuntu" ]]; then
        case $VERSION_UBU in
        "20")
cat >/etc/haproxy/haproxy.cfg<<-END
global       
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 1d

    
    tune.h2.initial-window-size 2147483647
    tune.ssl.default-dh-param 2048

    pidfile /run/haproxy.pid
    chroot /var/lib/haproxy

    user haproxy
    group haproxy
    daemon

    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

defaults
    log global
    mode tcp
    option dontlognull
    timeout connect 200ms
    timeout client  300s
    timeout server  300s
    
frontend multiport
    mode tcp
    bind-process 1 2
    bind *:222-1000 tfo
    tcp-request inspect-delay 500ms
    tcp-request content accept if HTTP
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend recir_http if HTTP 
    default_backend recir_https

frontend multiports
    mode tcp
    bind abns@haproxy-http accept-proxy tfo
    default_backend recir_https_www

frontend ssl
    mode tcp
    bind-process 1
    bind *:80 tfo
    bind *:55 tfo
    bind *:8080 tfo 
    bind *:8880 tfo
    bind *:2095 tfo
    bind *:2082 tfo
    bind *:2086 tfo
    bind *:2095 tfo
    bind abns@haproxy-https accept-proxy ssl crt /etc/haproxy/hap.pem alpn h2,http/1.1 tfo
    
    tcp-request inspect-delay 500ms
    tcp-request content capture req.ssl_sni len 100
    tcp-request content accept if { req.ssl_hello_type 1 }

    acl chk-02_up hdr(Connection) -i upgrade
    acl chk-02_ws hdr(Upgrade) -i websocket
    acl this_payload payload(0,7) -m bin 5353482d322e30
    acl up-to ssl_fc_alpn -i h2

    use_backend GRUP_FTVPN if up-to
    use_backend FTVPN if chk-02_up chk-02_ws 
    use_backend FTVPN if { path_reg -i ^\/(.*) }
    use_backend BOT_FTVPN if this_payload
    default_backend CHANNEL_FTVPN

backend recir_https_www
    mode tcp
    server misssv-bau 127.0.0.1:2223 check
     
backend FTVPN
    mode http
    server hencet-bau 127.0.0.1:1010 send-proxy check 

backend GRUP_FTVPN
    mode tcp
    server hencet-baus 127.0.0.1:1013 send-proxy check
    
backend CHANNEL_FTVPN
    mode tcp
    balance roundrobin
    server nonok-bau 127.0.0.1:1194 check
    server memek-bau 127.0.0.1:1012 send-proxy check

backend BOT_FTVPN
    mode tcp
    server misv-bau 127.0.0.1:2222 check
    
backend recir_http
    mode tcp
    server loopback-for-http abns@haproxy-http send-proxy-v2 check
    
backend recir_https
    mode tcp
    server loopback-for-https abns@haproxy-https send-proxy-v2 check
END
        ;;
        "22")
cat >/etc/haproxy/haproxy.cfg<<-END
global       
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 1d

    
    tune.h2.initial-window-size 2147483647
    tune.ssl.default-dh-param 2048

    pidfile /run/haproxy.pid
    chroot /var/lib/haproxy

    user haproxy
    group haproxy
    daemon

    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

defaults
    log global
    mode tcp
    option dontlognull
    timeout connect 200ms
    timeout client  300s
    timeout server  300s
    
frontend multiport
    mode tcp
    bind-process 1 2
    bind *:222-1000 tfo
    tcp-request inspect-delay 500ms
    tcp-request content accept if HTTP
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend recir_http if HTTP 
    default_backend recir_https

frontend multiports
    mode tcp
    bind abns@haproxy-http accept-proxy tfo
    default_backend recir_https_www

frontend ssl
    mode tcp
    bind-process 1
    bind *:80 tfo
    bind *:55 tfo
    bind *:8080 tfo 
    bind *:8880 tfo
    bind *:2095 tfo
    bind *:2082 tfo
    bind *:2086 tfo
    bind *:2095 tfo
    bind abns@haproxy-https accept-proxy ssl crt /etc/haproxy/hap.pem alpn h2,http/1.1 tfo
    
    tcp-request inspect-delay 500ms
    tcp-request content capture req.ssl_sni len 100
    tcp-request content accept if { req.ssl_hello_type 1 }

    acl chk-02_up hdr(Connection) -i upgrade
    acl chk-02_ws hdr(Upgrade) -i websocket
    acl this_payload payload(0,7) -m bin 5353482d322e30
    acl up-to ssl_fc_alpn -i h2

    use_backend GRUP_FTVPN if up-to
    use_backend FTVPN if chk-02_up chk-02_ws 
    use_backend FTVPN if { path_reg -i ^\/(.*) }
    use_backend BOT_FTVPN if this_payload
    default_backend CHANNEL_FTVPN

backend recir_https_www
    mode tcp
    server misssv-bau 127.0.0.1:2223 check
     
backend FTVPN
    mode http
    server hencet-bau 127.0.0.1:1010 send-proxy check 

backend GRUP_FTVPN
    mode tcp
    server hencet-baus 127.0.0.1:1013 send-proxy check
    
backend CHANNEL_FTVPN
    mode tcp
    balance roundrobin
    server nonok-bau 127.0.0.1:1194 check
    server memek-bau 127.0.0.1:1012 send-proxy check

backend BOT_FTVPN
    mode tcp
    server misv-bau 127.0.0.1:2222 check
    
backend recir_http
    mode tcp
    server loopback-for-http abns@haproxy-http send-proxy-v2 check
    
backend recir_https
    mode tcp
    server loopback-for-https abns@haproxy-https send-proxy-v2 check
END
        ;;
        "24")
cat >/etc/haproxy/haproxy.cfg<<-END
global
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 1d
    
    tune.h2.initial-window-size 2147483647
    tune.ssl.default-dh-param 2048

    pidfile /run/haproxy.pid
    chroot /var/lib/haproxy

    user haproxy
    group haproxy
    daemon

    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

defaults
    log global
    mode tcp
    option dontlognull
    timeout connect 200ms
    timeout client  300s
    timeout server  300s

frontend multiport
    mode tcp
    bind *:222-1000 tfo
    tcp-request inspect-delay 500ms
    tcp-request content accept if HTTP
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend recir_http if HTTP 
    default_backend recir_https

frontend multiports
    mode tcp
    bind abns@haproxy-http accept-proxy tfo
    default_backend recir_https_www

frontend ssl
    mode tcp
    bind *:80 tfo
    bind *:55 tfo
    bind *:8080 tfo 
    bind *:8880 tfo
    bind *:2095 tfo
    bind *:2082 tfo
    bind *:2086 tfo
    bind abns@haproxy-https accept-proxy ssl crt /etc/haproxy/hap.pem alpn h2,http/1.1 tfo
    
    tcp-request inspect-delay 500ms
    tcp-request content capture req.ssl_sni len 100
    tcp-request content accept if { req.ssl_hello_type 1 }

    acl chk-02_up hdr(Connection) -i upgrade
    acl chk-02_ws hdr(Upgrade) -i websocket
    acl this_payload payload(0,7) -m bin 5353482d322e30
    acl up-to ssl_fc_alpn -i h2

    use_backend GRUP_FTVPN if up-to
    use_backend FTVPN if chk-02_up chk-02_ws 
    use_backend FTVPN if { path_reg -i ^\/(.*) }
    use_backend BOT_FTVPN if this_payload
    default_backend CHANNEL_FTVPN

backend recir_https_www
    mode tcp
    server misssv-bau 127.0.0.1:2223 check
     
backend FTVPN
    mode http
    server hencet-bau 127.0.0.1:1010 send-proxy check 

backend GRUP_FTVPN
    mode tcp
    server hencet-baus 127.0.0.1:1013 send-proxy check
    
backend CHANNEL_FTVPN
    mode tcp
    balance roundrobin
    server nonok-bau 127.0.0.1:1194 check
    server memek-bau 127.0.0.1:1012 send-proxy check

backend BOT_FTVPN
    mode tcp
    server misv-bau 127.0.0.1:2222 check
    
backend recir_http
    mode tcp
    server loopback-for-http abns@haproxy-http send-proxy-v2 check
    
backend recir_https
    mode tcp
    server loopback-for-https abns@haproxy-https send-proxy-v2 check
END
        ;;
       *) exit ;;
      esac
      
      elif [[ "$OS" == "debian" ]]; then
           case $VERSION in
        "10")
cat >/etc/haproxy/haproxy.cfg<<-END
global       
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 1d

    
    tune.h2.initial-window-size 2147483647
    tune.ssl.default-dh-param 2048

    pidfile /run/haproxy.pid
    chroot /var/lib/haproxy

    user haproxy
    group haproxy
    daemon

    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

defaults
    log global
    mode tcp
    option dontlognull
    timeout connect 200ms
    timeout client  300s
    timeout server  300s
    
frontend multiport
    mode tcp
    bind-process 1 2
    bind *:222-1000 tfo
    tcp-request inspect-delay 500ms
    tcp-request content accept if HTTP
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend recir_http if HTTP 
    default_backend recir_https

frontend multiports
    mode tcp
    bind abns@haproxy-http accept-proxy tfo
    default_backend recir_https_www

frontend ssl
    mode tcp
    bind-process 1
    bind *:80 tfo
    bind *:55 tfo
    bind *:8080 tfo 
    bind *:8880 tfo
    bind *:2095 tfo
    bind *:2082 tfo
    bind *:2086 tfo
    bind *:2095 tfo
    bind abns@haproxy-https accept-proxy ssl crt /etc/haproxy/hap.pem alpn h2,http/1.1 tfo
    
    tcp-request inspect-delay 500ms
    tcp-request content capture req.ssl_sni len 100
    tcp-request content accept if { req.ssl_hello_type 1 }

    acl chk-02_up hdr(Connection) -i upgrade
    acl chk-02_ws hdr(Upgrade) -i websocket
    acl this_payload payload(0,7) -m bin 5353482d322e30
    acl up-to ssl_fc_alpn -i h2

    use_backend GRUP_FTVPN if up-to
    use_backend FTVPN if chk-02_up chk-02_ws 
    use_backend FTVPN if { path_reg -i ^\/(.*) }
    use_backend BOT_FTVPN if this_payload
    default_backend CHANNEL_FTVPN

backend recir_https_www
    mode tcp
    server misssv-bau 127.0.0.1:2223 check
     
backend FTVPN
    mode http
    server hencet-bau 127.0.0.1:1010 send-proxy check 

backend GRUP_FTVPN
    mode tcp
    server hencet-baus 127.0.0.1:1013 send-proxy check
    
backend CHANNEL_FTVPN
    mode tcp
    balance roundrobin
    server nonok-bau 127.0.0.1:1194 check
    server memek-bau 127.0.0.1:1012 send-proxy check

backend BOT_FTVPN
    mode tcp
    server misv-bau 127.0.0.1:2222 check
    
backend recir_http
    mode tcp
    server loopback-for-http abns@haproxy-http send-proxy-v2 check
    
backend recir_https
    mode tcp
    server loopback-for-https abns@haproxy-https send-proxy-v2 check
END
            ;;
        "11")
cat >/etc/haproxy/haproxy.cfg<<-END
global       
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 1d

    
    tune.h2.initial-window-size 2147483647
    tune.ssl.default-dh-param 2048

    pidfile /run/haproxy.pid
    chroot /var/lib/haproxy

    user haproxy
    group haproxy
    daemon

    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

defaults
    log global
    mode tcp
    option dontlognull
    timeout connect 200ms
    timeout client  300s
    timeout server  300s
    
frontend multiport
    mode tcp
    bind-process 1 2
    bind *:222-1000 tfo
    tcp-request inspect-delay 500ms
    tcp-request content accept if HTTP
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend recir_http if HTTP 
    default_backend recir_https

frontend multiports
    mode tcp
    bind abns@haproxy-http accept-proxy tfo
    default_backend recir_https_www

frontend ssl
    mode tcp
    bind-process 1
    bind *:80 tfo
    bind *:55 tfo
    bind *:8080 tfo 
    bind *:8880 tfo
    bind *:2095 tfo
    bind *:2082 tfo
    bind *:2086 tfo
    bind *:2095 tfo
    bind abns@haproxy-https accept-proxy ssl crt /etc/haproxy/hap.pem alpn h2,http/1.1 tfo
    
    tcp-request inspect-delay 500ms
    tcp-request content capture req.ssl_sni len 100
    tcp-request content accept if { req.ssl_hello_type 1 }

    acl chk-02_up hdr(Connection) -i upgrade
    acl chk-02_ws hdr(Upgrade) -i websocket
    acl this_payload payload(0,7) -m bin 5353482d322e30
    acl up-to ssl_fc_alpn -i h2

    use_backend GRUP_FTVPN if up-to
    use_backend FTVPN if chk-02_up chk-02_ws 
    use_backend FTVPN if { path_reg -i ^\/(.*) }
    use_backend BOT_FTVPN if this_payload
    default_backend CHANNEL_FTVPN

backend recir_https_www
    mode tcp
    server misssv-bau 127.0.0.1:2223 check
     
backend FTVPN
    mode http
    server hencet-bau 127.0.0.1:1010 send-proxy check 

backend GRUP_FTVPN
    mode tcp
    server hencet-baus 127.0.0.1:1013 send-proxy check
    
backend CHANNEL_FTVPN
    mode tcp
    balance roundrobin
    server nonok-bau 127.0.0.1:1194 check
    server memek-bau 127.0.0.1:1012 send-proxy check

backend BOT_FTVPN
    mode tcp
    server misv-bau 127.0.0.1:2222 check
    
backend recir_http
    mode tcp
    server loopback-for-http abns@haproxy-http send-proxy-v2 check
    
backend recir_https
    mode tcp
    server loopback-for-https abns@haproxy-https send-proxy-v2 check
END
            ;;
        "12")
cat >/etc/haproxy/haproxy.cfg<<-END
global
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 1d
    
    tune.h2.initial-window-size 2147483647
    tune.ssl.default-dh-param 2048

    pidfile /run/haproxy.pid
    chroot /var/lib/haproxy

    user haproxy
    group haproxy
    daemon

    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

defaults
    log global
    mode tcp
    option dontlognull
    timeout connect 200ms
    timeout client  300s
    timeout server  300s

frontend multiport
    mode tcp
    bind *:222-1000 tfo
    tcp-request inspect-delay 500ms
    tcp-request content accept if HTTP
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend recir_http if HTTP 
    default_backend recir_https

frontend multiports
    mode tcp
    bind abns@haproxy-http accept-proxy tfo
    default_backend recir_https_www

frontend ssl
    mode tcp
    bind *:80 tfo
    bind *:55 tfo
    bind *:8080 tfo 
    bind *:8880 tfo
    bind *:2095 tfo
    bind *:2082 tfo
    bind *:2086 tfo
    bind abns@haproxy-https accept-proxy ssl crt /etc/haproxy/hap.pem alpn h2,http/1.1 tfo
    
    tcp-request inspect-delay 500ms
    tcp-request content capture req.ssl_sni len 100
    tcp-request content accept if { req.ssl_hello_type 1 }

    acl chk-02_up hdr(Connection) -i upgrade
    acl chk-02_ws hdr(Upgrade) -i websocket
    acl this_payload payload(0,7) -m bin 5353482d322e30
    acl up-to ssl_fc_alpn -i h2

    use_backend GRUP_FTVPN if up-to
    use_backend FTVPN if chk-02_up chk-02_ws 
    use_backend FTVPN if { path_reg -i ^\/(.*) }
    use_backend BOT_FTVPN if this_payload
    default_backend CHANNEL_FTVPN

backend recir_https_www
    mode tcp
    server misssv-bau 127.0.0.1:2223 check
     
backend FTVPN
    mode http
    server hencet-bau 127.0.0.1:1010 send-proxy check 

backend GRUP_FTVPN
    mode tcp
    server hencet-baus 127.0.0.1:1013 send-proxy check
    
backend CHANNEL_FTVPN
    mode tcp
    balance roundrobin
    server nonok-bau 127.0.0.1:1194 check
    server memek-bau 127.0.0.1:1012 send-proxy check

backend BOT_FTVPN
    mode tcp
    server misv-bau 127.0.0.1:2222 check
    
backend recir_http
    mode tcp
    server loopback-for-http abns@haproxy-http send-proxy-v2 check
    
backend recir_https
    mode tcp
    server loopback-for-https abns@haproxy-https send-proxy-v2 check
END
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
    cd
        