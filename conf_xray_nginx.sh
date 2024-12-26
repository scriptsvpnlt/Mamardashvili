#!/bin/bash
clear

    # hapus file lama jika ada
    rm -rf /etc/nginx/nginx.conf
    rm -rf /etc/nginx/conf.d/xray.conf

    # buat dir nginx
    mkdir -p /etc/nginx
    mkdir -p /etc/nginx/conf.d

    # detek os
    OS_UBU=$(lsb_release -is)
    VERSION_UBU=$(lsb_release -rs | cut -d. -f1)    
    echo "Sistem Operasi terdeteksi: ${OS} ${VERSION}"

    # Konfigurasi instalasi HAProxy berdasarkan OS dan versi
    if [[ "$OS_UBU" == "ubuntu" ]]; then
        case $VERSION_UBU in
        "20")
cat >/etc/nginx/conf.d/xray.conf<<-END
server {
    listen 1010 proxy_protocol so_keepalive=on reuseport;
    set_real_ip_from 127.0.0.1;
    real_ip_header  proxy_protocol;
    server_name xxx;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-XSS-Protection "1; mode=block";

    location ~ /vless {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /vless break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10001;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /vmess {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /vmess break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10002;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  } 
    location ~ /trojan-ws {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /trojan-ws break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10003;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /ss-ws {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /ss-ws break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10004;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ / {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /fightertunnelssh break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10015;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
server {
    listen 1012 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;

    location ~ / {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /fightertunnelovpn break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10012;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
server {
    listen 81 ssl http2 reuseport;
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    root /var/www/html;
}
server {
    listen 1013 http2 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;
    location ~ /vless-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10005;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /vmess-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10006;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /trojan-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10007;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /ss-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10008;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
END

echo " install nginx.conf "
cat >/etc/nginx/nginx.conf<<-END
user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;
events {
    worker_connections 1024;
}
http {
    log_format main '[$time_local] $proxy_protocol_addr "$http_user_agent"';
    access_log /var/log/nginx/access.log main;
    set_real_ip_from 127.0.0.1;

    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/xray.conf;
}
END

            ;;
        "24")
cat >/etc/nginx/conf.d/xray.conf<<-END
map $http_upgrade $websocket {
    default 0;
    "WebSocket" 1;
}

server {
    listen 1010 proxy_protocol so_keepalive=on reuseport;
    set_real_ip_from 127.0.0.1;
    real_ip_header  proxy_protocol;
    server_name xxx;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-XSS-Protection "1; mode=block";

    location ~ /vless {
        if ($websocket = 0) {
            rewrite /(.*) /vless break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10001;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /vmess {
        if ($websocket = 0) {
            rewrite /(.*) /vmess break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10002;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /trojan-ws {
        if ($websocket = 0) {
            rewrite /(.*) /trojan-ws break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10003;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /ss-ws {
        if ($websocket = 0) {
            rewrite /(.*) /ss-ws break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10004;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ / {
        if ($websocket = 0) {
            rewrite /(.*) /fightertunnelssh break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10015;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }
}

server {
    listen 1012 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;

    location ~ / {
        if ($websocket = 0) {
            rewrite /(.*) /fightertunnelovpn break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10012;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }
}

server {
    listen 81 ssl http2 reuseport;
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    root /var/www/html;
}

server {
    listen 1013 http2 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;

    location ~ /vless-grpc {
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        grpc_pass grpc://127.0.0.1:10005;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $http_x_forwarded_for;
        grpc_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /vmess-grpc {
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        grpc_pass grpc://127.0.0.1:10006;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $http_x_forwarded_for;
        grpc_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /trojan-grpc {
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        grpc_pass grpc://127.0.0.1:10007;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $http_x_forwarded_for;
        grpc_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /ss-grpc {
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        grpc_pass grpc://127.0.0.1:10008;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $http_x_forwarded_for;
        grpc_set_header X-Forwarded-For $http_x_forwarded_for;
    }
}
END

echo " install nginx.conf "
cat >/etc/nginx/nginx.conf<<-END
user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;
events {
    worker_connections 1024;
}
http {
    log_format main '[$time_local] $proxy_protocol_addr "$http_user_agent"';
    access_log /var/log/nginx/access.log main;
    set_real_ip_from 127.0.0.1;

    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/xray.conf;
}
END

echo " install nginx.conf dan xray.conf sukses "
            ;;
        *)
            echo -e "OS Ubuntu ${VERSION} tidak didukung."
            exit 1
            ;;
        esac

    elif [[ "$OS" == "debian" ]]; then
        case $VERSION in
        "10")
cat >/etc/nginx/conf.d/xray.conf<<-END
server {
    listen 1010 proxy_protocol so_keepalive=on reuseport;
    set_real_ip_from 127.0.0.1;
    real_ip_header  proxy_protocol;
    server_name xxx;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-XSS-Protection "1; mode=block";

    location ~ /vless {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /vless break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10001;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /vmess {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /vmess break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10002;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  } 
    location ~ /trojan-ws {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /trojan-ws break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10003;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /ss-ws {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /ss-ws break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10004;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ / {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /fightertunnelssh break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10015;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
server {
    listen 1012 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;

    location ~ / {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /fightertunnelovpn break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10012;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
server {
    listen 81 ssl http2 reuseport;
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    root /var/www/html;
}
server {
    listen 1013 http2 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;
    location ~ /vless-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10005;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /vmess-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10006;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /trojan-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10007;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /ss-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10008;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
END

echo " install nginx.conf "
cat >/etc/nginx/nginx.conf<<-END
user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;
events {
    worker_connections 1024;
}
http {
    log_format main '[$time_local] $proxy_protocol_addr "$http_user_agent"';
    access_log /var/log/nginx/access.log main;
    set_real_ip_from 127.0.0.1;

    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/xray.conf;
}
END
            ;;
        "11")
cat >/etc/nginx/conf.d/xray.conf<<-END
server {
    listen 1010 proxy_protocol so_keepalive=on reuseport;
    set_real_ip_from 127.0.0.1;
    real_ip_header  proxy_protocol;
    server_name xxx;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-XSS-Protection "1; mode=block";

    location ~ /vless {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /vless break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10001;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /vmess {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /vmess break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10002;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  } 
    location ~ /trojan-ws {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /trojan-ws break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10003;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /ss-ws {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /ss-ws break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10004;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ / {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /fightertunnelssh break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10015;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
server {
    listen 1012 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;

    location ~ / {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /fightertunnelovpn break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10012;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
server {
    listen 81 ssl http2 reuseport;
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    root /var/www/html;
}
server {
    listen 1013 http2 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;
    location ~ /vless-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10005;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /vmess-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10006;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /trojan-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10007;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /ss-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10008;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
END

echo " install nginx.conf "
cat >/etc/nginx/nginx.conf<<-END
user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;
events {
    worker_connections 1024;
}
http {
    log_format main '[$time_local] $proxy_protocol_addr "$http_user_agent"';
    access_log /var/log/nginx/access.log main;
    set_real_ip_from 127.0.0.1;

    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/xray.conf;
}
END
            ;;
        "12")
cat >/etc/nginx/conf.d/xray.conf<<-END
map $http_upgrade $websocket {
    default 0;
    "WebSocket" 1;
}

server {
    listen 1010 proxy_protocol so_keepalive=on reuseport;
    set_real_ip_from 127.0.0.1;
    real_ip_header  proxy_protocol;
    server_name xxx;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-XSS-Protection "1; mode=block";

    location ~ /vless {
        if ($websocket = 0) {
            rewrite /(.*) /vless break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10001;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /vmess {
        if ($websocket = 0) {
            rewrite /(.*) /vmess break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10002;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /trojan-ws {
        if ($websocket = 0) {
            rewrite /(.*) /trojan-ws break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10003;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /ss-ws {
        if ($websocket = 0) {
            rewrite /(.*) /ss-ws break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10004;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ / {
        if ($websocket = 0) {
            rewrite /(.*) /fightertunnelssh break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10015;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }
}

server {
    listen 1012 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;

    location ~ / {
        if ($websocket = 0) {
            rewrite /(.*) /fightertunnelovpn break;
        }
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        proxy_pass http://127.0.0.1:10012;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_forwarded_for;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    }
}

server {
    listen 81 ssl http2 reuseport;
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    root /var/www/html;
}

server {
    listen 1013 http2 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;

    location ~ /vless-grpc {
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        grpc_pass grpc://127.0.0.1:10005;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $http_x_forwarded_for;
        grpc_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /vmess-grpc {
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        grpc_pass grpc://127.0.0.1:10006;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $http_x_forwarded_for;
        grpc_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /trojan-grpc {
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        grpc_pass grpc://127.0.0.1:10007;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $http_x_forwarded_for;
        grpc_set_header X-Forwarded-For $http_x_forwarded_for;
    }

    location ~ /ss-grpc {
        add_header X-HTTP-LEVEL-HEADER 1;
        add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
        add_header X-SERVER-LEVEL-HEADER 1;
        add_header X-LOCATION-LEVEL-HEADER 1;
        grpc_pass grpc://127.0.0.1:10008;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $http_x_forwarded_for;
        grpc_set_header X-Forwarded-For $http_x_forwarded_for;
    }
}
END

echo " install nginx.conf "
cat >/etc/nginx/nginx.conf<<-END
user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;
events {
    worker_connections 1024;
}
http {
    log_format main '[$time_local] $proxy_protocol_addr "$http_user_agent"';
    access_log /var/log/nginx/access.log main;
    set_real_ip_from 127.0.0.1;

    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/xray.conf;
}
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

    echo -e " Restart Nginx & xray & haproxy"

systemctl daemon-reload

systemctl restart nginx
systemctl restart haproxy
systemctl restart xray