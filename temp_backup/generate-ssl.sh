#!/bin/bash

SSL_DIR="/etc/nginx/ssl"
CERT_FILE="${SSL_DIR}/nginx.crt"
KEY_FILE="${SSL_DIR}/nginx.key"

# SSL 디렉토리 생성
mkdir -p $SSL_DIR

# SSL 인증서가 없거나 손상된 경우 새로 생성
if [[ ! -f "$CERT_FILE" ]] || [[ ! -f "$KEY_FILE" ]] || ! openssl x509 -in "$CERT_FILE" -noout 2>/dev/null || ! openssl rsa -in "$KEY_FILE" -check -noout 2>/dev/null; then
    echo "Generating new SSL certificate..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -subj "/C=KR/ST=Seoul/L=Seoul/O=Development/OU=IT/CN=localhost" \
        2>/dev/null
    
    # 파일 권한 설정
    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"
    
    echo "SSL certificate generated successfully"
else
    # 인증서와 키 파일이 일치하는지 확인
    CERT_MODULUS=$(openssl x509 -noout -modulus -in "$CERT_FILE" 2>/dev/null | openssl md5)
    KEY_MODULUS=$(openssl rsa -noout -modulus -in "$KEY_FILE" 2>/dev/null | openssl md5)
    
    if [[ "$CERT_MODULUS" != "$KEY_MODULUS" ]]; then
        echo "SSL certificate and key mismatch. Regenerating..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$KEY_FILE" \
            -out "$CERT_FILE" \
            -subj "/C=KR/ST=Seoul/L=Seoul/O=Development/OU=IT/CN=localhost" \
            2>/dev/null
        
        chmod 600 "$KEY_FILE"
        chmod 644 "$CERT_FILE"
        
        echo "SSL certificate regenerated successfully"
    else
        echo "SSL certificate is valid"
    fi
fi

# nginx 시작
exec "$@"