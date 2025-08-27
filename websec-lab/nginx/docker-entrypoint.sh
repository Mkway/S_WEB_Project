#!/bin/sh

# SSL 인증서 생성
/usr/local/bin/generate-ssl.sh

# 원래 nginx entrypoint 실행
exec /docker-entrypoint.sh "$@"