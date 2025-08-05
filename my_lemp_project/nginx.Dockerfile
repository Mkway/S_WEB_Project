FROM nginx:stable-alpine

# SSL 인증서 생성 스크립트 복사
COPY nginx/generate-ssl.sh /usr/local/bin/generate-ssl.sh
RUN chmod +x /usr/local/bin/generate-ssl.sh

# OpenSSL 설치 (Alpine에서 기본으로 포함되어 있음)
RUN apk add --no-cache openssl

# 기본 entrypoint를 재정의
COPY nginx/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]