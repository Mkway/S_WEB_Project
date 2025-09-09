#!/bin/bash
# Redis Cache Injection 테스트를 위한 초기 데이터 설정

echo "🔄 Redis Cache Injection 테스트 환경 초기화 중..."

# Redis에 연결하고 초기 데이터 설정
redis-cli << 'EOF'
# 사용자 세션 캐시
HSET user:1001 username "admin" role "administrator" session_token "abc123xyz" last_login "2024-01-15"
HSET user:1002 username "testuser" role "user" session_token "def456uvw" last_login "2024-01-14"
HSET user:1003 username "guest" role "guest" session_token "ghi789rst" last_login "2024-01-13"

# 제품 캐시 데이터
HSET product:101 name "Laptop" price "999.99" category "Electronics" stock "50"
HSET product:102 name "Phone" price "599.99" category "Electronics" stock "100" 
HSET product:103 name "Book" price "19.99" category "Education" stock "200"

# API 응답 캐시
SET api:weather:seoul '{"temperature": 15, "humidity": 60, "status": "cloudy"}'
SET api:news:latest '{"title": "Breaking News", "content": "Important update", "timestamp": "2024-01-15T10:30:00Z"}'

# 구성 설정 캐시
HSET config:app debug_mode "false" max_users "1000" maintenance_mode "false"
HSET config:security login_attempts "3" session_timeout "1800" encryption_key "secret_key_123"

# 통계 캐시
SET stats:daily_users "1250"
SET stats:total_orders "5678"
SET stats:revenue "89012.45"

# 임시 토큰 (TTL 설정)
SETEX temp_token:reset_123 3600 "user:1001"
SETEX temp_token:verification_456 1800 "user:1002"

# 블랙리스트 IP
SADD blacklist:ips "192.168.1.100" "10.0.0.50" "172.16.0.200"

# 화이트리스트 도메인
SADD whitelist:domains "example.com" "trusted-site.org" "secure.test"

echo "✅ Redis 초기 데이터 설정 완료!"
echo "📊 설정된 데이터:"
echo "   - 사용자 세션: 3개"
echo "   - 제품 정보: 3개"  
echo "   - API 응답 캐시: 2개"
echo "   - 설정 정보: 보안/앱 설정"
echo "   - 통계 데이터: 일일/총합 통계"
echo "   - 임시 토큰: TTL 설정"
echo "   - IP 블랙/화이트리스트"

EOF

echo "🚀 Redis Cache Injection 테스트 환경 준비 완료!"