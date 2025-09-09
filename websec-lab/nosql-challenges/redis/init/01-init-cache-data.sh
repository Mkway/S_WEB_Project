#!/bin/bash
# Redis 초기 데이터 설정 스크립트
# 보안 테스트용 캐시 데이터 및 세션 생성

# Redis 서버가 시작될 때까지 대기
sleep 5

# Redis CLI로 초기 데이터 설정
redis-cli <<EOF

# 1. 사용자 세션 데이터 (Session Hijacking 테스트용)
SET "session:admin_123" "{\"user_id\":1,\"username\":\"admin\",\"role\":\"administrator\",\"login_time\":\"$(date -Iseconds)\"}"
SET "session:user1_456" "{\"user_id\":2,\"username\":\"user1\",\"role\":\"user\",\"login_time\":\"$(date -Iseconds)\"}"
SET "session:guest_789" "{\"user_id\":3,\"username\":\"guest\",\"role\":\"guest\",\"login_time\":\"$(date -Iseconds)\"}"

# 세션 만료 시간 설정 (3600초 = 1시간)
EXPIRE "session:admin_123" 3600
EXPIRE "session:user1_456" 3600
EXPIRE "session:guest_789" 3600

# 2. 제품 캐시 데이터 (Cache Poisoning 테스트용)
SET "product:1" "{\"id\":1,\"name\":\"Laptop Computer\",\"price\":1299.99,\"stock\":50}"
SET "product:2" "{\"id\":2,\"name\":\"Smartphone\",\"price\":899.99,\"stock\":100}"
SET "product:3" "{\"id\":3,\"name\":\"Programming Book\",\"price\":49.99,\"stock\":25}"

# 제품 캐시 만료 시간 설정 (1800초 = 30분)
EXPIRE "product:1" 1800
EXPIRE "product:2" 1800
EXPIRE "product:3" 1800

# 3. 사용자 프로필 캐시 (데이터 조작 테스트용)
SET "user:1:profile" "{\"id\":1,\"name\":\"Administrator\",\"email\":\"admin@example.com\",\"premium\":true}"
SET "user:2:profile" "{\"id\":2,\"name\":\"Regular User\",\"email\":\"user1@example.com\",\"premium\":false}"
SET "user:3:profile" "{\"id\":3,\"name\":\"Guest User\",\"email\":\"guest@example.com\",\"premium\":false}"

# 4. API 응답 캐시 (Cache Injection 테스트용)
SET "api:users:all" "[{\"id\":1,\"name\":\"admin\"},{\"id\":2,\"name\":\"user1\"},{\"id\":3,\"name\":\"guest\"}]"
SET "api:products:category:electronics" "[{\"id\":1,\"name\":\"Laptop\"},{\"id\":2,\"name\":\"Smartphone\"}]"
SET "api:stats:daily" "{\"visits\":1250,\"orders\":45,\"revenue\":2345.67}"

# 5. 설정값 캐시 (Configuration Injection 테스트용)
SET "config:app:maintenance" "false"
SET "config:app:debug_mode" "false"
SET "config:app:max_upload_size" "10485760"

# 6. 카운터 및 통계 (Rate Limiting 우회 테스트용)
SET "counter:login:admin" "0"
SET "counter:api:user:1" "0"
SET "counter:failed_login:192.168.1.100" "0"

# 7. 임시 토큰 및 인증 데이터 (Token Injection 테스트용)
SET "token:reset:admin" "abc123def456"
SET "token:verification:user1@example.com" "xyz789uvw012"
SET "token:api:temp:12345" "{\"user_id\":1,\"permissions\":[\"read\",\"write\"],\"expires\":$(date -d '+1 hour' +%s)}"

# 토큰 만료 시간 설정
EXPIRE "token:reset:admin" 900
EXPIRE "token:verification:user1@example.com" 1800
EXPIRE "token:api:temp:12345" 3600

# 8. 큐 데이터 (Command Injection 테스트용)
LPUSH "queue:notifications" "{\"user_id\":1,\"message\":\"Welcome to the system\"}"
LPUSH "queue:notifications" "{\"user_id\":2,\"message\":\"Your order has been processed\"}"
LPUSH "queue:emails" "{\"to\":\"admin@example.com\",\"subject\":\"System Alert\",\"body\":\"Test message\"}"

# 9. 정렬된 세트 (Sorted Set Injection 테스트용)
ZADD "leaderboard:points" 1500 "admin"
ZADD "leaderboard:points" 850 "user1"
ZADD "leaderboard:points" 200 "guest"

ZADD "recent:logins" $(date +%s) "admin"
ZADD "recent:logins" $(($(date +%s) - 300)) "user1"
ZADD "recent:logins" $(($(date +%s) - 600)) "guest"

# 10. 해시 데이터 (Hash Injection 테스트용)
HSET "user:1:settings" "theme" "dark"
HSET "user:1:settings" "language" "ko"
HSET "user:1:settings" "notifications" "enabled"

HSET "user:2:settings" "theme" "light"
HSET "user:2:settings" "language" "en"
HSET "user:2:settings" "notifications" "disabled"

# 초기화 완료 메시지
ECHO "Redis 보안 테스트 데이터 초기화 완료!"

EOF

echo "Redis 초기 데이터 설정이 완료되었습니다."