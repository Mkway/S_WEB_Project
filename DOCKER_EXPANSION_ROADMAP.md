# 🐳 S_WEB_Project Docker 환경 확장 로드맵

**목표**: 다중 데이터베이스 및 Node.js 보안 테스트 환경 구축  
**버전**: v2.0 (Docker Multi-Service Architecture)  
**예상 기간**: 4-6주  

## 🎯 **확장 목표**

### 현재 상태 (v1.0)
```
LEMP Stack: Nginx + PHP + MariaDB + Node.js(기본)
보안 모듈: 62개 (PHP 기반)
```

### 목표 상태 (v2.0)  
```
Multi-Service: Nginx + PHP + MariaDB + PostgreSQL + MongoDB + Redis + Node.js(보안)
보안 모듈: 100+ (다중 언어 지원)
실시간 실행: JavaScript/Node.js 코드 즉시 실행 및 결과 확인
```

## 📋 **Docker 확장 계획**

### 🗄️ **1단계: 다중 데이터베이스 환경**

#### PostgreSQL 추가
```yaml
# docker-compose.yml 확장
postgres:
  image: postgres:15
  container_name: security_postgres
  environment:
    POSTGRES_MULTIPLE_DATABASES: "security_test,vuln_db"
    POSTGRES_USER: test_user
    POSTGRES_PASSWORD: test_pass
  ports:
    - "5432:5432"
  volumes:
    - ./sql-challenges/postgres/init:/docker-entrypoint-initdb.d
    - postgres_data:/var/lib/postgresql/data
  networks:
    - security_network
```

#### MongoDB 추가
```yaml
mongodb:
  image: mongo:7
  container_name: security_mongo
  environment:
    MONGO_INITDB_ROOT_USERNAME: admin
    MONGO_INITDB_ROOT_PASSWORD: admin123
  ports:
    - "27017:27017"
  volumes:
    - ./nosql-challenges/mongo:/docker-entrypoint-initdb.d
    - mongodb_data:/data/db
  networks:
    - security_network
```

#### Redis 추가
```yaml
redis:
  image: redis:7-alpine
  container_name: security_redis
  ports:
    - "6379:6379"
  volumes:
    - ./redis-challenges/redis.conf:/usr/local/etc/redis/redis.conf
    - redis_data:/data
  command: redis-server /usr/local/etc/redis/redis.conf
  networks:
    - security_network
```

### 🟢 **2단계: Node.js 보안 테스트 환경**

#### Node.js 보안 컨테이너
```yaml
nodejs_security:
  build: 
    context: ./nodejs-security
    dockerfile: Dockerfile
  container_name: security_nodejs
  ports:
    - "3001:3001"  # REST API
    - "3002:3002"  # WebSocket
  environment:
    - NODE_ENV=security_testing
    - MAX_EXECUTION_TIME=5000
    - MAX_MEMORY_USAGE=128MB
  volumes:
    - ./nodejs-modules:/app/modules
    - ./js-challenges:/app/challenges
  depends_on:
    - postgres
    - mongodb
    - redis
  networks:
    - security_network
```

#### Node.js Dockerfile
```dockerfile
FROM node:18-alpine

# 보안 사용자 생성
RUN addgroup -g 1001 -S nodejs && \
    adduser -S security -u 1001

WORKDIR /app

# 패키지 설치
COPY package*.json ./
RUN npm ci --only=production && \
    npm install vm2 ws express && \
    npm cache clean --force

# 애플리케이션 복사
COPY --chown=security:nodejs . .
USER security

EXPOSE 3001 3002
CMD ["node", "security-server.js"]
```

### 🔧 **3단계: 네트워크 및 보안 설정**

#### 보안 네트워크 구성
```yaml
networks:
  security_network:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 172.20.0.0/16
          gateway: 172.20.0.1

  frontend_network:
    driver: bridge
    internal: false

  backend_network:
    driver: bridge
    internal: true
```

#### 볼륨 관리
```yaml
volumes:
  postgres_data:
    driver: local
  mongodb_data:
    driver: local
  redis_data:
    driver: local
  uploads_data:
    driver: local
```

## 🛠️ **구현 TODO**

### ✅ **Week 1: PostgreSQL 환경**
- [ ] PostgreSQL 컨테이너 docker-compose.yml에 추가
- [ ] PostgreSQL 초기화 스크립트 작성 (`/sql-challenges/postgres/init/`)
- [ ] PL/pgSQL 인젝션 테스트 데이터 구성
- [ ] PHP PostgreSQL PDO 연결 클래스 구현

### ✅ **Week 2: MongoDB 환경**
- [ ] MongoDB 컨테이너 설정 및 초기 데이터 구성
- [ ] NoSQL 인젝션 테스트 컬렉션 생성
- [ ] PHP MongoDB 드라이버 설치 및 연결 클래스
- [ ] MongoDB Operator Injection 테스트 모듈

### ✅ **Week 3: Redis & Node.js 기반**
- [ ] Redis 컨테이너 및 설정 파일 구성
- [ ] Node.js 보안 테스트 컨테이너 Dockerfile 작성
- [ ] VM2 기반 안전한 JavaScript 실행 환경 구축
- [ ] WebSocket 실시간 통신 서버 구현

### ✅ **Week 4: 통합 및 보안 모듈**
- [ ] JavaScript/Node.js 보안 취약점 모듈 개발
- [ ] 다중 DB 환경 통합 테스트
- [ ] 실시간 코드 실행 UI 구현
- [ ] Docker 네트워크 보안 설정 최적화

## 📊 **예상 성과**

### 🎯 **기술적 성과**
- **다중 DB**: 4개 데이터베이스 환경 (MySQL, PostgreSQL, MongoDB, Redis)
- **실시간 실행**: JavaScript/Node.js 코드 즉시 실행
- **안전한 환경**: VM2 샌드박스로 격리된 실행
- **확장성**: 추후 다른 언어/환경 쉽게 추가 가능

### 🏆 **보안 모듈 확장**
- **현재**: 62개 PHP 기반 모듈
- **목표**: 100+ 다중 환경 모듈
- **추가 예상**: 
  - PostgreSQL 전용 (5개)
  - MongoDB NoSQL (7개) 
  - Redis 캐시 (3개)
  - JavaScript/Node.js (20개)

### 🌍 **업계 영향**
- **교육 표준**: 대학교/기업 보안 교육 플랫폼
- **실무 훈련**: 실제 환경과 동일한 테스트 시나리오
- **연구 도구**: 보안 연구자들의 실험 환경

## 🚀 **실행 명령어**

### 개발 환경 시작
```bash
# 전체 환경 시작
docker-compose up -d

# 특정 서비스만 시작
docker-compose up -d postgres mongodb nodejs_security

# 로그 확인
docker-compose logs -f nodejs_security

# 서비스 상태 확인
docker-compose ps
```

### 테스트 실행
```bash
# PostgreSQL 연결 테스트
docker-compose exec postgres psql -U test_user -d security_test

# MongoDB 연결 테스트  
docker-compose exec mongodb mongosh -u admin -p admin123

# Node.js 보안 서버 테스트
curl http://localhost:3001/health
```

## 🎯 **성공 지표**

1. **환경 구축**: 모든 컨테이너가 정상 실행
2. **연결 테스트**: PHP에서 모든 DB 연결 성공
3. **실시간 실행**: Node.js 코드 즉시 실행 및 결과 표시
4. **보안 모듈**: 15개 이상 새로운 취약점 테스트 추가
5. **성능**: 전체 환경이 8GB RAM 내에서 안정적 동작

## 🔄 **다음 단계**

이 Docker 확장이 완료되면:
- **Phase 2**: 마이크로서비스 아키텍처 시뮬레이션
- **Phase 3**: 복합 공격 체인 및 클라우드 보안 시나리오

**결과**: 세계 최고 수준의 실습형 보안 교육 플랫폼 완성! 🎉

---

**시작 제안**: PostgreSQL 컨테이너부터 추가하여 첫 번째 다중 DB 환경을 구축해보는 것이 어떨까요? 🚀