-- PostgreSQL 다중 데이터베이스 초기화 스크립트
-- 보안 테스트용 취약한 데이터베이스와 안전한 데이터베이스 생성

-- 취약한 데이터베이스 생성
CREATE DATABASE vuln_db;

-- 안전한 데이터베이스 생성  
CREATE DATABASE safe_db;

-- 테스트 사용자에게 권한 부여
GRANT ALL PRIVILEGES ON DATABASE vuln_db TO test_user;
GRANT ALL PRIVILEGES ON DATABASE safe_db TO test_user;

-- 확장 기능 활성화 (보안 테스트에 필요)
\c vuln_db;
CREATE EXTENSION IF NOT EXISTS plpgsql;

\c safe_db;
CREATE EXTENSION IF NOT EXISTS plpgsql;

-- 기본 데이터베이스로 돌아가기
\c security_test;