-- 안전한 데이터베이스 스키마 생성 (safe_db)
\c safe_db;

-- 안전한 사용자 테이블 생성
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL, -- 해시된 비밀번호 저장
    email VARCHAR(100) UNIQUE,
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('admin', 'user', 'guest')),
    is_admin BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 안전한 테스트 데이터 (비밀번호는 해시됨)
INSERT INTO users (username, password_hash, email, role, is_admin) VALUES
('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin@example.com', 'admin', TRUE),
('user1', '$2y$10$TKh8H1.PfQx37YgCzwiKb.KjNyWgaHb9cbcoQgdIVFlYg7B77UdFm', 'user1@example.com', 'user', FALSE),
('user2', '$2y$10$RK8lqDw7GdB8oNM0M6KfE.NjNz7kF4XwgJAJ3Kb5BaF7s2YcG8dfK', 'user2@example.com', 'user', FALSE);

-- 안전한 제품 테이블 (제약 조건 및 인덱스 포함)
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) CHECK (price >= 0),
    category_id INTEGER,
    stock_quantity INTEGER DEFAULT 0 CHECK (stock_quantity >= 0),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 인덱스 생성 (성능 최적화)
CREATE INDEX idx_products_name ON products(name);
CREATE INDEX idx_products_category ON products(category_id);

-- 안전한 제품 데이터
INSERT INTO products (name, description, price, category_id, stock_quantity) VALUES
('Laptop Pro', 'High-performance laptop', 1299.99, 1, 50),
('Smartphone X', 'Latest smartphone model', 899.99, 2, 100),
('Tablet Ultra', 'Premium tablet device', 699.99, 1, 75);

-- 안전한 주문 테이블
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    total_amount DECIMAL(10,2) NOT NULL CHECK (total_amount > 0),
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'shipped', 'completed', 'cancelled')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 감사 로그 테이블 (보안 로깅)
CREATE TABLE security_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action_type VARCHAR(50) NOT NULL,
    resource VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 안전한 검색 함수 (파라미터화된 쿼리 사용)
CREATE OR REPLACE FUNCTION safe_search_products(search_term TEXT)
RETURNS TABLE(id INT, name TEXT, description TEXT, price DECIMAL) AS $$
DECLARE
    safe_term TEXT;
BEGIN
    -- 입력값 검증 및 정제
    safe_term := TRIM(search_term);
    
    -- 입력값이 너무 긴 경우 제한
    IF LENGTH(safe_term) > 100 THEN
        RAISE EXCEPTION 'Search term too long';
    END IF;
    
    -- 파라미터화된 쿼리 사용
    RETURN QUERY 
    SELECT p.id, p.name, p.description, p.price 
    FROM products p 
    WHERE p.name ILIKE '%' || safe_term || '%' 
    AND p.is_active = TRUE
    ORDER BY p.name;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 안전한 사용자 인증 함수
CREATE OR REPLACE FUNCTION safe_authenticate_user(user_name TEXT, user_pass TEXT)
RETURNS TABLE(user_id INT, username TEXT, role TEXT, is_admin BOOLEAN) AS $$
DECLARE
    user_record RECORD;
    current_time TIMESTAMP := NOW();
BEGIN
    -- 입력값 검증
    IF user_name IS NULL OR LENGTH(TRIM(user_name)) = 0 THEN
        RAISE EXCEPTION 'Username cannot be empty';
    END IF;
    
    IF user_pass IS NULL OR LENGTH(user_pass) < 6 THEN
        RAISE EXCEPTION 'Invalid password format';
    END IF;
    
    -- 사용자 조회 (파라미터화된 쿼리)
    SELECT * INTO user_record FROM users u 
    WHERE u.username = TRIM(user_name);
    
    -- 사용자 존재 여부 확인
    IF NOT FOUND THEN
        -- 보안 로그 기록
        INSERT INTO security_logs (action_type, resource, success, details)
        VALUES ('LOGIN_ATTEMPT', 'USER_AUTH', FALSE, 
                jsonb_build_object('reason', 'user_not_found', 'username', user_name));
        RETURN;
    END IF;
    
    -- 계정 잠금 확인
    IF user_record.locked_until IS NOT NULL AND user_record.locked_until > current_time THEN
        INSERT INTO security_logs (user_id, action_type, resource, success, details)
        VALUES (user_record.id, 'LOGIN_ATTEMPT', 'USER_AUTH', FALSE,
                jsonb_build_object('reason', 'account_locked'));
        RETURN;
    END IF;
    
    -- 비밀번호 검증 (실제 구현에서는 bcrypt 등을 사용)
    -- 여기서는 단순화된 검증
    IF user_record.password_hash = crypt(user_pass, user_record.password_hash) THEN
        -- 로그인 성공
        UPDATE users SET failed_login_attempts = 0, locked_until = NULL
        WHERE id = user_record.id;
        
        -- 성공 로그 기록
        INSERT INTO security_logs (user_id, action_type, resource, success)
        VALUES (user_record.id, 'LOGIN_SUCCESS', 'USER_AUTH', TRUE);
        
        -- 사용자 정보 반환
        RETURN QUERY SELECT user_record.id, user_record.username, user_record.role, user_record.is_admin;
    ELSE
        -- 로그인 실패
        UPDATE users 
        SET failed_login_attempts = failed_login_attempts + 1,
            locked_until = CASE 
                WHEN failed_login_attempts >= 4 THEN current_time + INTERVAL '15 minutes'
                ELSE locked_until
            END
        WHERE id = user_record.id;
        
        -- 실패 로그 기록
        INSERT INTO security_logs (user_id, action_type, resource, success, details)
        VALUES (user_record.id, 'LOGIN_ATTEMPT', 'USER_AUTH', FALSE,
                jsonb_build_object('reason', 'invalid_password', 'attempts', user_record.failed_login_attempts + 1));
        RETURN;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;