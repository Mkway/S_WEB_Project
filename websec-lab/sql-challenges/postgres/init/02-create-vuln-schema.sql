-- 취약한 데이터베이스 스키마 생성 (vuln_db)
\c vuln_db;

-- 사용자 테이블 생성 (인증 우회 테스트용)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 테스트 사용자 데이터 삽입
INSERT INTO users (username, password, email, role, is_admin) VALUES
('admin', 'admin123', 'admin@example.com', 'admin', TRUE),
('user1', 'password123', 'user1@example.com', 'user', FALSE),
('user2', 'pass456', 'user2@example.com', 'user', FALSE),
('guest', 'guest123', 'guest@example.com', 'guest', FALSE),
('testuser', 'test123', 'test@example.com', 'user', FALSE);

-- 제품 테이블 생성 (SQL Injection 테스트용)
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    category_id INTEGER,
    stock_quantity INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE
);

-- 제품 데이터 삽입
INSERT INTO products (name, description, price, category_id, stock_quantity) VALUES
('Laptop Pro', 'High-performance laptop', 1299.99, 1, 50),
('Smartphone X', 'Latest smartphone model', 899.99, 2, 100),
('Tablet Ultra', 'Premium tablet device', 699.99, 1, 75),
('Headphones Premium', 'Noise-canceling headphones', 299.99, 3, 200),
('Smart Watch', 'Fitness tracking smartwatch', 399.99, 2, 150);

-- 주문 테이블 생성 (복합 SQL Injection 테스트용)
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL,
    total_amount DECIMAL(10,2),
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'pending'
);

-- 주문 데이터 삽입
INSERT INTO orders (user_id, product_id, quantity, total_amount, status) VALUES
(2, 1, 1, 1299.99, 'completed'),
(3, 2, 2, 1799.98, 'pending'),
(4, 4, 1, 299.99, 'shipped'),
(5, 3, 1, 699.99, 'completed');

-- 로그 테이블 생성 (COPY FROM PROGRAM 테스트용)
CREATE TABLE access_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- PL/pgSQL 취약한 저장 프로시저 생성
CREATE OR REPLACE FUNCTION vulnerable_search(search_term TEXT)
RETURNS TABLE(id INT, name TEXT, description TEXT) AS $$
BEGIN
    -- 취약한 동적 쿼리 실행 (SQL Injection 가능)
    RETURN QUERY EXECUTE 'SELECT p.id, p.name, p.description FROM products p WHERE p.name LIKE ''%' || search_term || '%''';
END;
$$ LANGUAGE plpgsql;

-- 취약한 사용자 인증 함수
CREATE OR REPLACE FUNCTION vulnerable_login(user_name TEXT, user_pass TEXT)
RETURNS TABLE(user_id INT, username TEXT, role TEXT, is_admin BOOLEAN) AS $$
BEGIN
    -- 취약한 동적 쿼리 (SQL Injection 가능)
    RETURN QUERY EXECUTE 'SELECT id, username, role, is_admin FROM users WHERE username = ''' || user_name || ''' AND password = ''' || user_pass || '''';
END;
$$ LANGUAGE plpgsql;

-- 취약한 데이터 삽입 함수 (COPY 명령 악용 가능)
CREATE OR REPLACE FUNCTION vulnerable_log_insert(log_data TEXT)
RETURNS VOID AS $$
BEGIN
    -- 취약한 COPY 명령 실행
    EXECUTE 'COPY access_logs(action) FROM PROGRAM ''' || log_data || '''';
END;
$$ LANGUAGE plpgsql;