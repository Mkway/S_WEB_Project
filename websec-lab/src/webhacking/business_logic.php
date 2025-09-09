<?php
/**
 * Business Logic Vulnerability 테스트 페이지
 * 
 * 비즈니스 로직 우회 공격을 시뮬레이션합니다:
 * - 가격 조작 (Price Manipulation)
 * - 권한 우회 (Authorization Bypass)
 * - 워크플로우 우회 (Workflow Bypass)
 * - 수량 제한 우회 (Quantity Limit Bypass)
 */

session_start();

// 데이터베이스 연결
try {
    $pdo = new PDO("mysql:host=security_mysql;dbname=security_test", "root", "root123");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("❌ DB 연결 실패: " . $e->getMessage());
}

// 테스트용 초기 데이터 확인
$pdo->exec("CREATE TABLE IF NOT EXISTS bl_products (
    id INT PRIMARY KEY,
    name VARCHAR(100),
    price DECIMAL(10,2),
    stock INT,
    discount_rate DECIMAL(5,2) DEFAULT 0
)");

$pdo->exec("CREATE TABLE IF NOT EXISTS bl_orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    product_id INT,
    quantity INT,
    price_paid DECIMAL(10,2),
    status VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");

$pdo->exec("CREATE TABLE IF NOT EXISTS bl_users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    role VARCHAR(20),
    balance DECIMAL(10,2)
)");

// 초기 데이터 삽입
$pdo->exec("INSERT IGNORE INTO bl_products VALUES 
    (1, 'Premium Laptop', 999.99, 10, 0.10),
    (2, 'Gaming Mouse', 59.99, 50, 0.05),
    (3, 'Mechanical Keyboard', 129.99, 30, 0.15)");

$pdo->exec("INSERT IGNORE INTO bl_users VALUES 
    (1, 'user', 'customer', 500.00),
    (2, 'admin', 'administrator', 9999.99),
    (3, 'guest', 'guest', 50.00)");

$result = "";
$vulnerability_executed = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $test_type = $_POST['test_type'] ?? '';
    
    switch ($test_type) {
        case 'price_manipulation':
            $result = testPriceManipulation($pdo, $_POST);
            break;
        case 'auth_bypass':
            $result = testAuthorizationBypass($pdo, $_POST);
            break;
        case 'workflow_bypass':
            $result = testWorkflowBypass($pdo, $_POST);
            break;
        case 'quantity_bypass':
            $result = testQuantityBypass($pdo, $_POST);
            break;
        case 'safe_implementation':
            $result = testSafeImplementation($pdo, $_POST);
            break;
    }
    $vulnerability_executed = true;
}

/**
 * 가격 조작 공격 테스트
 */
function testPriceManipulation($pdo, $post_data) {
    $result = "<h3>💰 Price Manipulation 테스트</h3>";
    
    $product_id = intval($post_data['product_id'] ?? 1);
    $quantity = intval($post_data['quantity'] ?? 1);
    $manipulated_price = floatval($post_data['price'] ?? 0);
    
    try {
        // 실제 제품 정보 조회
        $stmt = $pdo->prepare("SELECT * FROM bl_products WHERE id = ?");
        $stmt->execute([$product_id]);
        $product = $stmt->fetch();
        
        if (!$product) {
            return "<p class='error'>제품을 찾을 수 없습니다.</p>";
        }
        
        $result .= "<div class='vulnerable-output'>";
        $result .= "<h4>🚨 취약한 구현 실행 결과:</h4>";
        $result .= "<p><strong>제품:</strong> {$product['name']}</p>";
        $result .= "<p><strong>정상 가격:</strong> $" . number_format($product['price'], 2) . "</p>";
        $result .= "<p><strong>조작된 가격:</strong> $" . number_format($manipulated_price, 2) . "</p>";
        $result .= "<p><strong>수량:</strong> {$quantity}</p>";
        
        // 취약한 구현: 클라이언트에서 전송된 가격 그대로 사용
        $total = $manipulated_price * $quantity;
        
        // 음수 가격 처리
        if ($manipulated_price < 0) {
            $result .= "<p class='error'><strong>⚠️ 음수 가격 공격 성공!</strong></p>";
            $result .= "<p>계산된 총액: $" . number_format($total, 2) . " (환불 효과)</p>";
        } elseif ($manipulated_price < $product['price'] * 0.5) {
            $result .= "<p class='error'><strong>⚠️ 가격 조작 공격 성공!</strong></p>";
            $result .= "<p>50% 이상 할인된 가격으로 구매 가능</p>";
        } else {
            $result .= "<p>정상 범위의 가격입니다.</p>";
        }
        
        $result .= "<p><strong>최종 결제 금액:</strong> $" . number_format($total, 2) . "</p>";
        
        // 실제 주문 기록 (교육용)
        $stmt = $pdo->prepare("INSERT INTO bl_orders (user_id, product_id, quantity, price_paid, status) VALUES (1, ?, ?, ?, 'completed')");
        $stmt->execute([$product_id, $quantity, $total]);
        
        $result .= "<p><em>주문이 시스템에 기록되었습니다 (주문 ID: " . $pdo->lastInsertId() . ")</em></p>";
        $result .= "</div>";
        
        // 안전한 구현 비교
        $result .= "<div class='safe-comparison'>";
        $result .= "<h4>✅ 안전한 구현이었다면:</h4>";
        $safe_total = $product['price'] * $quantity;
        $result .= "<p>서버에서 가격 검증: $" . number_format($product['price'], 2) . " (고정)</p>";
        $result .= "<p>안전한 총액: $" . number_format($safe_total, 2) . "</p>";
        $result .= "<p>클라이언트 가격 무시, 서버 DB에서만 가격 조회</p>";
        $result .= "</div>";
        
        // 보안 권장사항
        $result .= "<div class='security-recommendations'>";
        $result .= "<h4>🛡️ 보안 권장사항:</h4>";
        $result .= "<ul>";
        $result .= "<li>가격은 항상 서버 DB에서만 조회</li>";
        $result .= "<li>클라이언트에서 전송된 가격 정보 절대 신뢰 금지</li>";
        $result .= "<li>음수 수량/가격 입력 차단</li>";
        $result .= "<li>할인율 검증 및 최대 할인 한도 설정</li>";
        $result .= "<li>모든 결제 트랜잭션 로그 및 모니터링</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $result .= "<p class='error'>오류: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    return $result;
}

/**
 * 권한 우회 공격 테스트
 */
function testAuthorizationBypass($pdo, $post_data) {
    $result = "<h3>🔓 Authorization Bypass 테스트</h3>";
    
    $user_id = intval($post_data['user_id'] ?? 1);
    $target_action = $post_data['action'] ?? 'view_orders';
    
    try {
        // 사용자 정보 조회
        $stmt = $pdo->prepare("SELECT * FROM bl_users WHERE id = ?");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch();
        
        if (!$user) {
            return "<p class='error'>사용자를 찾을 수 없습니다.</p>";
        }
        
        $result .= "<div class='vulnerable-output'>";
        $result .= "<h4>🚨 취약한 구현 실행 결과:</h4>";
        $result .= "<p><strong>현재 사용자:</strong> {$user['username']} ({$user['role']})</p>";
        $result .= "<p><strong>시도하는 작업:</strong> {$target_action}</p>";
        
        // 취약한 구현: 권한 검사 없이 작업 수행
        switch ($target_action) {
            case 'view_all_orders':
                $stmt = $pdo->query("SELECT COUNT(*) as count FROM bl_orders");
                $count = $stmt->fetch()['count'];
                $result .= "<p><strong>⚠️ 권한 우회 성공!</strong></p>";
                $result .= "<p>전체 주문 {$count}개 조회 완료 (관리자 권한 필요)</p>";
                
                $stmt = $pdo->query("SELECT * FROM bl_orders LIMIT 3");
                $orders = $stmt->fetchAll();
                $result .= "<p><strong>노출된 주문 정보:</strong></p>";
                foreach ($orders as $order) {
                    $result .= "<small>주문 #{$order['id']}: 사용자 {$order['user_id']}, 금액 ${$order['price_paid']}</small><br>";
                }
                break;
                
            case 'modify_balance':
                $new_balance = floatval($post_data['new_balance'] ?? 9999);
                $stmt = $pdo->prepare("UPDATE bl_users SET balance = ? WHERE id = ?");
                $stmt->execute([$new_balance, $user_id]);
                
                $result .= "<p><strong>⚠️ 권한 우회 성공!</strong></p>";
                $result .= "<p>잔액이 $" . number_format($new_balance, 2) . "로 변경되었습니다 (관리자 권한 필요)</p>";
                break;
                
            case 'delete_orders':
                $stmt = $pdo->prepare("DELETE FROM bl_orders WHERE user_id != ?");
                $stmt->execute([$user_id]);
                $affected = $stmt->rowCount();
                
                $result .= "<p><strong>⚠️ 권한 우회 성공!</strong></p>";
                $result .= "<p>다른 사용자의 주문 {$affected}개 삭제 완료 (관리자 권한 필요)</p>";
                break;
        }
        
        $result .= "</div>";
        
        // 안전한 구현 비교
        $result .= "<div class='safe-comparison'>";
        $result .= "<h4>✅ 안전한 구현이었다면:</h4>";
        $result .= "<p>권한 확인: {$user['role']} 권한으로는 '{$target_action}' 작업 불가</p>";
        $result .= "<p>접근 거부: HTTP 403 Forbidden 응답</p>";
        $result .= "<p>감사 로그: 권한 위반 시도 기록</p>";
        $result .= "</div>";
        
        // 보안 권장사항
        $result .= "<div class='security-recommendations'>";
        $result .= "<h4>🛡️ 보안 권장사항:</h4>";
        $result .= "<ul>";
        $result .= "<li>모든 민감한 작업에 권한 검사 필수</li>";
        $result .= "<li>역할 기반 접근 제어 (RBAC) 구현</li>";
        $result .= "<li>최소 권한 원칙 적용</li>";
        $result .= "<li>권한 위반 시도 모니터링 및 알림</li>";
        $result .= "<li>세션 기반 권한 검증</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $result .= "<p class='error'>오류: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    return $result;
}

/**
 * 워크플로우 우회 공격 테스트
 */
function testWorkflowBypass($pdo, $post_data) {
    $result = "<h3>🔄 Workflow Bypass 테스트</h3>";
    
    $product_id = intval($post_data['product_id'] ?? 1);
    $skip_step = $post_data['skip_step'] ?? '';
    
    try {
        $result .= "<div class='vulnerable-output'>";
        $result .= "<h4>🚨 취약한 구현 실행 결과:</h4>";
        
        switch ($skip_step) {
            case 'payment':
                // 결제 단계 건너뛰고 주문 완료
                $stmt = $pdo->prepare("INSERT INTO bl_orders (user_id, product_id, quantity, price_paid, status) VALUES (1, ?, 1, 0.00, 'completed')");
                $stmt->execute([$product_id]);
                
                $result .= "<p><strong>⚠️ 결제 우회 성공!</strong></p>";
                $result .= "<p>결제 없이 주문 완료 (주문 ID: " . $pdo->lastInsertId() . ")</p>";
                $result .= "<p>결제 금액: $0.00</p>";
                break;
                
            case 'stock_check':
                // 재고 확인 없이 주문 처리
                $stmt = $pdo->prepare("INSERT INTO bl_orders (user_id, product_id, quantity, price_paid, status) VALUES (1, ?, 999, 999.99, 'completed')");
                $stmt->execute([$product_id]);
                
                $result .= "<p><strong>⚠️ 재고 확인 우회 성공!</strong></p>";
                $result .= "<p>재고 부족 상품 999개 주문 완료</p>";
                break;
                
            case 'approval':
                // 승인 절차 없이 고액 주문
                $stmt = $pdo->prepare("INSERT INTO bl_orders (user_id, product_id, quantity, price_paid, status) VALUES (1, ?, 100, 99999.00, 'completed')");
                $stmt->execute([$product_id]);
                
                $result .= "<p><strong>⚠️ 승인 절차 우회 성공!</strong></p>";
                $result .= "<p>고액 주문 승인 없이 처리 완료 ($99,999)</p>";
                break;
        }
        
        $result .= "</div>";
        
        // 안전한 구현 비교
        $result .= "<div class='safe-comparison'>";
        $result .= "<h4>✅ 안전한 구현이었다면:</h4>";
        $result .= "<p>필수 단계 검증: 결제 → 재고 확인 → 승인 → 주문 완료</p>";
        $result .= "<p>단계별 상태 검사 및 롤백 메커니즘</p>";
        $result .= "<p>트랜잭션 무결성 보장</p>";
        $result .= "</div>";
        
        // 보안 권장사항
        $result .= "<div class='security-recommendations'>";
        $result .= "<h4>🛡️ 보안 권장사항:</h4>";
        $result .= "<ul>";
        $result .= "<li>상태 기반 워크플로우 검증 구현</li>";
        $result .= "<li>필수 단계 건너뛰기 방지</li>";
        $result .= "<li>트랜잭션 원자성 보장</li>";
        $result .= "<li>비즈니스 규칙 서버사이드 검증</li>";
        $result .= "<li>워크플로우 진행 상태 추적 및 로깅</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $result .= "<p class='error'>오류: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    return $result;
}

/**
 * 수량 제한 우회 공격 테스트
 */
function testQuantityBypass($pdo, $post_data) {
    $result = "<h3">📦 Quantity Limit Bypass 테스트</h3>";
    
    $product_id = intval($post_data['product_id'] ?? 1);
    $quantity = intval($post_data['quantity'] ?? 1);
    
    try {
        $stmt = $pdo->prepare("SELECT * FROM bl_products WHERE id = ?");
        $stmt->execute([$product_id]);
        $product = $stmt->fetch();
        
        $result .= "<div class='vulnerable-output'>";
        $result .= "<h4>🚨 취약한 구현 실행 결과:</h4>";
        $result .= "<p><strong>제품:</strong> {$product['name']}</p>";
        $result .= "<p><strong>현재 재고:</strong> {$product['stock']}</p>";
        $result .= "<p><strong>요청 수량:</strong> {$quantity}</p>";
        
        // 취약한 구현: 재고보다 많은 주문 허용
        if ($quantity > $product['stock']) {
            $result .= "<p><strong>⚠️ 재고 초과 주문 성공!</strong></p>";
            $result .= "<p>재고 {$product['stock']}개보다 {$quantity}개 더 많은 주문</p>";
            
            // 음수 재고 처리
            $new_stock = $product['stock'] - $quantity;
            $stmt = $pdo->prepare("UPDATE bl_products SET stock = ? WHERE id = ?");
            $stmt->execute([$new_stock, $product_id]);
            
            $result .= "<p>업데이트된 재고: {$new_stock}개 (음수 재고 발생)</p>";
        } elseif ($quantity <= 0) {
            $result .= "<p><strong>⚠️ 잘못된 수량 처리!</strong></p>";
            $result .= "<p>0개 이하 주문으로 시스템 혼란 유발</p>";
        }
        
        $result .= "</div>";
        
        // 안전한 구현 비교  
        $result .= "<div class='safe-comparison'>";
        $result .= "<h4>✅ 안전한 구현이었다면:</h4>";
        $result .= "<p>재고 검증: 주문 수량 ≤ 현재 재고</p>";
        $result .= "<p>최소/최대 주문 수량 제한</p>";
        $result .= "<p>원자적 재고 업데이트</p>";
        $result .= "</div>";
        
        // 보안 권장사항
        $result .= "<div class='security-recommendations'>";
        $result .= "<h4>🛡️ 보안 권장사항:</h4>";
        $result .= "<ul>";
        $result .= "<li>재고 수량 실시간 검증</li>";
        $result .= "<li>동시 주문에 대한 락 메커니즘</li>";
        $result .= "<li>음수 재고 방지</li>";
        $result .= "<li>최대 주문 수량 제한</li>";
        $result .= "<li>재고 부족 시 대기열 시스템</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $result .= "<p class='error'>오류: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    return $result;
}

/**
 * 안전한 구현 테스트
 */
function testSafeImplementation($pdo, $post_data) {
    $result = "<h3>✅ Safe Implementation 테스트</h3>";
    
    $product_id = intval($post_data['product_id'] ?? 1);
    $quantity = intval($post_data['quantity'] ?? 1);
    $user_id = intval($post_data['user_id'] ?? 1);
    
    try {
        $result .= "<div class='safe-implementation'>";
        $result .= "<h4>🛡️ 안전한 구현 실행:</h4>";
        
        // 1. 사용자 권한 확인
        $stmt = $pdo->prepare("SELECT * FROM bl_users WHERE id = ?");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch();
        
        if ($user['role'] !== 'customer' && $user['role'] !== 'administrator') {
            $result .= "<p><strong>❌ 권한 검증 실패:</strong> 주문 권한 없음</p>";
            return $result . "</div>";
        }
        
        // 2. 제품 및 재고 확인
        $stmt = $pdo->prepare("SELECT * FROM bl_products WHERE id = ?");
        $stmt->execute([$product_id]);
        $product = $stmt->fetch();
        
        if ($product['stock'] < $quantity || $quantity <= 0 || $quantity > 10) {
            $result .= "<p><strong>❌ 재고/수량 검증 실패:</strong> 주문 불가</p>";
            $result .= "<p>현재 재고: {$product['stock']}, 요청 수량: {$quantity}</p>";
            return $result . "</div>";
        }
        
        // 3. 가격 계산 (서버에서만)
        $unit_price = $product['price'];
        $discount = $product['discount_rate'];
        $final_price = $unit_price * (1 - $discount);
        $total = $final_price * $quantity;
        
        // 4. 잔액 확인
        if ($user['balance'] < $total) {
            $result .= "<p><strong>❌ 잔액 부족:</strong> 주문 불가</p>";
            $result .= "<p>필요 금액: $" . number_format($total, 2) . ", 보유 잔액: $" . number_format($user['balance'], 2) . "</p>";
            return $result . "</div>";
        }
        
        // 5. 트랜잭션으로 안전한 주문 처리
        $pdo->beginTransaction();
        
        try {
            // 재고 차감
            $stmt = $pdo->prepare("UPDATE bl_products SET stock = stock - ? WHERE id = ? AND stock >= ?");
            $stmt->execute([$quantity, $product_id, $quantity]);
            
            if ($stmt->rowCount() === 0) {
                throw new Exception("재고 업데이트 실패");
            }
            
            // 잔액 차감
            $stmt = $pdo->prepare("UPDATE bl_users SET balance = balance - ? WHERE id = ?");
            $stmt->execute([$total, $user_id]);
            
            // 주문 생성
            $stmt = $pdo->prepare("INSERT INTO bl_orders (user_id, product_id, quantity, price_paid, status) VALUES (?, ?, ?, ?, 'completed')");
            $stmt->execute([$user_id, $product_id, $quantity, $total]);
            
            $order_id = $pdo->lastInsertId();
            $pdo->commit();
            
            $result .= "<p><strong>✅ 안전한 주문 완료!</strong></p>";
            $result .= "<p>주문 ID: {$order_id}</p>";
            $result .= "<p>제품: {$product['name']} × {$quantity}</p>";
            $result .= "<p>결제 금액: $" . number_format($total, 2) . "</p>";
            
        } catch (Exception $e) {
            $pdo->rollback();
            $result .= "<p><strong>❌ 트랜잭션 실패:</strong> " . $e->getMessage() . "</p>";
        }
        
        $result .= "</div>";
        
        // 안전한 구현의 특징
        $result .= "<div class='implementation-benefits'>";
        $result .= "<h4>🎯 안전한 구현의 특징:</h4>";
        $result .= "<ul>";
        $result .= "<li><strong>권한 검증:</strong> 사용자 역할 확인</li>";
        $result .= "<li><strong>입력 검증:</strong> 수량/가격 서버사이드 검증</li>";
        $result .= "<li><strong>원자적 트랜잭션:</strong> 모든 단계가 성공해야 완료</li>";
        $result .= "<li><strong>실시간 검증:</strong> 재고/잔액 동시 확인</li>";
        $result .= "<li><strong>롤백 메커니즘:</strong> 실패 시 모든 변경 취소</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $result .= "<p class='error'>오류: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    return $result;
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Business Logic Vulnerability 테스트</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }

        .header {
            background: linear-gradient(135deg, #7c3aed, #a855f7);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }

        .test-container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #333;
        }

        select, input, textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
        }

        button {
            background: #7c3aed;
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
        }

        button:hover {
            background: #6d28d9;
        }

        .result {
            margin-top: 30px;
            border-radius: 10px;
            overflow: hidden;
        }

        .vulnerable-output {
            background: #fee2e2;
            border: 2px solid #fca5a5;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }

        .safe-comparison {
            background: #dcfce7;
            border: 2px solid #86efac;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }

        .security-recommendations {
            background: #dbeafe;
            border: 2px solid #93c5fd;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }

        .safe-implementation {
            background: #f0fdf4;
            border: 2px solid #4ade80;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }

        .implementation-benefits {
            background: #fefce8;
            border: 2px solid #facc15;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }

        .error {
            color: #dc2626;
            font-weight: bold;
        }

        .info-box {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }

        ul {
            padding-left: 20px;
        }

        li {
            margin-bottom: 8px;
        }

        h3 {
            color: #1f2937;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
        }

        h4 {
            margin-top: 0;
            color: #374151;
        }

        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>💰 Business Logic Vulnerability 테스트</h1>
        <p>비즈니스 로직 우회 공격을 시뮬레이션하고 안전한 구현과 비교합니다</p>
    </div>

    <div class="test-container">
        <div class="warning">
            ⚠️ <strong>경고:</strong> 이 테스트는 교육 목적으로만 사용되며, 실제 비즈니스 로직을 조작합니다. 
            프로덕션 환경에서는 절대 사용하지 마세요.
        </div>

        <form method="POST">
            <div class="grid">
                <div class="form-group">
                    <label for="test_type">테스트 유형:</label>
                    <select name="test_type" id="test_type" required>
                        <option value="">테스트 유형을 선택하세요</option>
                        <option value="price_manipulation" <?= ($_POST['test_type'] ?? '') == 'price_manipulation' ? 'selected' : '' ?>>
                            💰 Price Manipulation (가격 조작)
                        </option>
                        <option value="auth_bypass" <?= ($_POST['test_type'] ?? '') == 'auth_bypass' ? 'selected' : '' ?>>
                            🔓 Authorization Bypass (권한 우회)
                        </option>
                        <option value="workflow_bypass" <?= ($_POST['test_type'] ?? '') == 'workflow_bypass' ? 'selected' : '' ?>>
                            🔄 Workflow Bypass (워크플로우 우회)
                        </option>
                        <option value="quantity_bypass" <?= ($_POST['test_type'] ?? '') == 'quantity_bypass' ? 'selected' : '' ?>>
                            📦 Quantity Limit Bypass (수량 제한 우회)
                        </option>
                        <option value="safe_implementation" <?= ($_POST['test_type'] ?? '') == 'safe_implementation' ? 'selected' : '' ?>>
                            ✅ Safe Implementation (안전한 구현)
                        </option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="product_id">제품 ID:</label>
                    <select name="product_id" id="product_id">
                        <option value="1">1 - Premium Laptop ($999.99)</option>
                        <option value="2">2 - Gaming Mouse ($59.99)</option>
                        <option value="3">3 - Mechanical Keyboard ($129.99)</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="quantity">수량:</label>
                    <input type="number" name="quantity" id="quantity" value="<?= htmlspecialchars($_POST['quantity'] ?? '1') ?>" min="-999" max="9999">
                </div>

                <div class="form-group">
                    <label for="price">조작된 가격 (Price Manipulation용):</label>
                    <input type="number" name="price" id="price" step="0.01" value="<?= htmlspecialchars($_POST['price'] ?? '0.01') ?>" min="-9999" max="9999">
                </div>

                <div class="form-group">
                    <label for="user_id">사용자 ID:</label>
                    <select name="user_id" id="user_id">
                        <option value="1">1 - user (customer, $500)</option>
                        <option value="2">2 - admin (administrator, $9999)</option>
                        <option value="3">3 - guest (guest, $50)</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="action">권한 우회 작업:</label>
                    <select name="action" id="action">
                        <option value="view_all_orders">전체 주문 조회</option>
                        <option value="modify_balance">잔액 수정</option>
                        <option value="delete_orders">주문 삭제</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="skip_step">우회할 단계:</label>
                    <select name="skip_step" id="skip_step">
                        <option value="payment">결제 단계</option>
                        <option value="stock_check">재고 확인</option>
                        <option value="approval">승인 절차</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="new_balance">새 잔액 (권한 우회용):</label>
                    <input type="number" name="new_balance" id="new_balance" step="0.01" value="<?= htmlspecialchars($_POST['new_balance'] ?? '9999.99') ?>">
                </div>
            </div>

            <button type="submit">🚀 Business Logic 공격 실행</button>
        </form>

        <div class="info-box">
            <h3>📖 테스트 예제:</h3>
            <ul>
                <li><strong>Price Manipulation:</strong> 가격을 -10.00 또는 0.01로 설정</li>
                <li><strong>Authorization Bypass:</strong> guest 계정으로 관리자 작업 시도</li>
                <li><strong>Workflow Bypass:</strong> 결제/재고 확인 건너뛰기</li>
                <li><strong>Quantity Bypass:</strong> 재고보다 많은 수량 (999개) 주문</li>
                <li><strong>Safe Implementation:</strong> 정상적인 주문 프로세스</li>
            </ul>
        </div>
    </div>

    <?php if ($vulnerability_executed && $result): ?>
    <div class="test-container">
        <div class="result">
            <?= $result ?>
        </div>
    </div>
    <?php endif; ?>

    <div class="test-container">
        <h3>🎯 Business Logic Vulnerability 개요</h3>
        <div class="info-box">
            <h4>주요 공격 벡터:</h4>
            <ul>
                <li><strong>가격 조작:</strong> 음수 가격, 할인율 조작, 무료 구매</li>
                <li><strong>권한 우회:</strong> 다른 사용자 데이터 접근, 관리자 기능 사용</li>
                <li><strong>워크플로우 우회:</strong> 필수 단계 건너뛰기, 순서 무시</li>
                <li><strong>수량 조작:</strong> 재고 초과 주문, 음수 수량</li>
            </ul>
            
            <h4>실제 피해 사례:</h4>
            <ul>
                <li>무료 또는 음수 가격으로 구매하여 금전적 손실</li>
                <li>재고 관리 시스템 혼란 및 음수 재고</li>
                <li>권한이 없는 사용자의 민감 데이터 접근</li>
                <li>결제 없이 상품 획득</li>
            </ul>
        </div>
    </div>
</body>
</html>