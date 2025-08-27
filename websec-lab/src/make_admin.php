<?php
/**
 * 관리자 권한 부여 페이지 (개발/테스트 목적)
 * 로그인한 사용자를 관리자로 만들거나, 기존 사용자에게 관리자 권한을 부여합니다.
 */

session_start();
require_once 'db.php';
require_once 'config.php';
require_once 'utils.php';

// 디버그 모드에서만 접근 허용
if (!DEBUG_MODE) {
    die('This page is only available in debug mode.');
}

$success_message = '';
$error_message = '';

// POST 요청 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['make_current_admin']) && is_logged_in()) {
        // 현재 로그인한 사용자를 관리자로 만들기
        $user_id = $_SESSION['user_id'];
        
        try {
            $stmt = $pdo->prepare("UPDATE users SET is_admin = 1 WHERE id = ?");
            $stmt->execute([$user_id]);
            
            $_SESSION['is_admin'] = true;
            $success_message = "현재 사용자가 관리자 권한을 받았습니다!";
            
            // 로그 기록
            if (function_exists('log_security')) {
                log_security('admin_privilege_granted', 'User granted admin privileges via make_admin.php', [
                    'user_id' => $user_id,
                    'username' => $_SESSION['username']
                ]);
            }
        } catch (Exception $e) {
            $error_message = "관리자 권한 부여 실패: " . $e->getMessage();
        }
    } elseif (isset($_POST['make_user_admin']) && !empty($_POST['username'])) {
        // 특정 사용자를 관리자로 만들기
        $username = clean_input($_POST['username']);
        
        try {
            $stmt = $pdo->prepare("UPDATE users SET is_admin = 1 WHERE username = ?");
            $stmt->execute([$username]);
            
            if ($stmt->rowCount() > 0) {
                $success_message = "사용자 '{$username}'이 관리자 권한을 받았습니다!";
                
                // 로그 기록
                if (function_exists('log_security')) {
                    log_security('admin_privilege_granted', "Admin privileges granted to user: {$username}", [
                        'target_username' => $username,
                        'granted_by' => $_SESSION['username'] ?? 'anonymous'
                    ]);
                }
            } else {
                $error_message = "사용자 '{$username}'을 찾을 수 없습니다.";
            }
        } catch (Exception $e) {
            $error_message = "관리자 권한 부여 실패: " . $e->getMessage();
        }
    }
}

// 모든 사용자 조회
try {
    $users_stmt = $pdo->query("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC");
    $users = $users_stmt->fetchAll();
} catch (Exception $e) {
    $users = [];
    $error_message = "사용자 목록 조회 실패: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>관리자 권한 부여 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>🔧 관리자 권한 부여 (개발 모드)</h1>
        
        <div class="alert" style="background-color: #fff3cd; color: #856404; border: 1px solid #ffeaa7;">
            <strong>⚠️ 주의:</strong> 이 페이지는 개발/테스트 목적으로만 사용하세요. 운영 환경에서는 접근할 수 없습니다.
        </div>
        
        <!-- 성공/에러 메시지 -->
        <?php if ($success_message): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success_message); ?></div>
        <?php endif; ?>
        
        <?php if ($error_message): ?>
            <div class="alert alert-error"><?php echo htmlspecialchars($error_message); ?></div>
        <?php endif; ?>
        
        <!-- 현재 사용자를 관리자로 만들기 -->
        <?php if (is_logged_in()): ?>
            <div style="margin-bottom: 30px; padding: 20px; border: 2px solid #007bff; border-radius: 8px;">
                <h2>현재 로그인한 사용자</h2>
                <p><strong>사용자명:</strong> <?php echo htmlspecialchars($_SESSION['username']); ?></p>
                <p><strong>관리자 권한:</strong> 
                    <?php if (is_admin()): ?>
                        <span style="color: #51cf66;">✅ 이미 관리자입니다</span>
                    <?php else: ?>
                        <span style="color: #ff6b6b;">❌ 일반 사용자</span>
                    <?php endif; ?>
                </p>
                
                <?php if (!is_admin()): ?>
                    <form method="post" style="margin-top: 15px;">
                        <button type="submit" name="make_current_admin" class="btn" style="background-color: #007bff; color: white;" onclick="return confirm('현재 사용자에게 관리자 권한을 부여하시겠습니까?')">
                            🛡️ 관리자 권한 받기
                        </button>
                    </form>
                <?php else: ?>
                    <a href="admin.php" class="btn" style="background-color: #51cf66; color: white; margin-top: 15px;">
                        📊 관리자 페이지로 이동
                    </a>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div style="margin-bottom: 30px; padding: 20px; border: 2px solid #ffc107; border-radius: 8px;">
                <h2>로그인 필요</h2>
                <p>관리자 권한을 받으려면 먼저 로그인해야 합니다.</p>
                <a href="login.php" class="btn">로그인하기</a>
                <a href="register.php" class="btn">회원가입하기</a>
            </div>
        <?php endif; ?>
        
        <!-- 특정 사용자를 관리자로 만들기 -->
        <div style="margin-bottom: 30px; padding: 20px; border: 2px solid #6c757d; border-radius: 8px;">
            <h2>특정 사용자에게 관리자 권한 부여</h2>
            <form method="post">
                <div style="margin-bottom: 15px;">
                    <label for="username">사용자명:</label>
                    <input type="text" id="username" name="username" required style="margin-left: 10px; padding: 5px;">
                </div>
                <button type="submit" name="make_user_admin" class="btn" style="background-color: #6c757d; color: white;" onclick="return confirm('해당 사용자에게 관리자 권한을 부여하시겠습니까?')">
                    👤 관리자 권한 부여
                </button>
            </form>
        </div>
        
        <!-- 현재 사용자 목록 -->
        <div style="padding: 20px; border: 2px solid #ddd; border-radius: 8px;">
            <h2>등록된 사용자 목록</h2>
            <?php if (empty($users)): ?>
                <p>등록된 사용자가 없습니다.</p>
            <?php else: ?>
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background-color: #f8f9fa;">
                            <th style="padding: 10px; border: 1px solid #ddd;">ID</th>
                            <th style="padding: 10px; border: 1px solid #ddd;">사용자명</th>
                            <th style="padding: 10px; border: 1px solid #ddd;">관리자 권한</th>
                            <th style="padding: 10px; border: 1px solid #ddd;">가입일</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td style="padding: 10px; border: 1px solid #ddd;"><?php echo $user['id']; ?></td>
                                <td style="padding: 10px; border: 1px solid #ddd;"><?php echo htmlspecialchars($user['username']); ?></td>
                                <td style="padding: 10px; border: 1px solid #ddd;">
                                    <?php if ($user['is_admin']): ?>
                                        <span style="color: #51cf66;">✅ 관리자</span>
                                    <?php else: ?>
                                        <span style="color: #6c757d;">👤 일반 사용자</span>
                                    <?php endif; ?>
                                </td>
                                <td style="padding: 10px; border: 1px solid #ddd;"><?php echo format_date($user['created_at']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        
        <!-- 네비게이션 -->
        <div style="margin-top: 30px; text-align: center;">
            <a href="index.php" class="btn">메인 페이지로 돌아가기</a>
            <?php if (is_admin()): ?>
                <a href="admin.php" class="btn" style="background-color: #007bff; color: white;">관리자 페이지</a>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>