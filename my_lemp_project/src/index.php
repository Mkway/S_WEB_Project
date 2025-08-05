<?php
/**
 * 메인 게시판 페이지
 * 게시물 목록을 표시하고 검색 및 페이지네이션을 제공합니다.
 */

session_start();
require_once 'db.php';
require_once 'utils.php';

/**
 * 검색 조건에 따른 WHERE 절 생성
 * @param string $search_query 검색어
 * @param string $search_by 검색 필드
 * @return array WHERE 절과 매개변수
 */
function build_search_condition($search_query, $search_by) {
    if (empty($search_query)) {
        return ['where_clause' => '', 'param_value' => '', 'is_vulnerable' => false];
    }
    
    // 취약점 모드일 때 SQL Injection 허용 (교육 목적)
    if (defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true) {
        // 위험한 패턴 감지 (로깅 목적)
        $dangerous_patterns = ['union', 'select', '--', ';', 'drop', 'delete', 'update', 'insert'];
        $is_suspicious = false;
        foreach ($dangerous_patterns as $pattern) {
            if (stripos($search_query, $pattern) !== false) {
                $is_suspicious = true;
                break;
            }
        }
        
        if ($is_suspicious && function_exists('log_security')) {
            log_security('sql_injection_attempt', 'Potential SQL injection in search', [
                'search_query' => $search_query,
                'search_by' => $search_by,
                'vulnerability_mode' => true
            ]);
        }
        
        // 취약한 쿼리 생성 (직접 문자열 삽입)
        switch ($search_by) {
            case 'title':
                return [
                    'where_clause' => " WHERE posts.title LIKE '%" . $search_query . "%'",
                    'param_value' => '',
                    'is_vulnerable' => true
                ];
            case 'content':
                return [
                    'where_clause' => " WHERE posts.content LIKE '%" . $search_query . "%'",
                    'param_value' => '',
                    'is_vulnerable' => true
                ];
            case 'author':
                return [
                    'where_clause' => " WHERE users.username LIKE '%" . $search_query . "%'",
                    'param_value' => '',
                    'is_vulnerable' => true
                ];
            case 'all':
            default:
                return [
                    'where_clause' => " WHERE (posts.title LIKE '%" . $search_query . "%' OR posts.content LIKE '%" . $search_query . "%' OR users.username LIKE '%" . $search_query . "%')",
                    'param_value' => '',
                    'is_vulnerable' => true
                ];
        }
    }
    
    // 안전한 모드 - 기존 prepared statement 사용
    $param_value = '%' . $search_query . '%';
    
    switch ($search_by) {
        case 'title':
            return [
                'where_clause' => ' WHERE posts.title LIKE :search_param',
                'param_value' => $param_value,
                'is_vulnerable' => false
            ];
        case 'content':
            return [
                'where_clause' => ' WHERE posts.content LIKE :search_param',
                'param_value' => $param_value,
                'is_vulnerable' => false
            ];
        case 'author':
            return [
                'where_clause' => ' WHERE users.username LIKE :search_param',
                'param_value' => $param_value,
                'is_vulnerable' => false
            ];
        case 'all':
        default:
            return [
                'where_clause' => ' WHERE (posts.title LIKE :search_param OR posts.content LIKE :search_param OR users.username LIKE :search_param)',
                'param_value' => $param_value,
                'is_vulnerable' => false
            ];
    }
}

/**
 * 게시물 총 개수 조회
 * @param PDO $pdo 데이터베이스 연결
 * @param string $where_clause WHERE 절
 * @param string $param_value 검색 매개변수
 * @param bool $is_vulnerable 취약점 모드 여부
 * @return int 총 게시물 수
 */
function get_total_posts_count($pdo, $where_clause, $param_value, $is_vulnerable = false) {
    $sql = "SELECT COUNT(*) FROM posts JOIN users ON posts.user_id = users.id" . $where_clause;
    
    if ($is_vulnerable) {
        // 취약한 쿼리 실행 (교육 목적)
        try {
            $result = $pdo->query($sql);
            return (int)$result->fetchColumn();
        } catch (PDOException $e) {
            if (function_exists('log_database_error')) {
                log_database_error($sql, $e->getMessage(), ['vulnerability_mode' => true]);
            }
            return 0;
        }
    } else {
        // 안전한 prepared statement 사용
        $stmt = $pdo->prepare($sql);
        
        if (!empty($param_value)) {
            $stmt->bindValue(':search_param', $param_value, PDO::PARAM_STR);
        }
        
        $stmt->execute();
        return (int)$stmt->fetchColumn();
    }
}

/**
 * 페이지에 표시할 게시물 목록 조회
 * @param PDO $pdo 데이터베이스 연결
 * @param string $where_clause WHERE 절
 * @param string $param_value 검색 매개변수
 * @param int $limit 조회할 개수
 * @param int $offset 시작 위치
 * @param bool $is_vulnerable 취약점 모드 여부
 * @return array 게시물 목록
 */
function get_posts_for_page($pdo, $where_clause, $param_value, $limit, $offset, $is_vulnerable = false) {
    if ($is_vulnerable) {
        // 취약한 쿼리 실행 (교육 목적)
        $sql = "SELECT posts.id, posts.title, posts.user_id, users.username, posts.created_at 
                FROM posts 
                JOIN users ON posts.user_id = users.id" 
                . $where_clause . 
                " ORDER BY posts.created_at DESC LIMIT $limit OFFSET $offset";
        
        try {
            $result = $pdo->query($sql);
            return $result->fetchAll();
        } catch (PDOException $e) {
            if (function_exists('log_database_error')) {
                log_database_error($sql, $e->getMessage(), ['vulnerability_mode' => true]);
            }
            return [];
        }
    } else {
        // 안전한 prepared statement 사용
        $sql = "SELECT posts.id, posts.title, posts.user_id, users.username, posts.created_at 
                FROM posts 
                JOIN users ON posts.user_id = users.id" 
                . $where_clause . 
                " ORDER BY posts.created_at DESC LIMIT :limit OFFSET :offset";
        
        $stmt = $pdo->prepare($sql);
        
        if (!empty($param_value)) {
            $stmt->bindValue(':search_param', $param_value, PDO::PARAM_STR);
        }
        
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        
        $stmt->execute();
        return $stmt->fetchAll();
    }
}

/**
 * 페이지네이션 링크 생성
 * @param int $current_page 현재 페이지
 * @param int $total_pages 총 페이지 수
 * @param string $search_query 검색어
 * @param string $search_by 검색 필드
 * @return string 페이지네이션 HTML
 */
function generate_pagination_links($current_page, $total_pages, $search_query, $search_by) {
    $html = '<div class="pagination">';
    
    $query_params = '';
    if (!empty($search_query)) {
        $query_params = '&search=' . urlencode($search_query) . '&search_by=' . urlencode($search_by);
    }
    
    // 이전 페이지 링크
    if ($current_page > 1) {
        $prev_page = $current_page - 1;
        $html .= '<a href="?page=' . $prev_page . $query_params . '" class="btn">이전</a>';
    }
    
    // 페이지 번호 링크
    $start_page = max(1, $current_page - 2);
    $end_page = min($total_pages, $current_page + 2);
    
    for ($i = $start_page; $i <= $end_page; $i++) {
        $active_class = ($i == $current_page) ? ' active' : '';
        $html .= '<a href="?page=' . $i . $query_params . '" class="btn' . $active_class . '">' . $i . '</a>';
    }
    
    // 다음 페이지 링크
    if ($current_page < $total_pages) {
        $next_page = $current_page + 1;
        $html .= '<a href="?page=' . $next_page . $query_params . '" class="btn">다음</a>';
    }
    
    $html .= '</div>';
    return $html;
}

// 메인 로직 시작
try {
    // 사용자 입력 처리
    $search_query = clean_input($_GET['search'] ?? '');
    $search_by = clean_input($_GET['search_by'] ?? 'all');
    $current_page = max(1, (int)($_GET['page'] ?? 1));
    
    // 읽지 않은 알림 수 조회
    $unread_notifications_count = 0;
    if (is_logged_in()) {
        $unread_notifications_count = get_unread_notifications_count($pdo, $_SESSION['user_id']);
    }
    
    // 검색 조건 생성
    $search_condition = build_search_condition($search_query, $search_by);
    $is_vulnerable = $search_condition['is_vulnerable'] ?? false;
    
    // 페이지네이션 계산
    $total_posts = get_total_posts_count($pdo, $search_condition['where_clause'], $search_condition['param_value'], $is_vulnerable);
    $pagination = calculate_pagination($total_posts, POSTS_PER_PAGE, $current_page);
    
    // 게시물 목록 조회
    $posts = get_posts_for_page(
        $pdo, 
        $search_condition['where_clause'], 
        $search_condition['param_value'], 
        POSTS_PER_PAGE, 
        $pagination['offset'],
        $is_vulnerable
    );
    
} catch (Exception $e) {
    error_log("Error in index.php: " . $e->getMessage());
    $error_message = DEBUG_MODE ? $e->getMessage() : "페이지를 불러오는 중 오류가 발생했습니다.";
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?></title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.2/font/bootstrap-icons.css">
    <!-- Custom CSS -->
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <!-- Bootstrap 네비게이션 바 -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary sticky-top shadow">
        <div class="container">
            <a class="navbar-brand fw-bold" href="index.php">
                <i class="bi bi-journal-text"></i> <?php echo SITE_NAME; ?>
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <div class="navbar-nav ms-auto">
                    <?php if (is_logged_in()): ?>
                        <span class="navbar-text me-3">
                            <i class="bi bi-person-circle"></i> 환영합니다, <strong><?php echo safe_output($_SESSION['username']); ?></strong>님!
                        </span>
                        
                        <a href="notifications.php" class="nav-link position-relative me-2">
                            <i class="bi bi-bell"></i> 알림
                            <?php if ($unread_notifications_count > 0): ?>
                                <span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">
                                    <?php echo $unread_notifications_count; ?>
                                </span>
                            <?php endif; ?>
                        </a>
                        
                        <a href="create_post.php" class="nav-link me-2">
                            <i class="bi bi-plus-circle"></i> 새 게시물
                        </a>
                        
                        <?php if (is_admin()): ?>
                            <a href="admin.php" class="nav-link me-2">
                                <i class="bi bi-gear"></i> 관리
                            </a>
                        <?php elseif (DEBUG_MODE): ?>
                            <a href="make_admin.php" class="nav-link me-2 text-warning">
                                <i class="bi bi-tools"></i> 관리자 되기
                            </a>
                        <?php endif; ?>
                        
                        <a href="webhacking/index.php" class="nav-link me-2">
                            <i class="bi bi-shield-exclamation"></i> 보안 테스트
                        </a>
                        
                        <a href="logout.php" class="nav-link">
                            <i class="bi bi-box-arrow-right"></i> 로그아웃
                        </a>
                    <?php else: ?>
                        <a href="login.php" class="nav-link me-2">
                            <i class="bi bi-box-arrow-in-right"></i> 로그인
                        </a>
                        <a href="register.php" class="nav-link me-2">
                            <i class="bi bi-person-plus"></i> 회원가입
                        </a>
                        <?php if (DEBUG_MODE): ?>
                            <a href="make_admin.php" class="nav-link text-warning">
                                <i class="bi bi-tools"></i> 관리자 설정
                            </a>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </nav>

    <!-- 취약점 모드 경고 -->
    <?php if (defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true): ?>
        <div class="alert alert-warning alert-dismissible fade show m-0 rounded-0" role="alert">
            <div class="container">
                <i class="bi bi-exclamation-triangle-fill"></i>
                <strong>취약점 테스트 모드 활성화</strong> - 교육 목적으로만 사용하세요
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        </div>
    <?php endif; ?>

    <div class="container mt-4">

        <!-- 에러 메시지 표시 -->
        <?php if (isset($error_message)): ?>
            <?php echo show_error_message($error_message); ?>
        <?php endif; ?>

        <!-- 검색 폼 -->
        <div class="card shadow-sm mb-4">
            <div class="card-body">
                <form method="get" action="index.php" class="row g-3">
                    <div class="col-md-3">
                        <select name="search_by" class="form-select" aria-label="검색 범위">
                            <option value="all" <?php echo ($search_by === 'all') ? 'selected' : ''; ?>>전체</option>
                            <option value="title" <?php echo ($search_by === 'title') ? 'selected' : ''; ?>>제목</option>
                            <option value="content" <?php echo ($search_by === 'content') ? 'selected' : ''; ?>>내용</option>
                            <option value="author" <?php echo ($search_by === 'author') ? 'selected' : ''; ?>>작성자</option>
                        </select>
                    </div>
                    <div class="col-md-7">
                        <input type="text" 
                               name="search" 
                               class="form-control"
                               placeholder="검색어를 입력하세요" 
                               value="<?php echo safe_output($search_query); ?>"
                               aria-label="검색어">
                    </div>
                    <div class="col-md-2">
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="bi bi-search"></i> 검색
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- 게시물 목록 -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2 class="h4 mb-0">
                <i class="bi bi-journal-text"></i> 게시물 목록 
                <span class="badge bg-secondary"><?php echo number_format($total_posts); ?>개</span>
            </h2>
            <?php if (is_logged_in()): ?>
                <a href="create_post.php" class="btn btn-success">
                    <i class="bi bi-plus-circle"></i> 새 게시물 작성
                </a>
            <?php endif; ?>
        </div>
        
        <?php if (empty($posts)): ?>
            <div class="card text-center py-5">
                <div class="card-body">
                    <i class="bi bi-journal-x display-1 text-muted"></i>
                    <h3 class="mt-3 text-muted">게시물이 없습니다</h3>
                    <p class="text-muted">첫 번째 게시물을 작성해보세요!</p>
                    <?php if (is_logged_in()): ?>
                        <a href="create_post.php" class="btn btn-primary mt-3">
                            <i class="bi bi-plus-circle"></i> 첫 번째 게시물 작성하기
                        </a>
                    <?php endif; ?>
                </div>
            </div>
        <?php else: ?>
            <div class="row g-4">
                <?php foreach ($posts as $post): ?>
                    <?php 
                    $thumbnail_path = get_first_image_attachment($pdo, $post['id']);
                    $categories = get_post_categories($pdo, $post['id']);
                    ?>
                    <div class="col-lg-6 col-xl-4">
                        <div class="card h-100 shadow-sm post-card">
                            <?php if ($thumbnail_path): ?>
                                <img src="<?php echo safe_output($thumbnail_path); ?>" 
                                     class="card-img-top" 
                                     alt="게시물 미리보기"
                                     style="height: 200px; object-fit: cover;">
                            <?php else: ?>
                                <div class="card-img-top bg-light d-flex align-items-center justify-content-center" style="height: 200px;">
                                    <i class="bi bi-image text-muted" style="font-size: 3rem;"></i>
                                </div>
                            <?php endif; ?>
                            
                            <div class="card-body d-flex flex-column">
                                <h5 class="card-title mb-2">
                                    <a href="view_post.php?id=<?php echo $post['id']; ?>" class="text-decoration-none text-dark">
                                        <?php echo safe_output($post['title']); ?>
                                    </a>
                                </h5>
                                
                                <div class="mb-2">
                                    <?php if (!empty($categories)): ?>
                                        <?php foreach ($categories as $category): ?>
                                            <span class="badge bg-primary me-1">
                                                <?php echo safe_output($category['name']); ?>
                                            </span>
                                        <?php endforeach; ?>
                                    <?php else: ?>
                                        <span class="badge bg-secondary">미분류</span>
                                    <?php endif; ?>
                                </div>
                                
                                <div class="mt-auto">
                                    <div class="d-flex justify-content-between align-items-center text-muted small">
                                        <div>
                                            <i class="bi bi-person"></i>
                                            <a href="profile.php?id=<?php echo $post['user_id']; ?>" class="text-decoration-none text-muted">
                                                <?php echo safe_output($post['username']); ?>
                                            </a>
                                        </div>
                                        <div>
                                            <i class="bi bi-calendar3"></i>
                                            <?php echo format_date($post['created_at']); ?>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
            
            <!-- 페이지네이션 -->
            <?php if ($pagination['total_pages'] > 1): ?>
                <nav aria-label="게시물 페이지네이션" class="mt-5">
                    <ul class="pagination justify-content-center">
                        <?php if ($pagination['has_previous']): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?php echo $current_page - 1; ?><?php echo !empty($search_query) ? '&search=' . urlencode($search_query) . '&search_by=' . urlencode($search_by) : ''; ?>">
                                    <i class="bi bi-chevron-left"></i> 이전
                                </a>
                            </li>
                        <?php endif; ?>
                        
                        <?php 
                        $start_page = max(1, $current_page - 2);
                        $end_page = min($pagination['total_pages'], $current_page + 2);
                        ?>
                        
                        <?php for ($i = $start_page; $i <= $end_page; $i++): ?>
                            <li class="page-item <?php echo ($i == $current_page) ? 'active' : ''; ?>">
                                <a class="page-link" href="?page=<?php echo $i; ?><?php echo !empty($search_query) ? '&search=' . urlencode($search_query) . '&search_by=' . urlencode($search_by) : ''; ?>">
                                    <?php echo $i; ?>
                                </a>
                            </li>
                        <?php endfor; ?>
                        
                        <?php if ($pagination['has_next']): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?php echo $current_page + 1; ?><?php echo !empty($search_query) ? '&search=' . urlencode($search_query) . '&search_by=' . urlencode($search_by) : ''; ?>">
                                    다음 <i class="bi bi-chevron-right"></i>
                                </a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </nav>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- Footer -->
    <footer class="bg-light mt-5 py-4">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <h5><i class="bi bi-journal-text"></i> <?php echo SITE_NAME; ?></h5>
                    <p class="text-muted">현대적인 게시판 시스템과 보안 테스트 환경</p>
                </div>
                <div class="col-md-6 text-md-end">
                    <div class="mb-2">
                        <a href="webhacking/index.php" class="text-decoration-none me-3">
                            <i class="bi bi-shield-exclamation"></i> 보안 테스트
                        </a>
                        <?php if (is_admin()): ?>
                            <a href="admin.php" class="text-decoration-none">
                                <i class="bi bi-gear"></i> 관리자
                            </a>
                        <?php endif; ?>
                    </div>
                    <small class="text-muted">
                        &copy; <?php echo date('Y'); ?> <?php echo SITE_NAME; ?>. 교육 목적으로 제작됨.
                    </small>
                </div>
            </div>
        </div>
    </footer>

    <!-- Bootstrap JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Custom JavaScript -->
    <script>
        // 카드 호버 효과
        document.querySelectorAll('.post-card').forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.classList.add('shadow');
            });
            
            card.addEventListener('mouseleave', function() {
                this.classList.remove('shadow');
                this.classList.add('shadow-sm');
            });
        });
        
        // 검색 폼 엔터키 지원
        document.querySelector('input[name="search"]')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.target.closest('form').submit();
            }
        });

        // 알림 개수 애니메이션
        const notificationBadge = document.querySelector('.badge.bg-danger');
        if (notificationBadge) {
            notificationBadge.style.animation = 'pulse 2s infinite';
        }
    </script>
</body>
</html>