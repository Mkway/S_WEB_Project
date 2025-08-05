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
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1><?php echo SITE_NAME; ?></h1>
            <?php if (defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true): ?>
                <div class="vulnerability-mode-warning">
                    ⚠️ 취약점 테스트 모드 활성화 (교육 목적)
                </div>
            <?php endif; ?>
            <div class="nav-links">
                <?php if (is_logged_in()): ?>
                    <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                    <a href="notifications.php" class="btn">
                        알림 
                        <?php if ($unread_notifications_count > 0): ?>
                            <span class="notification-count"><?php echo $unread_notifications_count; ?></span>
                        <?php endif; ?>
                    </a>
                    <a href="logout.php" class="btn">로그아웃</a>
                    <a href="create_post.php" class="btn">새 게시물</a>
                    <?php if (is_admin()): ?>
                        <a href="admin.php" class="btn">관리</a>
                    <?php endif; ?>
                    <a href="../webhacking/index.php" class="btn">보안 테스트</a>
                <?php else: ?>
                    <a href="login.php" class="btn">로그인</a>
                    <a href="register.php" class="btn">회원가입</a>
                <?php endif; ?>
            </div>
        </nav>

        <!-- 에러 메시지 표시 -->
        <?php if (isset($error_message)): ?>
            <?php echo show_error_message($error_message); ?>
        <?php endif; ?>

        <!-- 검색 폼 -->
        <form method="get" action="index.php" class="search-form">
            <div class="search-controls">
                <select name="search_by" aria-label="검색 범위">
                    <option value="all" <?php echo ($search_by === 'all') ? 'selected' : ''; ?>>전체</option>
                    <option value="title" <?php echo ($search_by === 'title') ? 'selected' : ''; ?>>제목</option>
                    <option value="content" <?php echo ($search_by === 'content') ? 'selected' : ''; ?>>내용</option>
                    <option value="author" <?php echo ($search_by === 'author') ? 'selected' : ''; ?>>작성자</option>
                </select>
                <input type="text" 
                       name="search" 
                       placeholder="검색어를 입력하세요" 
                       value="<?php echo safe_output($search_query); ?>"
                       aria-label="검색어">
                <button type="submit" class="btn">검색</button>
            </div>
        </form>

        <!-- 게시물 목록 -->
        <section class="posts-section">
            <h2>게시물 목록 (총 <?php echo number_format($total_posts); ?>개)</h2>
            
            <?php if (empty($posts)): ?>
                <div class="no-posts">
                    <p>게시물이 없습니다.</p>
                    <?php if (is_logged_in()): ?>
                        <a href="create_post.php" class="btn">첫 번째 게시물 작성하기</a>
                    <?php endif; ?>
                </div>
            <?php else: ?>
                <div class="table-container">
                    <table class="posts-table">
                        <thead>
                            <tr>
                                <th class="thumbnail-col">미리보기</th>
                                <th class="title-col">제목</th>
                                <th class="author-col">작성자</th>
                                <th class="date-col">작성일</th>
                                <th class="category-col">카테고리</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($posts as $post): ?>
                                <?php 
                                $thumbnail_path = get_first_image_attachment($pdo, $post['id']);
                                $categories = get_post_categories($pdo, $post['id']);
                                ?>
                                <tr>
                                    <td class="thumbnail-cell">
                                        <?php if ($thumbnail_path): ?>
                                            <div class="thumbnail-container">
                                                <img src="<?php echo safe_output($thumbnail_path); ?>" 
                                                     alt="게시물 미리보기" 
                                                     class="post-thumbnail">
                                                <div class="thumbnail-popup">
                                                    <img src="<?php echo safe_output($thumbnail_path); ?>" 
                                                         alt="게시물 이미지">
                                                </div>
                                            </div>
                                        <?php endif; ?>
                                    </td>
                                    <td class="post-title">
                                        <a href="view_post.php?id=<?php echo $post['id']; ?>">
                                            <?php echo safe_output($post['title']); ?>
                                        </a>
                                    </td>
                                    <td class="author-cell">
                                        <a href="profile.php?id=<?php echo $post['user_id']; ?>">
                                            <?php echo safe_output($post['username']); ?>
                                        </a>
                                    </td>
                                    <td class="date-cell">
                                        <?php echo format_date($post['created_at']); ?>
                                    </td>
                                    <td class="category-cell">
                                        <?php if (!empty($categories)): ?>
                                            <?php foreach ($categories as $index => $category): ?>
                                                <a href="index.php?category=<?php echo $category['id']; ?>" class="category-tag">
                                                    <?php echo safe_output($category['name']); ?>
                                                </a>
                                                <?php if ($index < count($categories) - 1): ?>
                                                    <span class="category-separator">,</span>
                                                <?php endif; ?>
                                            <?php endforeach; ?>
                                        <?php else: ?>
                                            <span class="no-category">-</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                
                <!-- 페이지네이션 -->
                <?php if ($pagination['total_pages'] > 1): ?>
                    <div class="pagination-wrapper">
                        <?php echo generate_pagination_links($current_page, $pagination['total_pages'], $search_query, $search_by); ?>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        </section>
    </div>

    <!-- JavaScript -->
    <script>
        // 썸네일 팝업 기능
        document.querySelectorAll('.thumbnail-container').forEach(container => {
            const popup = container.querySelector('.thumbnail-popup');
            
            container.addEventListener('mouseenter', () => {
                popup.style.display = 'block';
            });
            
            container.addEventListener('mouseleave', () => {
                popup.style.display = 'none';
            });
        });
        
        // 검색 폼 자동 제출 (엔터키)
        document.querySelector('input[name="search"]').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.target.closest('form').submit();
            }
        });
    </script>
</body>
</html>