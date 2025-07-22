<?php
session_start();
require_once 'db.php';

// Fetch unread notification count for logged-in user
$unread_notifications_count = 0;
if (isset($_SESSION['user_id'])) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
    $stmt->execute([$_SESSION['user_id']]);
    $unread_notifications_count = $stmt->fetchColumn();
}

// Search parameters
$search_query = isset($_GET['search']) ? trim($_GET['search']) : '';
$search_by = isset($_GET['search_by']) ? $_GET['search_by'] : 'all'; // Default to 'all'

// Pagination settings
$posts_per_page = 10;
$current_page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$offset = ($current_page - 1) * $posts_per_page;

// Build WHERE clause for search
$where_clause = '';
$search_param_value = '';

if (!empty($search_query)) {
    $search_param_value = '%' . $search_query . '%';
    switch ($search_by) {
        case 'title':
            $where_clause = " WHERE posts.title LIKE :search_param";
            break;
        case 'content':
            $where_clause = " WHERE posts.content LIKE :search_param";
            break;
        case 'author':
            $where_clause = " WHERE users.username LIKE :search_param";
            break;
        case 'all':
        default:
            $where_clause = " WHERE (posts.title LIKE :search_param OR posts.content LIKE :search_param OR users.username LIKE :search_param)";
            break;
    }
}

// Category filter
$category_filter_clause = '';
if (isset($_GET['category']) && !empty($_GET['category'])) {
    $category_id = (int)$_GET['category'];
    $category_filter_clause = " JOIN post_categories pc ON posts.id = pc.post_id WHERE pc.category_id = :category_id";
    if (!empty($where_clause)) {
        $category_filter_clause = str_replace('WHERE', 'AND', $category_filter_clause); // Change JOIN...WHERE to JOIN...AND if search is also active
    } else {
        $category_filter_clause = str_replace('JOIN', ' JOIN', $category_filter_clause); // Ensure space before JOIN
    }
}

// Get total number of posts (with search filter)
$total_posts_sql = "SELECT COUNT(*) FROM posts JOIN users ON posts.user_id = users.id" . $where_clause;
$total_posts_stmt = $pdo->prepare($total_posts_sql);
if (!empty($search_query)) {
    $total_posts_stmt->bindValue(':search_param', $search_param_value, PDO::PARAM_STR);
}
$total_posts_stmt->execute();
$total_posts = $total_posts_stmt->fetchColumn();
$total_pages = ceil($total_posts / $posts_per_page);

// Fetch posts for the current page (with search filter)
$posts_sql = "SELECT posts.id, posts.title, posts.user_id, users.username FROM posts JOIN users ON posts.user_id = users.id" . $where_clause . " ORDER BY posts.created_at DESC LIMIT :limit OFFSET :offset";
$stmt = $pdo->prepare($posts_sql);

if (!empty($search_query)) {
    $stmt->bindValue(':search_param', $search_param_value, PDO::PARAM_STR);
}
$stmt->bindValue(':limit', $posts_per_page, PDO::PARAM_INT);
$stmt->bindValue(':offset', $offset, PDO::PARAM_INT);

$stmt->execute();
$posts = $stmt->fetchAll();

// Function to get the first image attachment for a post
function getFirstImageAttachment($pdo, $post_id) {
    $stmt = $pdo->prepare("SELECT filepath FROM files WHERE post_id = ? AND (filename LIKE '%.jpg' OR filename LIKE '%.jpeg' OR filename LIKE '%.png' OR filename LIKE '%.gif' OR filename LIKE '%.webp') LIMIT 1");
    $stmt->execute([$post_id]);
    return $stmt->fetchColumn();
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>My Board</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="nav">
            <h1>My Board</h1>
            <div>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</span>
                    <a href="notifications.php" class="btn">Notifications <?php if ($unread_notifications_count > 0): ?>(<span style="color: red;"><?php echo $unread_notifications_count; ?></span>)<?php endif; ?></a>
                    <a href="logout.php" class="btn">Logout</a>
                    <a href="create_post.php" class="btn">New Post</a>
                    <a href="../webhacking/index.php" class="btn">Security Tests</a>
                <?php else: ?>
                    <a href="login.php" class="btn">Login</a>
                    <a href="register.php" class="btn">Register</a>
                <?php endif; ?>
            </div>
        </div>

        <form method="get" action="index.php" style="margin-bottom: 20px;">
            <select name="search_by">
                <option value="all" <?php echo ($search_by == 'all') ? 'selected' : ''; ?>>All</option>
                <option value="title" <?php echo ($search_by == 'title') ? 'selected' : ''; ?>>Title</option>
                <option value="content" <?php echo ($search_by == 'content') ? 'selected' : ''; ?>>Content</option>
                <option value="author" <?php echo ($search_by == 'author') ? 'selected' : ''; ?>>Author</option>
            </select>
            <input type="text" name="search" placeholder="Search keyword" value="<?php echo htmlspecialchars($search_query); ?>">
            <button type="submit" class="btn">Search</button>
        </form>

        <h2>Posts</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 60px;"></th> <!-- For thumbnail -->
                    <th>Title</th>
                    <th>Author</th>
                    <th>Categories</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($posts as $post):
                    $thumbnail_path = getFirstImageAttachment($pdo, $post['id']);
                ?>
                    <tr>
                        <td>
                            <?php if ($thumbnail_path): ?>
                                <div class="thumbnail-container">
                                    <img src="<?php echo htmlspecialchars($thumbnail_path); ?>" alt="Thumbnail" class="post-thumbnail">
                                    <div class="thumbnail-popup">
                                        <img src="<?php echo htmlspecialchars($thumbnail_path); ?>" alt="Full Image">
                                    </div>
                                </div>
                            <?php endif; ?>
                        </td>
                        <td><a href="view_post.php?id=<?php echo $post['id']; ?>"><?php echo htmlspecialchars($post['title']); ?></a></td>
                        <td><a href="profile.php?id=<?php echo $post['user_id']; ?>"><?php echo htmlspecialchars($post['username']); ?></a></td>
                        <td>
                            <?php
                            $categories_stmt = $pdo->prepare("SELECT c.id, c.name FROM categories c JOIN post_categories pc ON c.id = pc.category_id WHERE pc.post_id = ?");
                            $categories_stmt->execute([$post['id']]);
                            $categories = $categories_stmt->fetchAll();
                            foreach ($categories as $index => $category) {
                                echo '<a href="index.php?category=' . $category['id'] . '">' . htmlspecialchars($category['name']) . '</a>';
                                if ($index < count($categories) - 1) {
                                    echo ', ';
                                }
                            }
                            ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <div class="pagination" style="margin-top: 20px; text-align: center;">
            <?php if ($current_page > 1): ?>
                <a href="?page=<?php echo $current_page - 1; ?><?php echo !empty($search_query) ? '&search=' . urlencode($search_query) . '&search_by=' . urlencode($search_by) : ''; ?>" class="btn">Previous</a>
            <?php endif; ?>

            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                <a href="?page=<?php echo $i; ?><?php echo !empty($search_query) ? '&search=' . urlencode($search_query) . '&search_by=' . urlencode($search_by) : ''; ?>" class="btn <?php echo ($i == $current_page) ? 'active' : ''; ?>"><?php echo $i; ?></a>
            <?php endfor; ?>

            <?php if ($current_page < $total_pages): ?>
                <a href="?page=<?php echo $current_page + 1; ?><?php echo !empty($search_query) ? '&search=' . urlencode($search_query) . '&search_by=' . urlencode($search_by) : ''; ?>" class="btn">Next</a>
            <?php endif; ?>
        </div>
    </div>

    <script>
        document.querySelectorAll('.thumbnail-container').forEach(container => {
            const popup = container.querySelector('.thumbnail-popup');

            container.addEventListener('mouseenter', () => {
                popup.style.display = 'block';
            });

            container.addEventListener('mouseleave', () => {
                popup.style.display = 'none';
            });
        });
    </script>
</body>
</html>