<?php
// 출력 버퍼링 시작 (헤더 전송 문제 방지)
ob_start();

// 세션 시작 (TestPage 전에)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . "/../db.php";
require_once __DIR__ . "/../utils.php";

// 로그인 확인
if (!is_logged_in()) {
    header("Location: ../login.php");
    exit();
}

require_once '../config.php';
require_once '../utils.php';

$page_title = 'Insecure Source Code Management';
$page_description = 'A vulnerability that involves exposing sensitive information through version control systems.';

include '../header.php';
?>

<div class="container">
    <h1 class="mt-5">Insecure Source Code Management</h1>
    <p class="lead">This page demonstrates a vulnerability related to insecure source code management.</p>

    <div class="alert alert-warning">
        <strong>Note:</strong> This type of vulnerability is typically found through reconnaissance and not through a specific script. It's a result of misconfiguration.
    </div>

    <h2>Explanation</h2>
    <p>Insecure source code management can expose sensitive information, such as credentials, API keys, or internal logic, to the public. This often happens when version control repositories, like Git, are accidentally exposed to the web.</p>

    <h2>Scenario</h2>
    <p>A common example is the exposure of the <code>.git</code> directory in the web root. If an attacker can access this directory, they can potentially download the entire source code of the application, including its history. This could reveal sensitive information that was committed at some point, even if it was later removed.</p>

    <p>For example, an attacker might try to access <code>/.git/config</code> or <code>/.git/logs/HEAD</code> to gather information about the repository and its commit history.</p>

    <p>To test for this, you would typically use a tool to check for the existence of a <code>.git</code> directory on the web server, like so:</p>
    <pre>curl https://vulnerable-website.com/.git/</pre>

    <p>If the server responds with the contents of the directory, it is vulnerable.</p>

</div>

<?php
include '../footer.php';
?>
