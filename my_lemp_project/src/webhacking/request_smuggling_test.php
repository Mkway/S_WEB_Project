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

$page_title = 'Request Smuggling';
$page_description = 'A vulnerability that involves interfering with the processing of a sequence of HTTP requests.';

include '../header.php';
?>

<div class="container">
    <h1 class="mt-5">Request Smuggling</h1>
    <p class="lead">This page demonstrates a Request Smuggling vulnerability.</p>

    <div class="alert alert-warning">
        <strong>Note:</strong> True Request Smuggling is difficult to demonstrate in a simple PHP script as it depends on the architecture of the web server and any proxy servers.
    </div>

    <h2>Explanation</h2>
    <p>Request Smuggling vulnerabilities arise when the frontend and backend servers interpret the boundaries of HTTP requests differently. This can allow an attacker to prepend or "smuggle" a second request into the body of a legitimate request.</p>

    <h2>Scenario</h2>
    <p>Imagine a scenario where a frontend proxy server uses the <code>Content-Length</code> header to determine the end of a request, while the backend server uses the <code>Transfer-Encoding</code> header. An attacker can craft a request that is interpreted as a single request by the frontend, but as two separate requests by the backend.</p>

    <pre>
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
    </pre>

    <p>In this example, the frontend server sees a single request with a body of "0\r\n\r\nSMUGGLED". The backend server, however, sees a chunked request that ends after the "0", and then starts processing a new request beginning with "SMUGGLED".</p>

</div>

<?php
include '../footer.php';
?>
