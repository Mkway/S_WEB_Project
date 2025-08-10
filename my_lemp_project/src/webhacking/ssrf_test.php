<?php
// SSRF (Server-Side Request Forgery) Vulnerability Test Page

// This page demonstrates a basic Server-Side Request Forgery vulnerability.
// An SSRF vulnerability allows an attacker to induce the server-side application
// to make HTTP requests to an arbitrary domain specified by the attacker.
// This can be used to target internal systems behind firewalls, access local files,
// or interact with other services that the server has access to.

// --- How it works ---
// The application takes a URL as input from the user and then fetches the content
// from that URL using a server-side function (e.g., file_get_contents(), curl).
// If the input is not properly validated, an attacker can supply internal IP addresses,
// localhost, or file paths, causing the server to make requests to these locations.

// --- Exploitation Examples ---
// 1. Accessing internal network resources: http://localhost/admin
// 2. Accessing cloud metadata services (AWS EC2): http://169.254.169.254/latest/meta-data/
// 3. Reading local files (if file:// protocol is allowed): file:///etc/passwd

// --- Mitigation ---
// - Validate and sanitize user-supplied URLs: Use a whitelist of allowed domains/protocols.
// - Disable unused URL schemas (e.g., file://, gopher://, ftp://).
// - Implement network segmentation and firewall rules to restrict outbound connections.
// - Use a URL parsing library to ensure the URL points to an expected host.

$result = '';
$url = '';

if (isset($_GET['url'])) {
    $url = $_GET['url'];
    // Vulnerable code: Directly using user input in file_get_contents()
    // without proper validation or sanitization.
    // This allows an attacker to make the server request arbitrary URLs.
    $result = @file_get_contents($url);

    if ($result === false) {
        $result = "Error: Could not fetch content from the provided URL. This might be due to an invalid URL, network issues, or restricted access.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSRF (Server-Side Request Forgery) Test</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        h1, h2 {
            color: #333;
        }
        .vulnerability-description, .mitigation-guide {
            background-color: #f9f9f9;
            border-left: 5px solid #f39c12;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .mitigation-guide {
            border-color: #28a745;
        }
        form {
            margin-bottom: 20px;
        }
        input[type="text"] {
            width: 70%;
            padding: 10px;
            margin-right: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        input[type="submit"] {
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #0056b3;
        }
        pre {
            background-color: #eee;
            padding: 15px;
            border-radius: 4px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .error {
            color: red;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SSRF (Server-Side Request Forgery) Test Page</h1>

        <div class="vulnerability-description">
            <h2>Vulnerability Description</h2>
            <p>This page is intentionally vulnerable to SSRF. It fetches content from a URL provided by the user without sufficient validation. An attacker can exploit this to make the server perform requests to internal resources or other external services.</p>
            <p><strong>Try fetching:</strong></p>
            <ul>
                <li><code>http://localhost/</code> (or <code>http://127.0.0.1/</code>) to see the server's own index page.</li>
                <li><code>file:///etc/passwd</code> (on Linux systems) to attempt reading a local file.</li>
                <li>An external URL like <code>https://example.com</code>.</li>
            </ul>
        </div>

        <form action="" method="GET">
            <label for="url">Enter URL to fetch:</label><br>
            <input type="text" id="url" name="url" value="<?php echo htmlspecialchars($url); ?>" placeholder="e.g., http://localhost/ or file:///etc/passwd">
            <input type="submit" value="Fetch Content">
        </form>

        <?php if (!empty($result)): ?>
            <h2>Result:</h2>
            <pre><?php echo htmlspecialchars($result); ?></pre>
        <?php endif; ?>

        <div class="mitigation-guide">
            <h2>Mitigation Guide</h2>
            <p>To prevent SSRF, always validate and sanitize user-supplied URLs. Consider using a whitelist of allowed domains and protocols. Implement network segmentation and firewall rules to restrict outbound connections from your application server.</p>
        </div>

        <p><a href="index.php">Back to Web Hacking Index</a></p>
    </div>
</body>
</html>