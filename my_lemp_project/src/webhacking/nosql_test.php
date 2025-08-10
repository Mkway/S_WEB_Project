<?php
/**
 * NoSQL Injection 취약점 테스트 페이지
 * 교육 목적으로만 사용하시기 바랍니다.
 */

session_start();
require_once '../db.php';
require_once '../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

$result = '';
$query_input = '';
$db_type = 'mongodb';

// NoSQL Injection 공격 시뮬레이션
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['query'])) {
    $query_input = $_POST['query'];
    $db_type = $_POST['db_type'] ?? 'mongodb';
    
    if (empty($query_input)) {
        $result = "NoSQL 쿼리를 입력해주세요.";
    } else {
        // 교육 목적의 NoSQL Injection 시뮬레이션
        $dangerous_patterns = [
            'mongodb' => ['$where', '$regex', '$ne', '$gt', '$lt', '$in', '$nin', '$or', '$and', '$not'],
            'couchdb' => ['_design', '_view', 'emit', 'function', 'eval'],
            'redis' => ['EVAL', 'SCRIPT', 'CONFIG', 'FLUSHALL', 'SHUTDOWN'],
            'elasticsearch' => ['script', '_source', 'query', 'bool', 'must'],
            'cassandra' => ['DROP', 'TRUNCATE', 'ALTER', 'CREATE', 'ALLOW FILTERING']
        ];
        
        $payload_detected = false;
        $detected_patterns = [];
        
        foreach ($dangerous_patterns[$db_type] as $pattern) {
            if (stripos($query_input, $pattern) !== false) {
                $payload_detected = true;
                $detected_patterns[] = $pattern;
            }
        }
        
        if ($payload_detected) {
            $result = "[시뮬레이션] NoSQL Injection 공격 감지됨\n";
            $result .= "데이터베이스 유형: " . strtoupper($db_type) . "\n";
            $result .= "감지된 패턴: " . implode(', ', $detected_patterns) . "\n\n";
            
            // DB별 특화된 경고 메시지
            switch ($db_type) {
                case 'mongodb':
                    $result .= "MongoDB Injection 공격 시나리오:\n";
                    $result .= "- 인증 우회: {username: {\$ne: null}, password: {\$ne: null}}\n";
                    $result .= "- 데이터 추출: {username: {\$regex: '^admin'}}\n";
                    $result .= "- JavaScript 실행: {\$where: 'this.username == \"admin\"'}\n";
                    $result .= "- 운영자 악용: {age: {\$gt: 0, \$lt: 999}}\n";
                    break;
                    
                case 'couchdb':
                    $result .= "CouchDB Injection 공격 시나리오:\n";
                    $result .= "- 뷰 조작: _design/malicious/_view/all\n";
                    $result .= "- JavaScript 실행: function(doc){emit(doc._id, eval('malicious_code'))}\n";
                    $result .= "- 데이터베이스 열거: _all_dbs\n";
                    break;
                    
                case 'redis':
                    $result .= "Redis Injection 공격 시나리오:\n";
                    $result .= "- Lua 스크립트 실행: EVAL 'redis.call(\"flushall\")' 0\n";
                    $result .= "- 설정 변경: CONFIG SET dir /var/www/html/\n";
                    $result .= "- 데이터 삭제: FLUSHALL\n";
                    break;
                    
                case 'elasticsearch':
                    $result .= "Elasticsearch Injection 공격 시나리오:\n";
                    $result .= "- 스크립트 실행: {\"script\": \"ctx._source.password = 'hacked'\"}\n";
                    $result .= "- 전체 데이터 조회: {\"query\": {\"match_all\": {}}}\n";
                    $result .= "- 인덱스 조작: DELETE /sensitive_index\n";
                    break;
                    
                case 'cassandra':
                    $result .= "Cassandra Injection 공격 시나리오:\n";
                    $result .= "- 테이블 삭제: DROP TABLE users;\n";
                    $result .= "- 데이터 전체 조회: SELECT * FROM users ALLOW FILTERING;\n";
                    $result .= "- 키스페이스 변경: ALTER KEYSPACE test WITH REPLICATION = {};\n";
                    break;
            }
        } else {
            // 안전한 쿼리 처리 시뮬레이션
            $result = "안전한 NoSQL 쿼리 처리 완료:\n";
            $result .= "데이터베이스 유형: " . strtoupper($db_type) . "\n";
            $result .= "입력된 쿼리가 정상적으로 처리되었습니다.\n";
            $result .= "위험한 패턴이 감지되지 않았습니다.\n\n";
            
            // 예상 결과 시뮬레이션
            switch ($db_type) {
                case 'mongodb':
                    $result .= "예상 MongoDB 쿼리 결과:\n";
                    $result .= "db.users.find(" . $query_input . ")\n";
                    $result .= "→ 정상적인 문서 조회 수행됨";
                    break;
                    
                case 'couchdb':
                    $result .= "예상 CouchDB 쿼리 결과:\n";
                    $result .= "GET /database/_find\n";
                    $result .= "→ 정상적인 문서 검색 수행됨";
                    break;
                    
                case 'redis':
                    $result .= "예상 Redis 명령 결과:\n";
                    $result .= $query_input . "\n";
                    $result .= "→ 정상적인 키-값 조작 수행됨";
                    break;
                    
                case 'elasticsearch':
                    $result .= "예상 Elasticsearch 쿼리 결과:\n";
                    $result .= "GET /index/_search\n";
                    $result .= "→ 정상적인 검색 쿼리 수행됨";
                    break;
                    
                case 'cassandra':
                    $result .= "예상 Cassandra 쿼리 결과:\n";
                    $result .= $query_input . "\n";
                    $result .= "→ 정상적인 CQL 쿼리 수행됨";
                    break;
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NoSQL Injection 테스트 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 900px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
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
        textarea {
            width: 100%;
            height: 150px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        select {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin: 10px 0;
            width: 200px;
        }
        .payload-btn {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 8px 12px;
            margin: 5px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .payload-btn:hover {
            background: #138496;
        }
        .nav {
            background: #343a40;
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .nav h1 {
            margin: 0;
            color: white;
        }
        .nav-links .btn {
            margin-left: 10px;
            background: #007bff;
            color: white;
            text-decoration: none;
            padding: 8px 15px;
            border-radius: 4px;
        }
        .db-tabs {
            margin: 15px 0;
        }
        .db-tabs button {
            background: #6c757d;
            color: white;
            border: none;
            padding: 10px 15px;
            margin-right: 5px;
            border-radius: 4px 4px 0 0;
            cursor: pointer;
        }
        .db-tabs button.active {
            background: #007bff;
        }
        .syntax-highlight {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>NoSQL Injection 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>🗃️ NoSQL Injection 취약점</h2>
            <p><strong>설명:</strong> NoSQL 데이터베이스에서 사용자 입력을 안전하게 처리하지 않을 때 발생하는 취약점입니다. 
            MongoDB, CouchDB, Redis 등 다양한 NoSQL DB에서 인증 우회, 데이터 추출, 코드 실행이 가능합니다.</p>
            
            <div class="db-tabs">
                <button onclick="changeDatabase('mongodb')" class="active" id="mongodb-tab">MongoDB</button>
                <button onclick="changeDatabase('couchdb')" id="couchdb-tab">CouchDB</button>
                <button onclick="changeDatabase('redis')" id="redis-tab">Redis</button>
                <button onclick="changeDatabase('elasticsearch')" id="elasticsearch-tab">Elasticsearch</button>
                <button onclick="changeDatabase('cassandra')" id="cassandra-tab">Cassandra</button>
            </div>
            
            <h3 id="payload-title">📋 MongoDB 테스트 페이로드:</h3>
            <div id="payload-buttons" style="margin: 10px 0;">
                <button onclick="testPayload('auth_bypass')" class="payload-btn">인증 우회</button>
                <button onclick="testPayload('data_extraction')" class="payload-btn">데이터 추출</button>
                <button onclick="testPayload('code_execution')" class="payload-btn">코드 실행</button>
                <button onclick="testPayload('operator_abuse')" class="payload-btn">연산자 악용</button>
                <button onclick="testPayload('safe')" class="payload-btn">안전한 쿼리</button>
            </div>
            
            <div class="syntax-highlight" id="syntax-example">
                <strong>MongoDB 구문 예제:</strong><br>
                <code>{"username": "admin", "password": "secret"}</code>
            </div>
        </div>

        <form method="POST">
            <label for="db_type">🗄️ 데이터베이스 유형 선택:</label><br>
            <select id="db_type" name="db_type">
                <option value="mongodb" <?php echo ($db_type == 'mongodb') ? 'selected' : ''; ?>>MongoDB</option>
                <option value="couchdb" <?php echo ($db_type == 'couchdb') ? 'selected' : ''; ?>>CouchDB</option>
                <option value="redis" <?php echo ($db_type == 'redis') ? 'selected' : ''; ?>>Redis</option>
                <option value="elasticsearch" <?php echo ($db_type == 'elasticsearch') ? 'selected' : ''; ?>>Elasticsearch</option>
                <option value="cassandra" <?php echo ($db_type == 'cassandra') ? 'selected' : ''; ?>>Cassandra</option>
            </select><br><br>
            
            <label for="query">🎯 NoSQL 쿼리/명령 입력:</label><br>
            <textarea id="query" name="query" placeholder="NoSQL 쿼리나 명령을 입력하세요..."><?php echo htmlspecialchars($query_input); ?></textarea><br><br>
            <input type="submit" value="쿼리 실행" class="btn">
        </form>

        <?php if (!empty($result)): ?>
            <div style="margin-top: 20px;">
                <h2>📊 테스트 결과:</h2>
                <pre style="background: #f1f3f4; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;"><?php echo htmlspecialchars($result); ?></pre>
            </div>
        <?php endif; ?>

        <div class="mitigation-guide">
            <h2>🛡️ 방어 방법</h2>
            <ul>
                <li><strong>입력 검증:</strong> 모든 사용자 입력에 대한 엄격한 검증</li>
                <li><strong>화이트리스트:</strong> 허용된 연산자와 함수만 사용 허용</li>
                <li><strong>매개변수화:</strong> 쿼리와 데이터 분리 (Prepared Statements 개념)</li>
                <li><strong>최소 권한:</strong> 데이터베이스 사용자 권한 최소화</li>
                <li><strong>스키마 검증:</strong> 입력 데이터의 스키마 검증</li>
                <li><strong>특수 문자 이스케이프:</strong> NoSQL 연산자 문자 이스케이프</li>
            </ul>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        const payloads = {
            mongodb: {
                auth_bypass: '{"username": {"$ne": null}, "password": {"$ne": null}}',
                data_extraction: '{"username": {"$regex": "^admin"}}',
                code_execution: '{"$where": "this.username == \\"admin\\""}',
                operator_abuse: '{"age": {"$gt": 0, "$lt": 999}}',
                safe: '{"username": "testuser", "status": "active"}'
            },
            couchdb: {
                auth_bypass: '_design/malicious/_view/users',
                data_extraction: '{"selector": {"_id": {"$gt": null}}}',
                code_execution: 'function(doc){emit(doc._id, eval("malicious_code"))}',
                operator_abuse: '_all_docs?include_docs=true',
                safe: '{"selector": {"username": "testuser"}}'
            },
            redis: {
                auth_bypass: 'AUTH bypass_attempt',
                data_extraction: 'KEYS *',
                code_execution: 'EVAL "redis.call(\\"flushall\\")" 0',
                operator_abuse: 'CONFIG GET *',
                safe: 'GET user:123:profile'
            },
            elasticsearch: {
                auth_bypass: '{"query": {"match_all": {}}}',
                data_extraction: '{"_source": ["password"], "query": {"match_all": {}}}',
                code_execution: '{"script": "ctx._source.password = \\"hacked\\""}',
                operator_abuse: '{"query": {"bool": {"must": [{"exists": {"field": "_id"}}]}}}',
                safe: '{"query": {"term": {"username": "testuser"}}}'
            },
            cassandra: {
                auth_bypass: 'SELECT * FROM users ALLOW FILTERING;',
                data_extraction: 'SELECT password FROM users;',
                code_execution: 'DROP TABLE users;',
                operator_abuse: 'ALTER KEYSPACE test WITH REPLICATION = {};',
                safe: 'SELECT name FROM users WHERE id = ?;'
            }
        };

        const syntaxExamples = {
            mongodb: 'MongoDB 구문 예제:<br><code>{"username": "admin", "password": "secret"}</code>',
            couchdb: 'CouchDB 구문 예제:<br><code>{"selector": {"username": "admin"}}</code>',
            redis: 'Redis 구문 예제:<br><code>GET user:123</code>',
            elasticsearch: 'Elasticsearch 구문 예제:<br><code>{"query": {"match": {"username": "admin"}}}</code>',
            cassandra: 'Cassandra 구문 예제:<br><code>SELECT * FROM users WHERE id = 123;</code>'
        };

        function changeDatabase(db) {
            // 탭 활성화
            document.querySelectorAll('.db-tabs button').forEach(btn => btn.classList.remove('active'));
            document.getElementById(db + '-tab').classList.add('active');
            
            // 데이터베이스 선택
            document.getElementById('db_type').value = db;
            
            // 제목 변경
            document.getElementById('payload-title').textContent = '📋 ' + db.charAt(0).toUpperCase() + db.slice(1) + ' 테스트 페이로드:';
            
            // 구문 예제 변경
            document.getElementById('syntax-example').innerHTML = '<strong>' + syntaxExamples[db] + '</strong>';
        }

        function testPayload(type) {
            const db = document.getElementById('db_type').value;
            const payload = payloads[db][type];
            
            if (confirm('⚠️ 교육 목적의 NoSQL Injection 테스트를 실행하시겠습니까?\n\n데이터베이스: ' + db + '\n유형: ' + type)) {
                document.getElementById('query').value = payload;
            }
        }

        // 위험 패턴 경고
        document.getElementById('query').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const warningPatterns = ['$where', '$ne', '$regex', 'eval', 'script', 'drop', 'delete', 'flushall'];
            
            let isRisky = warningPatterns.some(pattern => value.includes(pattern));
            
            if (isRisky) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });

        // 데이터베이스 변경 시 페이로드 업데이트
        document.getElementById('db_type').addEventListener('change', function() {
            changeDatabase(this.value);
        });
    </script>
</body>
</html>