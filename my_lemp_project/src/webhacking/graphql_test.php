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

require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'GraphQL Injection';
$description = '<p><strong>GraphQL Injection</strong>은 GraphQL API의 잘못된 구현으로 발생하는 취약점입니다.</p>
<p>스키마 노출, 깊이 공격, 배치 공격, 권한 우회 등을 통해 민감한 데이터 노출이나 서비스 장애를 일으킬 수 있습니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'introspection' => [
        'title' => '📋 스키마 인트로스펙션 공격',
        'description' => 'GraphQL 스키마 구조 전체를 노출시키는 공격입니다.',
        'payloads' => [
            'query IntrospectionQuery { __schema { queryType { name } types { name } } }'
        ]
    ],
    'depth_attack' => [
        'title' => '📈 깊이 공격 (DoS)',
        'description' => '깊은 중첩 쿼리로 서버 리소스 고갈을 유도하는 DoS 공격입니다.',
        'payloads' => [
            'query DepthAttack { user(id: 1) { name posts { title comments { content } } } }'
        ]
    ],
    'field_suggestion' => [
        'title' => '🔍 필드 추측 공격',
        'description' => '존재하지 않는 필드 요청으로 에러 메시지를 통해 실제 필드명을 추측하는 공격입니다.',
        'payloads' => [
            'query FieldSuggestion { user(id: 1) { name email secret_key } }'
        ]
    ],
    'injection' => [
        'title' => '💉 쿼리 조작 (Injection)',
        'description' => 'SQL Injection과 유사하게 쿼리를 조작하여 데이터를 탈취하거나 권한을 우회하는 공격입니다.',
        'payloads' => [
            'query InjectionTest { user(id: "1\' OR \'1\'=\'1") { name email } }'
        ]
    ],
    'batch_attack' => [
        'title' => '📦 배치 공격',
        'description' => '단일 요청으로 여러 쿼리를 동시에 실행하여 Rate Limiting을 우회하거나 서버 부하를 증가시키는 공격입니다.',
        'payloads' => [
            '[ { "query": "query { user(id: 1) { name } }" }, { "query": "query { user(id: 2) { name } }" } ]'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>인트로스펙션 비활성화:</strong> 프로덕션 환경에서 스키마 인트로스펙션을 비활성화합니다.",
    "<strong>쿼리 깊이 제한:</strong> 중첩 쿼리의 최대 깊이를 제한합니다. (권장: 5-10 레벨)",
    "<strong>복잡도 분석:</strong> 쿼리의 복잡도를 계산하고 제한하여 서버 과부하를 방지합니다.",
    "<strong>Rate Limiting:</strong> 요청 빈도를 제한하여 DoS 공격을 방어합니다.",
    "<strong>필드 레벨 인증:</strong> 민감한 필드에 대한 접근 제어를 구현합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - GraphQL Security Cheat Sheet" => "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Security_Cheat_Sheet.html",
    "PortSwigger - GraphQL API testing" => "https://portswigger.net/web-security/graphql"
];

// 5. 테스트 폼 UI 정의
$graphql_query = htmlspecialchars($_POST['payload'] ?? '');
$attack_type = htmlspecialchars($_POST['attack_type'] ?? 'introspection');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 GraphQL 쿼리 테스트</h3>
    <label for="attack_type">🎯 공격 유형 선택:</label><br>
    <select id="attack_type" name="attack_type">
        <option value="introspection" {$attack_type === 'introspection' ? 'selected' : ''}>스키마 인트로스펙션</option>
        <option value="depth_attack" {$attack_type === 'depth_attack' ? 'selected' : ''}>깊이 공격 (DoS)</option>
        <option value="field_suggestion" {$attack_type === 'field_suggestion' ? 'selected' : ''}>필드 추측</option>
        <option value="injection" {$attack_type === 'injection' ? 'selected' : ''}>쿼리 조작 (Injection)</option>
        <option value="batch_attack" {$attack_type === 'batch_attack' ? 'selected' : ''}>배치 공격</option>
    </select><br><br>
    
    <label for="payload">🎯 GraphQL 쿼리 입력:</label><br>
    <textarea id="payload" name="payload" placeholder="GraphQL 쿼리를 입력하세요...">{$graphql_query}</textarea><br><br>
    <button type="submit" class="btn">GraphQL 쿼리 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $query = $form_data['payload'] ?? '';
    $type = $form_data['attack_type'] ?? 'introspection';
    $result = '';
    $error = '';

    if (empty($query)) {
        $error = "GraphQL 쿼리를 입력해주세요.";
        return ['result' => $result, 'error' => $error];
    }

    $response_sim = "[시뮬레이션] GraphQL 공격 분석\n";
    $response_sim .= "공격 유형: " . strtoupper($type) . "\n";
    $response_sim .= "쿼리: " . htmlspecialchars($query) . "\n\n";

    switch ($type) {
        case 'introspection':
            if (strpos($query, '__schema') !== false) {
                $response_sim .= "스키마 노출 시뮬레이션: 모든 타입, 필드, 뮤테이션 노출 가능성.\n";
                $response_sim .= "예상 응답: { \"data\": { \"__schema\": { \"types\": [ { \"name\": \"User\" }, { \"name\": \"AdminUser\" } ] } } }\n";
                $response_sim .= "→ 공격자가 모든 데이터 구조와 숨겨진 필드를 파악 가능.";
            } else {
                $response_sim .= "안전한 인트로스펙션 쿼리입니다.";
            }
            break;
        case 'depth_attack':
            $depth_count = substr_count($query, '{');
            if ($depth_count > 5) {
                $response_sim .= "깊이 분석: {$depth_count} 레벨 (위험)\n";
                $response_sim .= "예상 결과: 서버 리소스 고갈, 메모리 부족.\n";
                $response_sim .= "→ 무한 순환 참조로 인한 서버 다운 가능성.";
            } else {
                $response_sim .= "적절한 깊이의 쿼리입니다.";
            }
            break;
        case 'field_suggestion':
            $response_sim .= "필드 추측 시뮬레이션: 에러 메시지를 통해 실제 필드명 추측 가능.\n";
            $response_sim .= "예상 응답: { \"errors\": [ { \"message\": \"Cannot query field 'secret_key' on type 'User'.\", \"extensions\": { \"suggestion\": \"Did you mean 'secretToken'?\" } } ] }\n";
            break;
        case 'injection':
            if (strpos($query, 'union') !== false || strpos($query, 'fragment') !== false) {
                $response_sim .= "쿼리 조작 시뮬레이션: Fragment/Union 남용 감지.\n";
                $response_sim .= "예상 피해: 관리자 전용 필드 접근, 다른 사용자 데이터 조회, 숨겨진 API 엔드포인트 노출.\n";
            } else {
                $response_sim .= "안전한 쿼리입니다.";
            }
            break;
        case 'batch_attack':
            $batch_count = substr_count($query, 'query');
            if ($batch_count > 1) {
                $response_sim .= "배치 쿼리 개수: {$batch_count}개\n";
                $response_sim .= "Rate Limiting 우회 가능성: 높음.\n";
                $response_sim .= "예상 피해: 브루트포스 공격 가속화, API 제한 회피, 대량 데이터 추출.\n";
            } else {
                $response_sim .= "단일 쿼리입니다.";
            }
            break;
    }

    return ['result' => "<pre>{$response_sim}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GraphQL Injection 테스트 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 1000px;
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
            height: 250px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        select {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin: 10px 0;
            width: 250px;
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
        .graphql-syntax {
            background: #e8f5e8;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .attack-vector {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>GraphQL Injection 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>🔗 GraphQL Injection 취약점</h2>
            <p><strong>설명:</strong> GraphQL API의 잘못된 구현으로 발생하는 취약점입니다. 
            스키마 노출, 깊이 공격, 배치 공격, 권한 우회 등을 통해 민감한 데이터 노출이나 서비스 장애를 일으킬 수 있습니다.</p>
            
            <div class="graphql-syntax">
                <h4>📖 GraphQL 기본 구조</h4>
                <p><strong>쿼리 (Query):</strong> 데이터 조회</p>
                <p><strong>뮤테이션 (Mutation):</strong> 데이터 변경</p>
                <p><strong>서브스크립션 (Subscription):</strong> 실시간 데이터</p>
                <p><strong>스키마 (Schema):</strong> 데이터 구조 정의</p>
                <p><strong>리졸버 (Resolver):</strong> 필드별 데이터 처리 함수</p>
            </div>
            
            <h3>📋 공격 유형별 테스트:</h3>
            <div style="margin: 10px 0;">
                <button onclick="testAttack('introspection')" class="payload-btn">스키마 노출</button>
                <button onclick="testAttack('depth_attack')" class="payload-btn">깊이 공격</button>
                <button onclick="testAttack('field_suggestion')" class="payload-btn">필드 추측</button>
                <button onclick="testAttack('injection')" class="payload-btn">쿼리 조작</button>
                <button onclick="testAttack('batch_attack')" class="payload-btn">배치 공격</button>
                <button onclick="testAttack('safe')" class="payload-btn">안전한 쿼리</button>
            </div>
        </div>

        <form method="POST">
            <label for="attack_type">🎯 공격 유형 선택:</label><br>
            <select id="attack_type" name="attack_type">
                <option value="introspection" <?php echo ($attack_type == 'introspection') ? 'selected' : ''; ?>>Schema Introspection</option>
                <option value="depth_attack" <?php echo ($attack_type == 'depth_attack') ? 'selected' : ''; ?>>Depth Attack (DoS)</option>
                <option value="field_suggestion" <?php echo ($attack_type == 'field_suggestion') ? 'selected' : ''; ?>>Field Suggestion</option>
                <option value="injection" <?php echo ($attack_type == 'injection') ? 'selected' : ''; ?>>Query Injection</option>
                <option value="batch_attack" <?php echo ($attack_type == 'batch_attack') ? 'selected' : ''; ?>>Batch Attack</option>
            </select><br><br>
            
            <label for="graphql_query">🎯 GraphQL 쿼리 입력:</label><br>
            <textarea id="graphql_query" name="graphql_query" placeholder="GraphQL 쿼리를 입력하세요..."><?php echo htmlspecialchars($graphql_query); ?></textarea><br><br>
            <input type="submit" value="GraphQL 쿼리 실행" class="btn">
        </form>

        <?php if (!empty($result)): ?>
            <div style="margin-top: 20px;">
                <h2>📊 테스트 결과:</h2>
                <pre style="background: #f1f3f4; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;"><?php echo htmlspecialchars($result); ?></pre>
            </div>
        <?php endif; ?>

        <div class="attack-vector">
            <h4>⚠️ GraphQL 공격 벡터</h4>
            <p><strong>1. 스키마 인트로스펙션:</strong> 전체 API 구조 노출</p>
            <p><strong>2. Depth Attack:</strong> 깊은 중첩 쿼리로 DoS 공격</p>
            <p><strong>3. Field Suggestion:</strong> 에러 메시지를 통한 필드명 추측</p>
            <p><strong>4. Query Complexity:</strong> 복잡한 쿼리로 서버 과부하</p>
            <p><strong>5. Batch Attack:</strong> 여러 쿼리를 한 번에 실행</p>
            <p><strong>6. Alias Overloading:</strong> 같은 필드의 여러 별칭 사용</p>
        </div>

        <div class="mitigation-guide">
            <h2>🛡️ 방어 방법</h2>
            <ul>
                <li><strong>인트로스펙션 비활성화:</strong> 프로덕션 환경에서 스키마 인트로스펙션을 비활성화합니다.</li>
                <li><strong>쿼리 깊이 제한:</strong> 중첩 쿼리의 최대 깊이를 제한합니다. (권장: 5-10 레벨)</li>
                <li><strong>복잡도 분석:</strong> 쿼리의 복잡도를 계산하고 제한하여 서버 과부하를 방지합니다.</li>
                <li><strong>Rate Limiting:</strong> 요청 빈도를 제한하여 DoS 공격을 방어합니다.</li>
                <li><strong>필드 레벨 인증:</strong> 민감한 필드에 대한 접근 제어를 구현합니다.</li>
            </ul>
            
            <h4>🔧 GraphQL 보안 설정 예제:</h4>
            <pre style="background: #e8f5e8; padding: 10px; border-radius: 4px; font-size: 12px;">
// Query Depth Limiting
const depthLimit = require('graphql-depth-limit');

const server = new GraphQLServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(5)]
});

// Query Complexity Analysis  
const costAnalysis = require('graphql-query-complexity');

server.use(costAnalysis({
  maximumCost: 1000,
  createError: (max, actual) => {
    return new Error(`Query is too complex: ${actual}. Max allowed: ${max}`);
  }
}));
            </pre>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        const payloads = {
            introspection: `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
    }
  }
}`,
            
            depth_attack: `query DepthAttack {
  user(id: 1) {
    name
    posts {
      title
      comments {
        content
      }
    }
  }
}

query DepthAttack2 {
  user(id: 1) {
    name
    posts {
      title
      comments {
        content
        author {
          name
          posts {
            title
            comments {
              content
              author {
                name
                posts {
                  title
                  comments {
                    content
                    author {
                      name
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}`,
            
            field_suggestion: `query FieldSuggestion {
  user(id: 1) {
    name
    email
    secret_key
    admin_token
    private_data
    hidden_field
    sensitive_info
  }
}`,
            
            injection: `query InjectionTest {
  user(id: "1' OR '1'='1") {
    name
    email
  }
}

fragment UserFragment on User {
  ...on AdminUser {
    secretKey
    adminPrivileges
  }
}

query UnionInjection {
  search(term: "admin") {
    ...UserFragment
    ...on PublicUser {
      publicData
    }
  }
}`,
            
            batch_attack: `[
  { "query": "query { user(id: 1) { name } }" },
  { "query": "query { user(id: 2) { name } }" },
  { "query": "query { user(id: 3) { name } }" },
  { "query": "query { user(id: 4) { name } }" },
  { "query": "query { user(id: 5) { name } }" }
]`,
            
            safe: `query SafeQuery {
  user(id: 123) {
    id
    name
    email
    createdAt
  }
  
  posts(limit: 10) {
    id
    title
    publishedAt
  }
}`
        };

        function testAttack(type) {
            const payload = payloads[type];
            
            if (confirm('⚠️ 교육 목적의 GraphQL 공격 테스트를 실행하시겠습니까?\n\n공격 유형: ' + type)) {
                document.getElementById('attack_type').value = type;
                document.getElementById('graphql_query').value = payload;
            }
        }

        // 위험 패턴 경고
        document.getElementById('graphql_query').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const warningPatterns = ['__schema', '__type', 'introspection', 'fragment', 'union', 'directive'];
            
            let isRisky = warningPatterns.some(pattern => value.includes(pattern));
            
            if (isRisky) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });

        // 쿼리 복잡도 계산
        function calculateComplexity() {
            const query = document.getElementById('graphql_query').value;
            const depth = (query.match(/{/g) || []).length;
            const fields = (query.match(/\w+\s*{/g) || []).length;
            const fragments = (query.match(/fragment/g) || []).length;
            
            const complexity = depth * 2 + fields + fragments * 3;
            
            alert(`쿼리 복잡도 분석:\n깊이: ${depth}\n필드 수: ${fields}\n프래그먼트: ${fragments}\n총 복잡도: ${complexity}\n\n${complexity > 20 ? '⚠️ 높은 복잡도 (DoS 위험)' : '✅ 적절한 복잡도'}`);
        }

        // 복잡도 계산 버튼 추가
        document.addEventListener('DOMContentLoaded', function() {
            const button = document.createElement('button');
            button.textContent = '쿼리 복잡도 계산';
            button.type = 'button';
            button.className = 'btn';
            button.style.marginLeft = '10px';
            button.onclick = calculateComplexity;
            
            const submitBtn = document.querySelector('input[type="submit"]');
            submitBtn.parentNode.insertBefore(button, submitBtn.nextSibling);
        });
    </script>
</body>
</html>
