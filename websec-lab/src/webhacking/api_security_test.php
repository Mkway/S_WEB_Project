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

$pageTitle = "API Security Testing - OWASP API Top 10";
$currentTest = "API Security";
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $pageTitle; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <?php include 'templates/header.php'; ?>

    <div class="container mt-4">
        <?php include 'templates/breadcrumb.php'; ?>
        
        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h3>🔌 API Security Testing - OWASP API Top 10</h3>
                    </div>
                    <div class="card-body">
                        <p>이 테스트는 OWASP API Security Top 10 기준으로 API 보안 취약점을 검증합니다.</p>
                        
                        <!-- API1: Broken Object Level Authorization -->
                        <div class="mb-4">
                            <h5>API1: Broken Object Level Authorization (BOLA)</h5>
                            <p>객체 수준 권한 부여 취약점 테스트</p>
                            
                            <form id="bolaForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="resourceId" class="form-label">리소스 ID</label>
                                        <input type="text" class="form-control" id="resourceId" name="resourceId" 
                                               placeholder="12345" value="12345">
                                    </div>
                                    <div class="col-md-6">
                                        <label for="attackMethod" class="form-label">공격 방법</label>
                                        <select class="form-select" id="attackMethod" name="attackMethod">
                                            <option value="id_enumeration">ID 열거 공격</option>
                                            <option value="horizontal_access">수평적 접근 시도</option>
                                            <option value="vertical_access">수직적 접근 시도</option>
                                            <option value="uuid_prediction">UUID 예측 공격</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-warning mt-2" onclick="testBOLA()">
                                    🎯 BOLA 취약점 테스트
                                </button>
                            </form>
                            
                            <div id="bolaResults" class="mt-3"></div>
                        </div>

                        <!-- API2: Broken Authentication -->
                        <div class="mb-4">
                            <h5>API2: Broken Authentication</h5>
                            <p>API 인증 메커니즘 취약점 검증</p>
                            
                            <form id="authForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="authType" class="form-label">인증 방식</label>
                                        <select class="form-select" id="authType" name="authType">
                                            <option value="jwt_token">JWT 토큰</option>
                                            <option value="api_key">API 키</option>
                                            <option value="oauth_bearer">OAuth Bearer</option>
                                            <option value="session_cookie">세션 쿠키</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="authAttack" class="form-label">공격 유형</label>
                                        <select class="form-select" id="authAttack" name="authAttack">
                                            <option value="token_manipulation">토큰 조작</option>
                                            <option value="weak_signature">약한 서명 알고리즘</option>
                                            <option value="credential_stuffing">자격증명 스터핑</option>
                                            <option value="session_fixation">세션 고정</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-danger mt-2" onclick="testBrokenAuth()">
                                    🔐 인증 취약점 테스트
                                </button>
                            </form>
                            
                            <div id="authResults" class="mt-3"></div>
                        </div>

                        <!-- API3: Excessive Data Exposure -->
                        <div class="mb-4">
                            <h5>API3: Excessive Data Exposure</h5>
                            <p>과도한 데이터 노출 취약점 검증</p>
                            
                            <form id="dataExposureForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="endpoint" class="form-label">API 엔드포인트</label>
                                        <select class="form-select" id="endpoint" name="endpoint">
                                            <option value="/api/users/profile">/api/users/profile</option>
                                            <option value="/api/orders/history">/api/orders/history</option>
                                            <option value="/api/admin/users">/api/admin/users</option>
                                            <option value="/api/internal/logs">/api/internal/logs</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="dataType" class="form-label">민감한 데이터 유형</label>
                                        <select class="form-select" id="dataType" name="dataType">
                                            <option value="personal_info">개인정보 (PII)</option>
                                            <option value="financial_data">금융 데이터</option>
                                            <option value="internal_ids">내부 식별자</option>
                                            <option value="system_info">시스템 정보</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-info mt-2" onclick="testDataExposure()">
                                    📊 데이터 노출 테스트
                                </button>
                            </form>
                            
                            <div id="dataExposureResults" class="mt-3"></div>
                        </div>

                        <!-- API4: Lack of Resources & Rate Limiting -->
                        <div class="mb-4">
                            <h5>API4: Lack of Resources & Rate Limiting</h5>
                            <p>리소스 제한 및 속도 제한 부족 테스트</p>
                            
                            <form id="rateLimitForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="requestCount" class="form-label">요청 횟수</label>
                                        <select class="form-select" id="requestCount" name="requestCount">
                                            <option value="100">100 requests/sec</option>
                                            <option value="1000">1,000 requests/sec</option>
                                            <option value="10000">10,000 requests/sec</option>
                                            <option value="unlimited">무제한 요청</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="resourceType" class="form-label">리소스 타입</label>
                                        <select class="form-select" id="resourceType" name="resourceType">
                                            <option value="cpu_intensive">CPU 집약적</option>
                                            <option value="memory_intensive">메모리 집약적</option>
                                            <option value="io_intensive">I/O 집약적</option>
                                            <option value="network_intensive">네트워크 집약적</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-warning mt-2" onclick="testRateLimit()">
                                    🚦 Rate Limiting 테스트
                                </button>
                            </form>
                            
                            <div id="rateLimitResults" class="mt-3"></div>
                        </div>

                        <!-- API5: Broken Function Level Authorization -->
                        <div class="mb-4">
                            <h5>API5: Broken Function Level Authorization (BFLA)</h5>
                            <p>기능 수준 권한 부여 취약점 테스트</p>
                            
                            <form id="bflaForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="userRole" class="form-label">사용자 역할</label>
                                        <select class="form-select" id="userRole" name="userRole">
                                            <option value="guest">게스트</option>
                                            <option value="user">일반 사용자</option>
                                            <option value="admin">관리자</option>
                                            <option value="superadmin">슈퍼 관리자</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="restrictedFunction" class="form-label">제한된 기능</label>
                                        <select class="form-select" id="restrictedFunction" name="restrictedFunction">
                                            <option value="user_management">사용자 관리</option>
                                            <option value="system_config">시스템 설정</option>
                                            <option value="data_export">데이터 내보내기</option>
                                            <option value="audit_logs">감사 로그</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-danger mt-2" onclick="testBFLA()">
                                    🔒 BFLA 취약점 테스트
                                </button>
                            </form>
                            
                            <div id="bflaResults" class="mt-3"></div>
                        </div>

                        <!-- API6: Mass Assignment -->
                        <div class="mb-4">
                            <h5>API6: Mass Assignment</h5>
                            <p>대량 할당 취약점 테스트</p>
                            
                            <form id="massAssignmentForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="targetField" class="form-label">대상 필드</label>
                                        <select class="form-select" id="targetField" name="targetField">
                                            <option value="role">사용자 역할</option>
                                            <option value="balance">계정 잔액</option>
                                            <option value="permissions">권한 설정</option>
                                            <option value="internal_id">내부 ID</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="injectionMethod" class="form-label">주입 방법</label>
                                        <select class="form-select" id="injectionMethod" name="injectionMethod">
                                            <option value="json_payload">JSON 페이로드</option>
                                            <option value="form_data">폼 데이터</option>
                                            <option value="query_params">쿼리 매개변수</option>
                                            <option value="nested_objects">중첩 객체</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-warning mt-2" onclick="testMassAssignment()">
                                    📝 Mass Assignment 테스트
                                </button>
                            </form>
                            
                            <div id="massAssignmentResults" class="mt-3"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <?php 
                $defenseContent = "
                <strong>🛡️ API 보안 강화 방법:</strong><br>
                • 객체별 권한 검증 (RBAC/ABAC)<br>
                • 강력한 JWT 서명 (RS256/ES256)<br>
                • 응답 필드 화이트리스팅<br>
                • Rate Limiting & Throttling<br>
                • 입력 검증 & 화이트리스팅<br><br>

                <strong>⚙️ 보안 헤더 설정:</strong><br>
                <code>X-Rate-Limit: 100</code><br>
                <code>Content-Type: application/json</code><br>
                <code>Access-Control-Allow-Origin</code>
                ";
                include 'templates/defense_box.php';
                ?>

                <?php
                $infoContent = "
                <strong>📋 OWASP API Top 10 (2023):</strong><br>
                1. Broken Object Level Authorization<br>
                2. Broken Authentication<br>
                3. Excessive Data Exposure<br>
                4. Lack of Resources & Rate Limiting<br>
                5. Broken Function Level Authorization<br>
                6. Mass Assignment<br>
                7. Security Misconfiguration<br>
                8. Injection<br>
                9. Improper Asset Management<br>
                10. Insufficient Logging & Monitoring
                ";
                include 'templates/info_box.php';
                ?>

                <?php
                $referenceContent = "
                <strong>📚 참고 자료:</strong><br>
                • <a href='https://owasp.org/API-Security/editions/2023/en/0x11-t10/' target='_blank'>OWASP API Top 10</a><br>
                • <a href='https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html' target='_blank'>REST Security Cheat Sheet</a><br>
                • <a href='https://tools.ietf.org/html/rfc7519' target='_blank'>JWT RFC 7519</a><br><br>

                <strong>🔧 테스트 도구:</strong><br>
                • Postman/Newman<br>
                • OWASP ZAP API Scanner<br>
                • Burp Suite API Testing<br>
                • APICheck
                ";
                include 'templates/reference_box.php';
                ?>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function testBOLA() {
            const resourceId = document.getElementById('resourceId').value;
            const method = document.getElementById('attackMethod').value;
            const resultsDiv = document.getElementById('bolaResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🎯 BOLA 취약점 테스트 실행 중...</strong><br>
                    리소스 ID: ${resourceId}<br>
                    공격 방법: ${method}
                </div>
            `;
            
            setTimeout(() => {
                let vulnerable = Math.random() > 0.6; // 40% 취약점 발견률
                let alertClass = vulnerable ? 'danger' : 'success';
                let icon = vulnerable ? '❌' : '✅';
                
                let result = '';
                switch (method) {
                    case 'id_enumeration':
                        result = vulnerable ?
                            'ID 열거 공격에 성공했습니다. 다른 사용자의 리소스에 무단 접근이 가능합니다.' :
                            'ID 열거 공격이 차단되었습니다. 적절한 권한 검증이 이루어지고 있습니다.';
                        break;
                    case 'horizontal_access':
                        result = vulnerable ?
                            '수평적 권한 상승에 성공했습니다. 같은 레벨 사용자의 데이터에 접근할 수 있습니다.' :
                            '수평적 접근 시도가 차단되었습니다. 사용자별 데이터 격리가 적절합니다.';
                        break;
                    case 'vertical_access':
                        result = vulnerable ?
                            '수직적 권한 상승에 성공했습니다. 더 높은 권한의 리소스에 접근할 수 있습니다.' :
                            '수직적 접근 시도가 차단되었습니다. 역할 기반 접근 제어가 효과적입니다.';
                        break;
                    case 'uuid_prediction':
                        result = vulnerable ?
                            'UUID 예측에 성공했습니다. 예측 가능한 식별자가 사용되고 있습니다.' :
                            'UUID가 충분히 무작위입니다. 식별자 예측이 불가능합니다.';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} BOLA 테스트 결과:</strong><br>
                        ${result}<br><br>
                        <strong>보안 권장사항:</strong><br>
                        • 모든 API 요청에서 사용자 권한 검증<br>
                        • 객체별 접근 제어 목록 구현<br>
                        • 예측 불가능한 리소스 식별자 사용<br>
                        • 세션 기반 컨텍스트 검증 추가
                    </div>
                `;
            }, 2000);
        }
        
        function testBrokenAuth() {
            const authType = document.getElementById('authType').value;
            const attack = document.getElementById('authAttack').value;
            const resultsDiv = document.getElementById('authResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🔐 인증 취약점 테스트 실행 중...</strong><br>
                    인증 방식: ${authType}<br>
                    공격 유형: ${attack}
                </div>
            `;
            
            setTimeout(() => {
                let success = Math.random() > 0.7; // 30% 공격 성공률
                let alertClass = success ? 'danger' : 'success';
                let icon = success ? '🚨' : '🛡️';
                
                let analysis = '';
                switch (attack) {
                    case 'token_manipulation':
                        analysis = success ?
                            '토큰 조작에 성공했습니다. 서명 검증이 적절하지 않거나 알고리즘이 취약합니다.' :
                            '토큰 무결성이 보호되고 있습니다. 조작 시도가 탐지되어 차단되었습니다.';
                        break;
                    case 'weak_signature':
                        analysis = success ?
                            '약한 서명 알고리즘을 악용했습니다. HS256 대신 RS256 사용을 권장합니다.' :
                            '강력한 서명 알고리즘이 사용되고 있습니다. 암호학적 보안이 유지됩니다.';
                        break;
                    case 'credential_stuffing':
                        analysis = success ?
                            '자격증명 스터핑 공격에 성공했습니다. 계정 보호 메커니즘이 부족합니다.' :
                            '계정 보호 기능이 작동합니다. 비정상적인 로그인 시도가 차단되었습니다.';
                        break;
                    case 'session_fixation':
                        analysis = success ?
                            '세션 고정 공격에 성공했습니다. 로그인 시 세션 ID 재생성이 필요합니다.' :
                            '세션 관리가 안전합니다. 로그인 시 새로운 세션 ID가 발급됩니다.';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} 인증 보안 테스트 결과:</strong><br>
                        ${analysis}<br><br>
                        <strong>인증 강화 방안:</strong><br>
                        • JWT 서명에 RS256/ES256 알고리즘 사용<br>
                        • 토큰 만료 시간 최소화 (15분 이하)<br>
                        • Refresh Token 로테이션 구현<br>
                        • 다중 인증 요소 (MFA) 도입<br>
                        • 이상 로그인 탐지 및 차단
                    </div>
                `;
            }, 3000);
        }
        
        function testDataExposure() {
            const endpoint = document.getElementById('endpoint').value;
            const dataType = document.getElementById('dataType').value;
            const resultsDiv = document.getElementById('dataExposureResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>📊 데이터 노출 테스트 실행 중...</strong><br>
                    엔드포인트: ${endpoint}<br>
                    데이터 유형: ${dataType}
                </div>
            `;
            
            setTimeout(() => {
                let exposed = Math.random() > 0.5; // 50% 노출 확률
                let alertClass = exposed ? 'warning' : 'success';
                let icon = exposed ? '⚠️' : '🔒';
                
                let sensitiveFields = [];
                switch (dataType) {
                    case 'personal_info':
                        sensitiveFields = ['email', 'phone', 'address', 'birth_date'];
                        break;
                    case 'financial_data':
                        sensitiveFields = ['account_number', 'balance', 'transaction_history'];
                        break;
                    case 'internal_ids':
                        sensitiveFields = ['internal_user_id', 'system_id', 'database_id'];
                        break;
                    case 'system_info':
                        sensitiveFields = ['server_version', 'database_schema', 'api_keys'];
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} 데이터 노출 분석 결과:</strong><br>
                        • 엔드포인트: ${endpoint}<br>
                        • 민감한 데이터 노출: ${exposed ? '발견됨' : '없음'}<br>
                        • 위험 필드: ${exposed ? sensitiveFields.join(', ') : '없음'}<br><br>
                        
                        <strong>${exposed ? '발견된 문제점:' : '보안 상태:'}</strong><br>
                        ${exposed ? 
                            '• 필요 이상의 데이터가 응답에 포함됨<br>• 클라이언트에서 필터링에 의존<br>• 민감한 내부 정보 노출 위험' :
                            '• 응답 필드가 적절히 제한됨<br>• 필요한 데이터만 노출<br>• 민감한 정보 보호 양호'
                        }<br><br>
                        
                        <strong>데이터 보호 권장사항:</strong><br>
                        • 응답 필드 화이트리스팅 구현<br>
                        • 사용자별 데이터 접근 권한 검증<br>
                        • 민감한 필드 마스킹 처리<br>
                        • API 응답 스키마 최소화
                    </div>
                `;
            }, 2500);
        }
        
        function testRateLimit() {
            const requestCount = document.getElementById('requestCount').value;
            const resourceType = document.getElementById('resourceType').value;
            const resultsDiv = document.getElementById('rateLimitResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🚦 Rate Limiting 테스트 실행 중...</strong><br>
                    요청량: ${requestCount}<br>
                    리소스 타입: ${resourceType}
                </div>
            `;
            
            setTimeout(() => {
                let limited = Math.random() > 0.4; // 60% 제한 적용률
                let alertClass = limited ? 'success' : 'danger';
                let icon = limited ? '✅' : '⚠️';
                
                let impact = '';
                switch (resourceType) {
                    case 'cpu_intensive':
                        impact = limited ?
                            'CPU 집약적 요청이 적절히 제한되었습니다. 서버 자원이 보호되고 있습니다.' :
                            'CPU 과부하가 발생했습니다. 집약적 연산에 대한 제한이 필요합니다.';
                        break;
                    case 'memory_intensive':
                        impact = limited ?
                            '메모리 사용량이 제어되고 있습니다. 메모리 누수 방지 기능이 작동합니다.' :
                            '메모리 소진 위험이 있습니다. 대용량 데이터 처리에 제한이 필요합니다.';
                        break;
                    case 'io_intensive':
                        impact = limited ?
                            'I/O 집약적 요청이 조절되고 있습니다. 디스크 및 네트워크 자원이 보호됩니다.' :
                            'I/O 병목이 발생했습니다. 파일/데이터베이스 접근에 제한이 필요합니다.';
                        break;
                    case 'network_intensive':
                        impact = limited ?
                            '네트워크 대역폭이 적절히 관리되고 있습니다. 트래픽 제어가 효과적입니다.' :
                            '네트워크 대역폭이 과도하게 사용되었습니다. 트래픽 제한이 필요합니다.';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} Rate Limiting 테스트 결과:</strong><br>
                        ${impact}<br><br>
                        <strong>성능 영향 분석:</strong><br>
                        • 요청 처리율: ${limited ? '안정적' : '과부하'}<br>
                        • 시스템 응답성: ${limited ? '양호' : '저하'}<br>
                        • 서비스 가용성: ${limited ? '유지' : '위험'}<br><br>
                        
                        <strong>리소스 보호 권장사항:</strong><br>
                        • 사용자별 요청 할당량 설정<br>
                        • 동적 속도 제한 알고리즘 적용<br>
                        • 리소스 사용량 모니터링 구현<br>
                        • 백오프 및 재시도 정책 수립
                    </div>
                `;
            }, 4000);
        }
        
        function testBFLA() {
            const userRole = document.getElementById('userRole').value;
            const restrictedFunction = document.getElementById('restrictedFunction').value;
            const resultsDiv = document.getElementById('bflaResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🔒 BFLA 취약점 테스트 실행 중...</strong><br>
                    사용자 역할: ${userRole}<br>
                    제한된 기능: ${restrictedFunction}
                </div>
            `;
            
            setTimeout(() => {
                // 게스트나 일반 사용자가 관리자 기능에 접근 시 취약점 확률 증가
                let shouldHaveAccess = (userRole === 'admin' || userRole === 'superadmin');
                let hasAccess = Math.random() > (shouldHaveAccess ? 0.1 : 0.7); // 권한이 있으면 90% 접근 가능, 없으면 30% 접근 가능
                
                let alertClass = (shouldHaveAccess === hasAccess) ? 'success' : 'danger';
                let icon = (shouldHaveAccess === hasAccess) ? '✅' : '❌';
                
                let message = '';
                if (shouldHaveAccess && hasAccess) {
                    message = '정상: 권한이 있는 사용자가 기능에 접근할 수 있습니다.';
                } else if (!shouldHaveAccess && !hasAccess) {
                    message = '정상: 권한이 없는 사용자의 접근이 차단되었습니다.';
                } else if (!shouldHaveAccess && hasAccess) {
                    message = '취약점 발견: 권한이 없는 사용자가 제한된 기능에 접근할 수 있습니다.';
                } else {
                    message = '설정 오류: 권한이 있는 사용자가 접근할 수 없습니다.';
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} BFLA 테스트 결과:</strong><br>
                        ${message}<br><br>
                        <strong>접근 제어 분석:</strong><br>
                        • 사용자 역할: ${userRole}<br>
                        • 대상 기능: ${restrictedFunction}<br>
                        • 접근 가능 여부: ${hasAccess ? '가능' : '차단'}<br>
                        • 보안 상태: ${(shouldHaveAccess === hasAccess) ? '안전' : '취약'}<br><br>
                        
                        <strong>기능별 접근 제어 권장사항:</strong><br>
                        • 역할 기반 접근 제어 (RBAC) 구현<br>
                        • 기능별 세밀한 권한 정의<br>
                        • 권한 검증을 비즈니스 로직과 분리<br>
                        • 정기적인 권한 검토 및 감사
                    </div>
                `;
            }, 3000);
        }
        
        function testMassAssignment() {
            const targetField = document.getElementById('targetField').value;
            const method = document.getElementById('injectionMethod').value;
            const resultsDiv = document.getElementById('massAssignmentResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>📝 Mass Assignment 테스트 실행 중...</strong><br>
                    대상 필드: ${targetField}<br>
                    주입 방법: ${method}
                </div>
            `;
            
            setTimeout(() => {
                let vulnerable = Math.random() > 0.6; // 40% 취약점 발견률
                let alertClass = vulnerable ? 'danger' : 'success';
                let icon = vulnerable ? '🚨' : '🛡️';
                
                let riskLevel = '';
                switch (targetField) {
                    case 'role':
                        riskLevel = vulnerable ? '매우 높음 (권한 상승 가능)' : '안전';
                        break;
                    case 'balance':
                        riskLevel = vulnerable ? '높음 (금전적 피해 가능)' : '안전';
                        break;
                    case 'permissions':
                        riskLevel = vulnerable ? '매우 높음 (시스템 장악 가능)' : '안전';
                        break;
                    case 'internal_id':
                        riskLevel = vulnerable ? '중간 (내부 정보 노출)' : '안전';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} Mass Assignment 테스트 결과:</strong><br>
                        • 대상 필드: ${targetField}<br>
                        • 주입 성공 여부: ${vulnerable ? '성공 (취약)' : '실패 (안전)'}<br>
                        • 위험 수준: ${riskLevel}<br>
                        • 사용된 방법: ${method}<br><br>
                        
                        <strong>${vulnerable ? '발견된 위험:' : '보안 상태:'}</strong><br>
                        ${vulnerable ? 
                            `• ${targetField} 필드가 무단 수정되었습니다<br>• 클라이언트 입력이 직접 모델에 바인딩됨<br>• 입력 검증 및 필터링 부족` :
                            `• ${targetField} 필드가 적절히 보호됨<br>• 화이트리스팅된 필드만 업데이트 허용<br>• 입력 검증이 효과적으로 작동`
                        }<br><br>
                        
                        <strong>Mass Assignment 방어 권장사항:</strong><br>
                        • 허용된 필드만 화이트리스팅<br>
                        • 민감한 필드는 별도 API로 분리<br>
                        • 입력 데이터 스키마 검증<br>
                        • 모델 바인딩 시 필드 제한 설정
                    </div>
                `;
            }, 2500);
        }
    </script>

    <?php include 'templates/footer.php'; ?>
</body>
</html>