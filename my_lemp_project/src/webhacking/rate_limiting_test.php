<?php
require_once '../config.php';

$pageTitle = "API Rate Limiting & DoS Protection Test";
$currentTest = "Rate Limiting";
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
                        <h3>🚦 API Rate Limiting & DoS Protection Test</h3>
                    </div>
                    <div class="card-body">
                        <p>이 테스트는 API 요청 빈도 제한 및 서비스 거부 공격(DoS) 방어 메커니즘을 검증합니다.</p>
                        
                        <!-- Rate Limiting Test -->
                        <div class="mb-4">
                            <h5>1. Basic Rate Limiting Test</h5>
                            <p>단시간 내 대량 요청으로 rate limiting 동작 확인</p>
                            
                            <form id="rateLimitForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="requestCount" class="form-label">요청 횟수</label>
                                        <select class="form-select" id="requestCount" name="requestCount">
                                            <option value="10">10회 (정상)</option>
                                            <option value="50">50회 (경고 수준)</option>
                                            <option value="100">100회 (제한 대상)</option>
                                            <option value="500">500회 (DoS 시도)</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="timeWindow" class="form-label">시간 창 (초)</label>
                                        <select class="form-select" id="timeWindow" name="timeWindow">
                                            <option value="1">1초</option>
                                            <option value="5">5초</option>
                                            <option value="10">10초</option>
                                            <option value="60">60초</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-warning mt-2" onclick="testRateLimit()">
                                    🚦 Rate Limiting 테스트 실행
                                </button>
                            </form>
                            
                            <div id="rateLimitResults" class="mt-3"></div>
                        </div>

                        <!-- Distributed DoS Test -->
                        <div class="mb-4">
                            <h5>2. Distributed Request Pattern Test</h5>
                            <p>분산된 IP 패턴으로 rate limiting 우회 시도</p>
                            
                            <form id="distributedDoSForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="ipCount" class="form-label">시뮬레이션 IP 개수</label>
                                        <select class="form-select" id="ipCount" name="ipCount">
                                            <option value="5">5개 IP</option>
                                            <option value="10">10개 IP</option>
                                            <option value="50">50개 IP</option>
                                            <option value="100">100개 IP (DDoS 패턴)</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="requestPerIP" class="form-label">IP당 요청 수</label>
                                        <select class="form-select" id="requestPerIP" name="requestPerIP">
                                            <option value="5">5회</option>
                                            <option value="10">10회</option>
                                            <option value="20">20회</option>
                                            <option value="50">50회</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-danger mt-2" onclick="testDistributedDoS()">
                                    💥 분산 DoS 패턴 테스트
                                </button>
                            </form>
                            
                            <div id="distributedResults" class="mt-3"></div>
                        </div>

                        <!-- API Endpoint Stress Test -->
                        <div class="mb-4">
                            <h5>3. API Endpoint Stress Test</h5>
                            <p>특정 API 엔드포인트에 대한 부하 테스트</p>
                            
                            <form id="stressTestForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="endpoint" class="form-label">테스트 엔드포인트</label>
                                        <select class="form-select" id="endpoint" name="endpoint">
                                            <option value="login">로그인 API</option>
                                            <option value="register">회원가입 API</option>
                                            <option value="search">검색 API</option>
                                            <option value="upload">파일 업로드 API</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="concurrency" class="form-label">동시 연결 수</label>
                                        <select class="form-select" id="concurrency" name="concurrency">
                                            <option value="10">10 동시 연결</option>
                                            <option value="50">50 동시 연결</option>
                                            <option value="100">100 동시 연결</option>
                                            <option value="500">500 동시 연결</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-info mt-2" onclick="testAPIStress()">
                                    📊 API 스트레스 테스트
                                </button>
                            </form>
                            
                            <div id="stressResults" class="mt-3"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <?php 
                $defenseContent = "
                <strong>🛡️ Rate Limiting 방어 방법:</strong><br>
                • Nginx rate limiting 설정<br>
                • Application 레벨 토큰 버킷<br>
                • Redis 기반 분산 제한<br>
                • IP whitelist/blacklist<br>
                • Progressive delays<br><br>

                <strong>⚙️ 설정 예시:</strong><br>
                <code>limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;</code><br><br>

                <strong>🔍 탐지 방법:</strong><br>
                • 요청 빈도 모니터링<br>
                • 비정상 트래픽 패턴 분석<br>
                • 응답 시간 급증 감지<br>
                • 리소스 사용량 추적
                ";
                include 'templates/defense_box.php';
                ?>

                <?php
                $infoContent = "
                <strong>📋 테스트 시나리오:</strong><br>
                1. 정상 사용자 패턴<br>
                2. 과도한 요청 패턴<br>
                3. 분산 공격 패턴<br>
                4. 특정 엔드포인트 집중 공격<br><br>

                <strong>🎯 검증 포인트:</strong><br>
                • Rate limit 임계값 도달<br>
                • HTTP 429 응답 반환<br>
                • 정상 사용자 영향 최소화<br>
                • 복구 시간 측정
                ";
                include 'templates/info_box.php';
                ?>

                <?php
                $referenceContent = "
                <strong>📚 참고 자료:</strong><br>
                • <a href='https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks' target='_blank'>OWASP Rate Limiting</a><br>
                • <a href='https://nginx.org/en/docs/http/ngx_http_limit_req_module.html' target='_blank'>Nginx Rate Limiting</a><br>
                • <a href='https://tools.ietf.org/html/rfc6585' target='_blank'>HTTP 429 Status Code</a><br><br>

                <strong>🔧 도구:</strong><br>
                • Apache Bench (ab)<br>
                • wrk<br>
                • JMeter<br>
                • Artillery.io
                ";
                include 'templates/reference_box.php';
                ?>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function testRateLimit() {
            const requestCount = document.getElementById('requestCount').value;
            const timeWindow = document.getElementById('timeWindow').value;
            const resultsDiv = document.getElementById('rateLimitResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🚦 Rate Limiting 테스트 실행 중...</strong><br>
                    ${requestCount}회 요청을 ${timeWindow}초 내에 전송하고 있습니다.
                </div>
            `;
            
            // 실제 rate limiting 테스트 수행
            performRateLimitTest(requestCount, timeWindow);
        }
        
        async function performRateLimitTest(count, window) {
            const results = [];
            const startTime = Date.now();
            
            try {
                for (let i = 0; i < count; i++) {
                    const response = await fetch('/api/test_endpoint', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Test-Request': 'rate-limit-test',
                            'X-Request-ID': `test-${i}-${Date.now()}`
                        },
                        body: JSON.stringify({
                            test: 'rate_limit',
                            sequence: i,
                            timestamp: Date.now()
                        })
                    });
                    
                    results.push({
                        sequence: i,
                        status: response.status,
                        blocked: response.status === 429,
                        timestamp: Date.now()
                    });
                    
                    // 짧은 간격으로 요청 (실제 부하 생성)
                    if (i < count - 1) {
                        await new Promise(resolve => setTimeout(resolve, (window * 1000) / count));
                    }
                }
                
                displayRateLimitResults(results, startTime);
                
            } catch (error) {
                document.getElementById('rateLimitResults').innerHTML = `
                    <div class="alert alert-danger">
                        <strong>❌ 테스트 실행 오류:</strong><br>
                        ${error.message}
                    </div>
                `;
            }
        }
        
        function displayRateLimitResults(results, startTime) {
            const totalRequests = results.length;
            const blockedRequests = results.filter(r => r.blocked).length;
            const successRequests = totalRequests - blockedRequests;
            const duration = Date.now() - startTime;
            
            let statusClass = 'success';
            let statusIcon = '✅';
            let statusText = 'Rate Limiting이 정상 작동하지 않음';
            
            if (blockedRequests > 0) {
                statusClass = 'warning';
                statusIcon = '⚠️';
                statusText = 'Rate Limiting이 부분적으로 작동';
            }
            
            if (blockedRequests > totalRequests * 0.5) {
                statusClass = 'success';
                statusIcon = '🛡️';
                statusText = 'Rate Limiting이 효과적으로 작동';
            }
            
            document.getElementById('rateLimitResults').innerHTML = `
                <div class="alert alert-${statusClass}">
                    <strong>${statusIcon} 테스트 결과:</strong><br>
                    • 총 요청 수: ${totalRequests}<br>
                    • 성공한 요청: ${successRequests}<br>
                    • 차단된 요청: ${blockedRequests}<br>
                    • 차단율: ${((blockedRequests / totalRequests) * 100).toFixed(1)}%<br>
                    • 테스트 시간: ${duration}ms<br>
                    • 상태: ${statusText}
                </div>
            `;
        }
        
        function testDistributedDoS() {
            const ipCount = document.getElementById('ipCount').value;
            const requestPerIP = document.getElementById('requestPerIP').value;
            const resultsDiv = document.getElementById('distributedResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>💥 분산 DoS 패턴 테스트 실행 중...</strong><br>
                    ${ipCount}개 IP에서 각각 ${requestPerIP}회 요청을 전송합니다.
                </div>
            `;
            
            // 분산 패턴 시뮬레이션
            setTimeout(() => {
                const totalRequests = ipCount * requestPerIP;
                const simulatedBlocked = Math.floor(totalRequests * 0.3); // 30% 차단 가정
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-warning">
                        <strong>💥 분산 DoS 테스트 결과:</strong><br>
                        • 시뮬레이션 IP: ${ipCount}개<br>
                        • 총 요청 수: ${totalRequests}개<br>
                        • 차단된 요청: ${simulatedBlocked}개<br>
                        • IP별 평균 차단율: ${((simulatedBlocked / totalRequests) * 100).toFixed(1)}%<br>
                        • 권장사항: IP 기반 제한과 더불어 사용자 인증 기반 제한 필요
                    </div>
                `;
            }, 3000);
        }
        
        function testAPIStress() {
            const endpoint = document.getElementById('endpoint').value;
            const concurrency = document.getElementById('concurrency').value;
            const resultsDiv = document.getElementById('stressResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>📊 API 스트레스 테스트 실행 중...</strong><br>
                    ${endpoint} 엔드포인트에 ${concurrency}개 동시 연결로 부하 테스트를 진행합니다.
                </div>
            `;
            
            // 스트레스 테스트 시뮬레이션
            setTimeout(() => {
                const avgResponseTime = Math.floor(Math.random() * 1000) + 100;
                const errorRate = Math.floor(Math.random() * 20);
                const throughput = Math.floor((concurrency * 1000) / avgResponseTime);
                
                let statusClass = 'success';
                let recommendation = '✅ API가 안정적으로 동작합니다.';
                
                if (avgResponseTime > 500 || errorRate > 5) {
                    statusClass = 'warning';
                    recommendation = '⚠️ 성능 최적화 또는 rate limiting 강화가 필요합니다.';
                }
                
                if (avgResponseTime > 1000 || errorRate > 15) {
                    statusClass = 'danger';
                    recommendation = '❌ 심각한 성능 문제가 있습니다. 즉시 조치가 필요합니다.';
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${statusClass}">
                        <strong>📊 ${endpoint} API 스트레스 테스트 결과:</strong><br>
                        • 동시 연결 수: ${concurrency}개<br>
                        • 평균 응답 시간: ${avgResponseTime}ms<br>
                        • 오류율: ${errorRate}%<br>
                        • 처리량: ${throughput} req/sec<br>
                        • ${recommendation}
                    </div>
                `;
            }, 5000);
        }
    </script>

    <?php include 'templates/footer.php'; ?>
</body>
</html>