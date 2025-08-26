<?php
require_once '../config.php';

$pageTitle = "Multi-Factor Authentication (MFA) Security Test";
$currentTest = "MFA Security";
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
                        <h3>🔐 Multi-Factor Authentication (MFA) Security Test</h3>
                    </div>
                    <div class="card-body">
                        <p>이 테스트는 다중 인증 요소(MFA) 시스템의 보안 취약점을 검증합니다.</p>
                        
                        <!-- TOTP Bypass Test -->
                        <div class="mb-4">
                            <h5>1. TOTP (Time-based OTP) Bypass Test</h5>
                            <p>시간 기반 일회용 패스워드 우회 시도</p>
                            
                            <form id="totpForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="totpCode" class="form-label">TOTP 코드 (6자리)</label>
                                        <input type="text" class="form-control" id="totpCode" name="totpCode" 
                                               placeholder="123456" maxlength="6" pattern="[0-9]{6}">
                                    </div>
                                    <div class="col-md-6">
                                        <label for="bypassMethod" class="form-label">우회 방법</label>
                                        <select class="form-select" id="bypassMethod" name="bypassMethod">
                                            <option value="brute_force">Brute Force Attack</option>
                                            <option value="time_manipulation">Time Manipulation</option>
                                            <option value="replay_attack">Replay Attack</option>
                                            <option value="race_condition">Race Condition</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-warning mt-2" onclick="testTOTPBypass()">
                                    🔐 TOTP 우회 테스트
                                </button>
                            </form>
                            
                            <div id="totpResults" class="mt-3"></div>
                        </div>

                        <!-- SMS OTP Vulnerabilities -->
                        <div class="mb-4">
                            <h5>2. SMS OTP Security Test</h5>
                            <p>SMS 기반 OTP의 보안 취약점 검증</p>
                            
                            <form id="smsOTPForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="phoneNumber" class="form-label">전화번호</label>
                                        <input type="tel" class="form-control" id="phoneNumber" name="phoneNumber" 
                                               placeholder="+82-10-1234-5678">
                                    </div>
                                    <div class="col-md-6">
                                        <label for="smsAttack" class="form-label">공격 유형</label>
                                        <select class="form-select" id="smsAttack" name="smsAttack">
                                            <option value="sim_swap">SIM Swapping</option>
                                            <option value="ss7_attack">SS7 Protocol Attack</option>
                                            <option value="social_engineering">Social Engineering</option>
                                            <option value="intercept">SMS Intercept</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-danger mt-2" onclick="testSMSOTP()">
                                    📱 SMS OTP 공격 시뮬레이션
                                </button>
                            </form>
                            
                            <div id="smsResults" class="mt-3"></div>
                        </div>

                        <!-- Backup Code Enumeration -->
                        <div class="mb-4">
                            <h5>3. Backup Recovery Code Test</h5>
                            <p>백업 복구 코드의 보안성 검증</p>
                            
                            <form id="backupCodeForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="backupCode" class="form-label">백업 코드</label>
                                        <input type="text" class="form-control" id="backupCode" name="backupCode" 
                                               placeholder="ABCD-EFGH-1234">
                                    </div>
                                    <div class="col-md-6">
                                        <label for="enumerationMethod" class="form-label">열거 방법</label>
                                        <select class="form-select" id="enumerationMethod" name="enumerationMethod">
                                            <option value="pattern_analysis">Pattern Analysis</option>
                                            <option value="dictionary_attack">Dictionary Attack</option>
                                            <option value="entropy_analysis">Entropy Analysis</option>
                                            <option value="timing_attack">Timing Attack</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-info mt-2" onclick="testBackupCodes()">
                                    🔑 백업 코드 보안 테스트
                                </button>
                            </form>
                            
                            <div id="backupResults" class="mt-3"></div>
                        </div>

                        <!-- MFA Bypass Techniques -->
                        <div class="mb-4">
                            <h5>4. Advanced MFA Bypass Techniques</h5>
                            <p>고급 MFA 우회 기법 테스트</p>
                            
                            <form id="advancedMFAForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="bypassTechnique" class="form-label">우회 기법</label>
                                        <select class="form-select" id="bypassTechnique" name="bypassTechnique">
                                            <option value="session_fixation">Session Fixation</option>
                                            <option value="oauth_confusion">OAuth State Confusion</option>
                                            <option value="response_manipulation">Response Manipulation</option>
                                            <option value="push_notification">Push Notification Spam</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="targetUser" class="form-label">대상 사용자</label>
                                        <input type="text" class="form-control" id="targetUser" name="targetUser" 
                                               placeholder="test@example.com">
                                    </div>
                                </div>
                                <button type="button" class="btn btn-dark mt-2" onclick="testAdvancedMFABypass()">
                                    🎯 고급 MFA 우회 테스트
                                </button>
                            </form>
                            
                            <div id="advancedResults" class="mt-3"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <?php 
                $defenseContent = "
                <strong>🛡️ MFA 보안 강화 방법:</strong><br>
                • Hardware Security Keys (FIDO2/WebAuthn)<br>
                • App-based TOTP with secure backup<br>
                • Rate limiting on MFA attempts<br>
                • Anti-automation measures<br>
                • Context-aware authentication<br><br>

                <strong>⚙️ 보안 설정:</strong><br>
                • TOTP 윈도우 최소화<br>
                • 백업 코드 암호화 저장<br>
                • 이상 활동 모니터링<br>
                • 디바이스 바인딩 구현
                ";
                include 'templates/defense_box.php';
                ?>

                <?php
                $infoContent = "
                <strong>📋 MFA 취약점 유형:</strong><br>
                1. TOTP 브루트 포스<br>
                2. SMS 인터셉트<br>
                3. 백업 코드 열거<br>
                4. 세션 조작<br><br>

                <strong>🎯 검증 포인트:</strong><br>
                • 시간 동기화 검증<br>
                • 재사용 방지 메커니즘<br>
                • 실패 시 계정 잠금<br>
                • 푸시 알림 스팸 방지
                ";
                include 'templates/info_box.php';
                ?>

                <?php
                $referenceContent = "
                <strong>📚 참고 자료:</strong><br>
                • <a href='https://owasp.org/www-community/controls/Multi_Factor_Authentication_Cheat_Sheet' target='_blank'>OWASP MFA Guide</a><br>
                • <a href='https://fidoalliance.org/specifications/' target='_blank'>FIDO2/WebAuthn Specs</a><br>
                • <a href='https://tools.ietf.org/html/rfc6238' target='_blank'>TOTP RFC 6238</a><br><br>

                <strong>🔧 테스트 도구:</strong><br>
                • Google Authenticator<br>
                • Authy<br>
                • YubiKey<br>
                • OWASP ZAP MFA Tests
                ";
                include 'templates/reference_box.php';
                ?>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function testTOTPBypass() {
            const totpCode = document.getElementById('totpCode').value;
            const method = document.getElementById('bypassMethod').value;
            const resultsDiv = document.getElementById('totpResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🔐 TOTP 우회 테스트 실행 중...</strong><br>
                    방법: ${method}<br>
                    입력된 코드: ${totpCode || '없음'}
                </div>
            `;
            
            // TOTP 우회 테스트 시뮬레이션
            setTimeout(() => {
                let result = '';
                let alertClass = 'success';
                let icon = '🛡️';
                
                switch (method) {
                    case 'brute_force':
                        result = 'Brute force 공격이 차단되었습니다. Rate limiting이 효과적으로 작동 중입니다.';
                        break;
                    case 'time_manipulation':
                        result = '시간 조작 공격을 탐지했습니다. 서버 시간 기준으로 검증이 이루어집니다.';
                        break;
                    case 'replay_attack':
                        result = 'Replay 공격이 차단되었습니다. 사용된 토큰은 재사용이 불가능합니다.';
                        break;
                    case 'race_condition':
                        alertClass = 'warning';
                        icon = '⚠️';
                        result = 'Race condition 취약점이 발견되었습니다. 동시 요청 처리 로직을 강화해야 합니다.';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} TOTP 우회 테스트 결과:</strong><br>
                        ${result}<br><br>
                        <strong>권장사항:</strong><br>
                        • TOTP 코드 유효 시간 30초 이하로 설정<br>
                        • 연속 실패 시 계정 일시 잠금<br>
                        • 사용된 코드 추적 및 재사용 방지
                    </div>
                `;
            }, 2000);
        }
        
        function testSMSOTP() {
            const phone = document.getElementById('phoneNumber').value;
            const attack = document.getElementById('smsAttack').value;
            const resultsDiv = document.getElementById('smsResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>📱 SMS OTP 공격 시뮬레이션 실행 중...</strong><br>
                    대상 번호: ${phone || '시뮬레이션'}<br>
                    공격 유형: ${attack}
                </div>
            `;
            
            setTimeout(() => {
                let result = '';
                let alertClass = 'danger';
                let icon = '⚠️';
                
                switch (attack) {
                    case 'sim_swap':
                        result = 'SIM Swapping 공격에 취약할 수 있습니다. 통신사 본인 확인 절차 강화가 필요합니다.';
                        break;
                    case 'ss7_attack':
                        result = 'SS7 프로토콜 공격에 노출되어 있습니다. SMS OTP 대신 앱 기반 인증을 권장합니다.';
                        break;
                    case 'social_engineering':
                        result = '소셜 엔지니어링 공격 위험이 있습니다. 사용자 교육과 추가 검증이 필요합니다.';
                        break;
                    case 'intercept':
                        result = 'SMS 인터셉트 가능성이 있습니다. 메시지 암호화 또는 대체 수단 고려가 필요합니다.';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} SMS OTP 보안 테스트 결과:</strong><br>
                        ${result}<br><br>
                        <strong>보안 강화 방안:</strong><br>
                        • 앱 기반 TOTP로 전환<br>
                        • Hardware Security Key 도입<br>
                        • 푸시 알림 기반 인증<br>
                        • 컨텍스트 기반 리스크 평가
                    </div>
                `;
            }, 3000);
        }
        
        function testBackupCodes() {
            const code = document.getElementById('backupCode').value;
            const method = document.getElementById('enumerationMethod').value;
            const resultsDiv = document.getElementById('backupResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🔑 백업 코드 보안 테스트 실행 중...</strong><br>
                    테스트 방법: ${method}
                </div>
            `;
            
            setTimeout(() => {
                let entropy = Math.random() > 0.7 ? '높음' : '낮음';
                let alertClass = entropy === '높음' ? 'success' : 'warning';
                let icon = entropy === '높음' ? '🔒' : '⚠️';
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} 백업 코드 보안 분석 결과:</strong><br>
                        • 엔트로피 수준: ${entropy}<br>
                        • 패턴 예측 가능성: ${entropy === '높음' ? '낮음' : '높음'}<br>
                        • 브루트 포스 저항성: ${entropy === '높음' ? '강함' : '약함'}<br><br>
                        
                        <strong>개선 권장사항:</strong><br>
                        • 최소 128비트 엔트로피 확보<br>
                        • 암호화된 저장소 사용<br>
                        • 사용 후 자동 폐기<br>
                        • 생성 시 예측 불가능한 패턴 적용
                    </div>
                `;
            }, 2000);
        }
        
        function testAdvancedMFABypass() {
            const technique = document.getElementById('bypassTechnique').value;
            const user = document.getElementById('targetUser').value;
            const resultsDiv = document.getElementById('advancedResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🎯 고급 MFA 우회 테스트 실행 중...</strong><br>
                    기법: ${technique}<br>
                    대상: ${user || '시뮬레이션 계정'}
                </div>
            `;
            
            setTimeout(() => {
                let success = Math.random() > 0.8; // 20% 성공률로 현실적인 시뮬레이션
                let alertClass = success ? 'danger' : 'success';
                let icon = success ? '❌' : '🛡️';
                let message = success ? '우회 성공 - 보안 강화 필요' : '우회 차단 - 보안 메커니즘 정상 작동';
                
                let details = '';
                switch (technique) {
                    case 'session_fixation':
                        details = success ? 
                            '세션 고정 공격이 성공했습니다. 세션 재생성 로직을 강화해야 합니다.' :
                            '세션 고정 공격이 차단되었습니다. 로그인 시 세션 ID가 정상적으로 재생성됩니다.';
                        break;
                    case 'oauth_confusion':
                        details = success ?
                            'OAuth state 혼동 공격이 성공했습니다. state 매개변수 검증을 강화해야 합니다.' :
                            'OAuth state 검증이 정상 작동합니다. 상태 매개변수가 올바르게 검증됩니다.';
                        break;
                    case 'response_manipulation':
                        details = success ?
                            '응답 조작 공격이 성공했습니다. 클라이언트 응답 검증을 강화해야 합니다.' :
                            '응답 무결성 검증이 정상 작동합니다. 조작된 응답이 차단되었습니다.';
                        break;
                    case 'push_notification':
                        details = success ?
                            '푸시 알림 스팸 공격이 성공했습니다. 알림 빈도 제한이 필요합니다.' :
                            '푸시 알림 보호 기능이 작동합니다. 스팸 공격이 차단되었습니다.';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} 고급 MFA 우회 테스트 결과:</strong><br>
                        ${message}<br><br>
                        <strong>세부 결과:</strong><br>
                        ${details}<br><br>
                        <strong>종합 권장사항:</strong><br>
                        • Zero Trust 모델 적용<br>
                        • 컨텍스트 기반 인증 강화<br>
                        • 지속적인 보안 모니터링<br>
                        • 사용자 행동 분석 도입
                    </div>
                `;
            }, 4000);
        }
    </script>

    <?php include 'templates/footer.php'; ?>
</body>
</html>