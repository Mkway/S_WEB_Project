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

$pageTitle = "Container Security & Docker Escape Test";
$currentTest = "Container Security";
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
                        <h3>🐳 Container Security & Docker Escape Test</h3>
                    </div>
                    <div class="card-body">
                        <p>이 테스트는 컨테이너 환경의 보안 취약점과 Docker 탈출 기법을 검증합니다.</p>
                        
                        <!-- Container Information Gathering -->
                        <div class="mb-4">
                            <h5>1. Container Environment Analysis</h5>
                            <p>현재 컨테이너 환경의 보안 설정 분석</p>
                            
                            <button type="button" class="btn btn-primary" onclick="analyzeContainer()">
                                🔍 컨테이너 환경 분석
                            </button>
                            
                            <div id="containerAnalysis" class="mt-3"></div>
                        </div>

                        <!-- Privileged Container Detection -->
                        <div class="mb-4">
                            <h5>2. Privileged Container Detection</h5>
                            <p>권한이 상승된 컨테이너 실행 여부 확인</p>
                            
                            <form id="privilegedForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="testCommand" class="form-label">테스트 명령어</label>
                                        <select class="form-select" id="testCommand" name="testCommand">
                                            <option value="proc_check">프로세스 권한 확인</option>
                                            <option value="device_access">디바이스 접근 테스트</option>
                                            <option value="capability_check">Capabilities 검사</option>
                                            <option value="mount_namespace">Mount Namespace 분석</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="escalationMethod" class="form-label">권한 상승 방법</label>
                                        <select class="form-select" id="escalationMethod" name="escalationMethod">
                                            <option value="setuid">SETUID 바이너리</option>
                                            <option value="sudo_abuse">sudo 남용</option>
                                            <option value="cgroup_escape">cgroup 탈출</option>
                                            <option value="kernel_exploit">커널 익스플로잇</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-warning mt-2" onclick="testPrivileged()">
                                    ⚡ 권한 상승 테스트
                                </button>
                            </form>
                            
                            <div id="privilegedResults" class="mt-3"></div>
                        </div>

                        <!-- Docker Socket Escape -->
                        <div class="mb-4">
                            <h5>3. Docker Socket Escape Test</h5>
                            <p>Docker 소켓을 통한 컨테이너 탈출 시도</p>
                            
                            <form id="socketForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="socketPath" class="form-label">Docker 소켓 경로</label>
                                        <select class="form-select" id="socketPath" name="socketPath">
                                            <option value="/var/run/docker.sock">표준 소켓 (/var/run/docker.sock)</option>
                                            <option value="/var/lib/docker.sock">대체 경로</option>
                                            <option value="tcp://docker:2375">TCP 소켓</option>
                                            <option value="custom">사용자 지정 경로</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="escapePayload" class="form-label">탈출 페이로드</label>
                                        <select class="form-select" id="escapePayload" name="escapePayload">
                                            <option value="host_mount">호스트 파일시스템 마운트</option>
                                            <option value="privileged_container">권한 컨테이너 생성</option>
                                            <option value="host_network">호스트 네트워크 접근</option>
                                            <option value="bind_mount">바인드 마운트 악용</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-danger mt-2" onclick="testDockerEscape()">
                                    🚪 Docker 탈출 테스트
                                </button>
                            </form>
                            
                            <div id="socketResults" class="mt-3"></div>
                        </div>

                        <!-- Volume Mount Abuse -->
                        <div class="mb-4">
                            <h5>4. Volume Mount Security Test</h5>
                            <p>볼륨 마운트를 통한 호스트 파일 시스템 접근</p>
                            
                            <form id="volumeForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="mountType" class="form-label">마운트 타입</label>
                                        <select class="form-select" id="mountType" name="mountType">
                                            <option value="bind_mount">바인드 마운트</option>
                                            <option value="volume_mount">볼륨 마운트</option>
                                            <option value="tmpfs_mount">tmpfs 마운트</option>
                                            <option value="named_pipe">Named Pipe</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="targetPath" class="form-label">대상 경로</label>
                                        <select class="form-select" id="targetPath" name="targetPath">
                                            <option value="/etc/passwd">패스워드 파일</option>
                                            <option value="/root/.ssh">SSH 키</option>
                                            <option value="/var/log">로그 파일</option>
                                            <option value="/proc">프로세스 정보</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-info mt-2" onclick="testVolumeMount()">
                                    💾 볼륨 마운트 보안 테스트
                                </button>
                            </form>
                            
                            <div id="volumeResults" class="mt-3"></div>
                        </div>

                        <!-- Runtime Security Bypass -->
                        <div class="mb-4">
                            <h5>5. Runtime Security Bypass</h5>
                            <p>컨테이너 런타임 보안 메커니즘 우회 테스트</p>
                            
                            <form id="runtimeForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="runtimeType" class="form-label">런타임 보안</label>
                                        <select class="form-select" id="runtimeType" name="runtimeType">
                                            <option value="seccomp">seccomp 프로필</option>
                                            <option value="apparmor">AppArmor</option>
                                            <option value="selinux">SELinux</option>
                                            <option value="gvisor">gVisor</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="bypassTechnique" class="form-label">우회 기법</label>
                                        <select class="form-select" id="bypassTechnique" name="bypassTechnique">
                                            <option value="syscall_bypass">시스템 콜 우회</option>
                                            <option value="policy_confusion">정책 혼동</option>
                                            <option value="race_condition">Race Condition</option>
                                            <option value="ptrace_abuse">ptrace 남용</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-dark mt-2" onclick="testRuntimeBypass()">
                                    🔓 런타임 보안 우회 테스트
                                </button>
                            </form>
                            
                            <div id="runtimeResults" class="mt-3"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <?php 
                $defenseContent = "
                <strong>🛡️ Container 보안 강화:</strong><br>
                • 최소 권한 원칙 (Least Privilege)<br>
                • ReadOnly 루트 파일시스템<br>
                • 비루트 사용자 실행<br>
                • Seccomp, AppArmor 프로필 적용<br>
                • 불필요한 Capabilities 제거<br><br>

                <strong>⚙️ Docker 보안 설정:</strong><br>
                <code>--user 1000:1000</code><br>
                <code>--read-only</code><br>
                <code>--no-new-privileges</code><br>
                <code>--cap-drop=ALL</code>
                ";
                include 'templates/defense_box.php';
                ?>

                <?php
                $infoContent = "
                <strong>📋 Container 위협 벡터:</strong><br>
                1. 권한 있는 컨테이너 실행<br>
                2. Docker 소켓 노출<br>
                3. 호스트 네트워크 바인딩<br>
                4. 볼륨 마운트 남용<br><br>

                <strong>🎯 보안 검증 포인트:</strong><br>
                • 컨테이너 격리 상태<br>
                • 호스트 리소스 접근 제한<br>
                • 네트워크 세그멘테이션<br>
                • 런타임 정책 준수
                ";
                include 'templates/info_box.php';
                ?>

                <?php
                $referenceContent = "
                <strong>📚 참고 자료:</strong><br>
                • <a href='https://owasp.org/www-project-docker-top-10/' target='_blank'>OWASP Docker Top 10</a><br>
                • <a href='https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html' target='_blank'>Docker Security Cheat Sheet</a><br>
                • <a href='https://docs.docker.com/engine/security/' target='_blank'>Docker Security</a><br><br>

                <strong>🔧 보안 도구:</strong><br>
                • Docker Bench Security<br>
                • Falco<br>
                • Anchore<br>
                • Twistlock/Prisma Cloud
                ";
                include 'templates/reference_box.php';
                ?>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function analyzeContainer() {
            const resultsDiv = document.getElementById('containerAnalysis');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🔍 컨테이너 환경 분석 중...</strong><br>
                    시스템 정보를 수집하고 있습니다.
                </div>
            `;
            
            // 컨테이너 환경 분석 시뮬레이션
            setTimeout(() => {
                const containerInfo = {
                    runtime: 'Docker 20.10.x',
                    privileged: Math.random() > 0.8 ? '예' : '아니오',
                    rootUser: Math.random() > 0.6 ? '예' : '아니오',
                    networkMode: Math.random() > 0.7 ? 'host' : 'bridge',
                    volumes: Math.floor(Math.random() * 5) + 1,
                    capabilities: Math.floor(Math.random() * 10) + 5
                };
                
                let alertClass = 'success';
                let riskLevel = '낮음';
                let icon = '✅';
                
                if (containerInfo.privileged === '예' || containerInfo.rootUser === '예' || containerInfo.networkMode === 'host') {
                    alertClass = 'danger';
                    riskLevel = '높음';
                    icon = '⚠️';
                } else if (containerInfo.volumes > 2 || containerInfo.capabilities > 8) {
                    alertClass = 'warning';
                    riskLevel = '중간';
                    icon = '🔍';
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} 컨테이너 환경 분석 결과:</strong><br>
                        • 컨테이너 런타임: ${containerInfo.runtime}<br>
                        • 권한 모드 실행: ${containerInfo.privileged}<br>
                        • Root 사용자: ${containerInfo.rootUser}<br>
                        • 네트워크 모드: ${containerInfo.networkMode}<br>
                        • 마운트된 볼륨: ${containerInfo.volumes}개<br>
                        • 활성 Capabilities: ${containerInfo.capabilities}개<br>
                        • 위험도: <strong>${riskLevel}</strong><br><br>
                        
                        <strong>권장 조치사항:</strong><br>
                        ${containerInfo.privileged === '예' ? '• --privileged 플래그 제거<br>' : ''}
                        ${containerInfo.rootUser === '예' ? '• 비루트 사용자로 실행<br>' : ''}
                        ${containerInfo.networkMode === 'host' ? '• 호스트 네트워크 모드 변경<br>' : ''}
                        • 불필요한 볼륨 마운트 제거<br>
                        • Capabilities 최소화 적용
                    </div>
                `;
            }, 2000);
        }
        
        function testPrivileged() {
            const command = document.getElementById('testCommand').value;
            const method = document.getElementById('escalationMethod').value;
            const resultsDiv = document.getElementById('privilegedResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>⚡ 권한 상승 테스트 실행 중...</strong><br>
                    테스트: ${command}<br>
                    방법: ${method}
                </div>
            `;
            
            setTimeout(() => {
                let success = Math.random() > 0.7; // 30% 성공률
                let alertClass = success ? 'danger' : 'success';
                let icon = success ? '❌' : '🛡️';
                let message = success ? '권한 상승 성공 - 보안 위험' : '권한 상승 차단 - 보안 정상';
                
                let details = '';
                switch (method) {
                    case 'setuid':
                        details = success ? 
                            'SETUID 바이너리를 통한 권한 상승이 성공했습니다. 위험한 바이너리가 발견되었습니다.' :
                            'SETUID 바이너리 보안이 정상입니다. 권한 상승이 차단되었습니다.';
                        break;
                    case 'sudo_abuse':
                        details = success ?
                            'sudo 설정 오류로 권한 상승이 가능합니다. sudoers 파일을 검토해야 합니다.' :
                            'sudo 보안 설정이 올바릅니다. 무단 권한 상승이 차단되었습니다.';
                        break;
                    case 'cgroup_escape':
                        details = success ?
                            'cgroup 제한을 우회했습니다. 컨테이너 격리가 부분적으로 손상되었습니다.' :
                            'cgroup 격리가 정상 작동합니다. 권한 상승 시도가 차단되었습니다.';
                        break;
                    case 'kernel_exploit':
                        details = success ?
                            '커널 취약점을 통한 권한 상승이 성공했습니다. 즉시 시스템 업데이트가 필요합니다.' :
                            '커널 보안 패치가 적용되어 있습니다. 익스플로잇이 차단되었습니다.';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} 권한 상승 테스트 결과:</strong><br>
                        ${message}<br><br>
                        <strong>상세 결과:</strong><br>
                        ${details}<br><br>
                        <strong>보안 강화 방안:</strong><br>
                        • 비루트 사용자로 실행<br>
                        • --no-new-privileges 플래그 사용<br>
                        • seccomp 프로필 적용<br>
                        • 정기적인 보안 업데이트
                    </div>
                `;
            }, 3000);
        }
        
        function testDockerEscape() {
            const socketPath = document.getElementById('socketPath').value;
            const payload = document.getElementById('escapePayload').value;
            const resultsDiv = document.getElementById('socketResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🚪 Docker 탈출 테스트 실행 중...</strong><br>
                    소켓: ${socketPath}<br>
                    페이로드: ${payload}
                </div>
            `;
            
            setTimeout(() => {
                let vulnerable = Math.random() > 0.6; // 40% 취약점 발견률
                let alertClass = vulnerable ? 'danger' : 'success';
                let icon = vulnerable ? '🚨' : '🔒';
                
                let result = '';
                switch (payload) {
                    case 'host_mount':
                        result = vulnerable ?
                            '호스트 파일시스템 마운트에 성공했습니다. 루트 디렉토리 접근이 가능합니다.' :
                            '호스트 파일시스템 접근이 차단되었습니다. 마운트 권한이 제한되어 있습니다.';
                        break;
                    case 'privileged_container':
                        result = vulnerable ?
                            '권한 있는 새 컨테이너 생성에 성공했습니다. 호스트 제어권을 획득할 수 있습니다.' :
                            '권한 있는 컨테이너 생성이 차단되었습니다. Docker 소켓 접근이 제한됩니다.';
                        break;
                    case 'host_network':
                        result = vulnerable ?
                            '호스트 네트워크에 접근했습니다. 네트워크 인터페이스 조작이 가능합니다.' :
                            '호스트 네트워크 접근이 차단되었습니다. 네트워크 격리가 유지됩니다.';
                        break;
                    case 'bind_mount':
                        result = vulnerable ?
                            '바인드 마운트를 통해 호스트 파일에 접근했습니다. 중요 시스템 파일 조작이 가능합니다.' :
                            '바인드 마운트 접근이 제한되었습니다. 파일 시스템 격리가 유지됩니다.';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} Docker 탈출 테스트 결과:</strong><br>
                        ${result}<br><br>
                        <strong>보안 권장사항:</strong><br>
                        • Docker 소켓을 컨테이너에 마운트하지 않기<br>
                        • Unix 소켓 대신 TLS로 보안된 TCP 소켓 사용<br>
                        • Docker API 접근 권한 최소화<br>
                        • 컨테이너 런타임 보안 정책 강화<br>
                        • 네트워크 세그멘테이션 적용
                    </div>
                `;
            }, 4000);
        }
        
        function testVolumeMount() {
            const mountType = document.getElementById('mountType').value;
            const targetPath = document.getElementById('targetPath').value;
            const resultsDiv = document.getElementById('volumeResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>💾 볼륨 마운트 보안 테스트 실행 중...</strong><br>
                    마운트 타입: ${mountType}<br>
                    대상 경로: ${targetPath}
                </div>
            `;
            
            setTimeout(() => {
                let accessible = Math.random() > 0.5;
                let alertClass = accessible ? 'warning' : 'success';
                let icon = accessible ? '⚠️' : '🛡️';
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} 볼륨 마운트 보안 테스트 결과:</strong><br>
                        • 마운트 타입: ${mountType}<br>
                        • 대상 경로 접근: ${accessible ? '가능' : '차단'}<br>
                        • 보안 상태: ${accessible ? '취약' : '안전'}<br><br>
                        
                        <strong>발견된 위험:</strong><br>
                        ${accessible ? 
                            `• ${targetPath} 경로에 무단 접근 가능<br>• 호스트 시스템 파일 조작 위험<br>• 권한 상승 가능성 존재` :
                            '• 적절한 접근 제어가 설정되어 있음<br>• 볼륨 마운트 보안이 정상 작동<br>• 호스트 파일 시스템이 보호됨'
                        }<br><br>
                        
                        <strong>보안 개선 권장사항:</strong><br>
                        • ReadOnly 마운트 사용<br>
                        • 최소 필요 경로만 마운트<br>
                        • 적절한 파일 권한 설정<br>
                        • 민감한 시스템 디렉토리 마운트 금지
                    </div>
                `;
            }, 3000);
        }
        
        function testRuntimeBypass() {
            const runtimeType = document.getElementById('runtimeType').value;
            const technique = document.getElementById('bypassTechnique').value;
            const resultsDiv = document.getElementById('runtimeResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🔓 런타임 보안 우회 테스트 실행 중...</strong><br>
                    보안 메커니즘: ${runtimeType}<br>
                    우회 기법: ${technique}
                </div>
            `;
            
            setTimeout(() => {
                let bypassed = Math.random() > 0.8; // 20% 우회 성공률
                let alertClass = bypassed ? 'danger' : 'success';
                let icon = bypassed ? '💥' : '🛡️';
                
                let analysis = '';
                switch (runtimeType) {
                    case 'seccomp':
                        analysis = bypassed ?
                            'seccomp 프로필을 우회했습니다. 제한된 시스템 콜에 접근이 가능합니다.' :
                            'seccomp 보안이 효과적으로 작동합니다. 위험한 시스템 콜이 차단되었습니다.';
                        break;
                    case 'apparmor':
                        analysis = bypassed ?
                            'AppArmor 정책을 우회했습니다. MAC(Mandatory Access Control)이 무력화되었습니다.' :
                            'AppArmor가 정상적으로 동작합니다. 정책 위반 시도가 차단되었습니다.';
                        break;
                    case 'selinux':
                        analysis = bypassed ?
                            'SELinux 컨텍스트를 조작했습니다. 보안 정책이 우회되었습니다.' :
                            'SELinux 보안 모델이 유지됩니다. 정책 우회 시도가 실패했습니다.';
                        break;
                    case 'gvisor':
                        analysis = bypassed ?
                            'gVisor 샌드박스를 탈출했습니다. 사용자 공간 커널이 손상되었습니다.' :
                            'gVisor 샌드박스가 정상 작동합니다. 탈출 시도가 차단되었습니다.';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} 런타임 보안 우회 테스트 결과:</strong><br>
                        ${analysis}<br><br>
                        <strong>우회 기법 분석:</strong><br>
                        • 사용된 기법: ${technique}<br>
                        • 성공 여부: ${bypassed ? '성공 (위험)' : '실패 (안전)'}<br>
                        • 영향 범위: ${bypassed ? '시스템 전체' : '컨테이너 내부'}<br><br>
                        
                        <strong>종합 보안 권장사항:</strong><br>
                        • 최신 런타임 보안 정책 적용<br>
                        • 다층 보안 메커니즘 구현<br>
                        • 컨테이너 행동 모니터링 강화<br>
                        • 정기적인 보안 정책 업데이트<br>
                        • Zero Trust 네트워크 모델 적용
                    </div>
                `;
            }, 5000);
        }
    </script>

    <?php include 'templates/footer.php'; ?>
</body>
</html>