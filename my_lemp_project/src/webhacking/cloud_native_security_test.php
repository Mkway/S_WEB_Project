<?php
require_once '../config.php';

$pageTitle = "Cloud Native Security Testing";
$currentTest = "Cloud Native Security";
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
                        <h3>☁️ Cloud Native Security Testing</h3>
                    </div>
                    <div class="card-body">
                        <p>이 테스트는 클라우드 네이티브 환경의 보안 취약점과 설정 오류를 검증합니다.</p>
                        
                        <!-- Kubernetes Security Test -->
                        <div class="mb-4">
                            <h5>1. Kubernetes Security Configuration</h5>
                            <p>쿠버네티스 클러스터 보안 설정 분석</p>
                            
                            <form id="k8sForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="k8sComponent" class="form-label">K8s 구성 요소</label>
                                        <select class="form-select" id="k8sComponent" name="k8sComponent">
                                            <option value="rbac">RBAC 정책</option>
                                            <option value="network_policy">네트워크 정책</option>
                                            <option value="pod_security">Pod 보안 정책</option>
                                            <option value="secrets">Secret 관리</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="k8sTest" class="form-label">보안 테스트</label>
                                        <select class="form-select" id="k8sTest" name="k8sTest">
                                            <option value="privilege_escalation">권한 상승</option>
                                            <option value="namespace_isolation">네임스페이스 격리</option>
                                            <option value="service_account">서비스 계정 악용</option>
                                            <option value="etcd_access">etcd 무단 접근</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-warning mt-2" onclick="testK8sSecurity()">
                                    ⚙️ K8s 보안 테스트
                                </button>
                            </form>
                            
                            <div id="k8sResults" class="mt-3"></div>
                        </div>

                        <!-- Service Mesh Security -->
                        <div class="mb-4">
                            <h5>2. Service Mesh Security</h5>
                            <p>서비스 메시 환경의 보안 설정 검증</p>
                            
                            <form id="serviceMeshForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="meshType" class="form-label">Service Mesh</label>
                                        <select class="form-select" id="meshType" name="meshType">
                                            <option value="istio">Istio</option>
                                            <option value="linkerd">Linkerd</option>
                                            <option value="consul_connect">Consul Connect</option>
                                            <option value="envoy">Envoy Proxy</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="meshAttack" class="form-label">공격 벡터</label>
                                        <select class="form-select" id="meshAttack" name="meshAttack">
                                            <option value="mtls_bypass">mTLS 우회</option>
                                            <option value="traffic_interception">트래픽 가로채기</option>
                                            <option value="policy_bypass">정책 우회</option>
                                            <option value="sidecar_escape">사이드카 탈출</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-info mt-2" onclick="testServiceMesh()">
                                    🕸️ Service Mesh 보안 테스트
                                </button>
                            </form>
                            
                            <div id="serviceMeshResults" class="mt-3"></div>
                        </div>

                        <!-- Cloud Provider Security -->
                        <div class="mb-4">
                            <h5>3. Cloud Provider Security</h5>
                            <p>클라우드 제공업체별 보안 설정 검사</p>
                            
                            <form id="cloudForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="cloudProvider" class="form-label">클라우드 제공업체</label>
                                        <select class="form-select" id="cloudProvider" name="cloudProvider">
                                            <option value="aws">Amazon Web Services</option>
                                            <option value="gcp">Google Cloud Platform</option>
                                            <option value="azure">Microsoft Azure</option>
                                            <option value="alibaba">Alibaba Cloud</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="cloudService" class="form-label">클라우드 서비스</label>
                                        <select class="form-select" id="cloudService" name="cloudService">
                                            <option value="iam">IAM 정책</option>
                                            <option value="storage">스토리지 보안</option>
                                            <option value="networking">네트워킹</option>
                                            <option value="logging">로깅 및 모니터링</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-primary mt-2" onclick="testCloudSecurity()">
                                    ☁️ 클라우드 보안 검사
                                </button>
                            </form>
                            
                            <div id="cloudResults" class="mt-3"></div>
                        </div>

                        <!-- Serverless Security -->
                        <div class="mb-4">
                            <h5>4. Serverless Security</h5>
                            <p>서버리스 아키텍처 보안 취약점 검증</p>
                            
                            <form id="serverlessForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="serverlessType" class="form-label">서버리스 플랫폼</label>
                                        <select class="form-select" id="serverlessType" name="serverlessType">
                                            <option value="lambda">AWS Lambda</option>
                                            <option value="cloud_functions">Google Cloud Functions</option>
                                            <option value="azure_functions">Azure Functions</option>
                                            <option value="vercel">Vercel Functions</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="serverlessVuln" class="form-label">취약점 유형</label>
                                        <select class="form-select" id="serverlessVuln" name="serverlessVuln">
                                            <option value="function_injection">Function Injection</option>
                                            <option value="cold_start_abuse">Cold Start 남용</option>
                                            <option value="event_injection">Event Injection</option>
                                            <option value="resource_exhaustion">리소스 고갈</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-success mt-2" onclick="testServerless()">
                                    ⚡ 서버리스 보안 테스트
                                </button>
                            </form>
                            
                            <div id="serverlessResults" class="mt-3"></div>
                        </div>

                        <!-- Infrastructure as Code Security -->
                        <div class="mb-4">
                            <h5>5. Infrastructure as Code (IaC) Security</h5>
                            <p>IaC 템플릿의 보안 설정 오류 검사</p>
                            
                            <form id="iacForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="iacTool" class="form-label">IaC 도구</label>
                                        <select class="form-select" id="iacTool" name="iacTool">
                                            <option value="terraform">Terraform</option>
                                            <option value="cloudformation">CloudFormation</option>
                                            <option value="arm_template">ARM Template</option>
                                            <option value="pulumi">Pulumi</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="iacVuln" class="form-label">보안 검사 항목</label>
                                        <select class="form-select" id="iacVuln" name="iacVuln">
                                            <option value="hardcoded_secrets">하드코딩된 비밀</option>
                                            <option value="overprivileged_roles">과도한 권한</option>
                                            <option value="public_resources">공개 리소스</option>
                                            <option value="unencrypted_storage">암호화되지 않은 저장소</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-warning mt-2" onclick="testIaC()">
                                    📋 IaC 보안 검사
                                </button>
                            </form>
                            
                            <div id="iacResults" class="mt-3"></div>
                        </div>

                        <!-- Cloud Native Supply Chain -->
                        <div class="mb-4">
                            <h5>6. Supply Chain Security</h5>
                            <p>클라우드 네이티브 공급망 보안 검증</p>
                            
                            <form id="supplyChainForm" class="mb-3">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="supplyChainStage" class="form-label">공급망 단계</label>
                                        <select class="form-select" id="supplyChainStage" name="supplyChainStage">
                                            <option value="source_code">소스 코드</option>
                                            <option value="build_pipeline">빌드 파이프라인</option>
                                            <option value="container_registry">컨테이너 레지스트리</option>
                                            <option value="deployment">배포 단계</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="supplyChainAttack" class="form-label">공격 유형</label>
                                        <select class="form-select" id="supplyChainAttack" name="supplyChainAttack">
                                            <option value="malicious_dependency">악성 의존성</option>
                                            <option value="build_system_compromise">빌드 시스템 침해</option>
                                            <option value="registry_poisoning">레지스트리 오염</option>
                                            <option value="deployment_manipulation">배포 조작</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-danger mt-2" onclick="testSupplyChain()">
                                    🔗 공급망 보안 테스트
                                </button>
                            </form>
                            
                            <div id="supplyChainResults" class="mt-3"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <?php 
                $defenseContent = "
                <strong>🛡️ Cloud Native 보안 강화:</strong><br>
                • Zero Trust 네트워크 모델<br>
                • Pod Security Standards (PSS)<br>
                • Service Mesh mTLS 암호화<br>
                • RBAC 최소 권한 원칙<br>
                • 컨테이너 이미지 서명 검증<br><br>

                <strong>⚙️ 보안 정책 예시:</strong><br>
                <code>securityContext:<br>
                &nbsp;&nbsp;runAsNonRoot: true<br>
                &nbsp;&nbsp;readOnlyRootFilesystem: true</code>
                ";
                include 'templates/defense_box.php';
                ?>

                <?php
                $infoContent = "
                <strong>📋 Cloud Native 위협 모델:</strong><br>
                1. 컨테이너 런타임 취약점<br>
                2. Kubernetes API 서버 공격<br>
                3. 서비스 간 통신 가로채기<br>
                4. 공급망 공격<br>
                5. 클라우드 설정 오류<br><br>

                <strong>🎯 보안 검증 영역:</strong><br>
                • 클러스터 보안 정책<br>
                • 네트워크 세그멘테이션<br>
                • 시크릿 관리<br>
                • 이미지 보안 스캔
                ";
                include 'templates/info_box.php';
                ?>

                <?php
                $referenceContent = "
                <strong>📚 참고 자료:</strong><br>
                • <a href='https://kubernetes.io/docs/concepts/security/' target='_blank'>Kubernetes Security</a><br>
                • <a href='https://www.cncf.io/projects/' target='_blank'>CNCF Security Projects</a><br>
                • <a href='https://owasp.org/www-project-kubernetes-top-ten/' target='_blank'>OWASP Kubernetes Top 10</a><br><br>

                <strong>🔧 보안 도구:</strong><br>
                • Falco<br>
                • Open Policy Agent (OPA)<br>
                • Twistlock/Prisma Cloud<br>
                • Aqua Security
                ";
                include 'templates/reference_box.php';
                ?>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function testK8sSecurity() {
            const component = document.getElementById('k8sComponent').value;
            const test = document.getElementById('k8sTest').value;
            const resultsDiv = document.getElementById('k8sResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>⚙️ Kubernetes 보안 테스트 실행 중...</strong><br>
                    구성 요소: ${component}<br>
                    테스트 유형: ${test}
                </div>
            `;
            
            setTimeout(() => {
                let vulnerable = Math.random() > 0.6; // 40% 취약점 발견률
                let alertClass = vulnerable ? 'danger' : 'success';
                let icon = vulnerable ? '🚨' : '🛡️';
                
                let analysis = '';
                let recommendations = [];
                
                switch (component) {
                    case 'rbac':
                        analysis = vulnerable ?
                            'RBAC 설정에 과도한 권한이 발견되었습니다. 클러스터 전체 권한을 가진 서비스 계정이 존재합니다.' :
                            'RBAC 설정이 적절합니다. 최소 권한 원칙이 잘 적용되어 있습니다.';
                        recommendations = [
                            '최소 권한 원칙 적용',
                            'ClusterRole 대신 Role 사용',
                            '정기적인 RBAC 권한 감사'
                        ];
                        break;
                    case 'network_policy':
                        analysis = vulnerable ?
                            '네트워크 정책이 미설정되어 Pod 간 무제한 통신이 가능합니다.' :
                            '네트워크 정책이 적절히 설정되어 Pod 간 통신이 제어되고 있습니다.';
                        recommendations = [
                            '기본 거부 정책 설정',
                            '네임스페이스별 격리',
                            '마이크로세그멘테이션 구현'
                        ];
                        break;
                    case 'pod_security':
                        analysis = vulnerable ?
                            'Pod 보안 컨텍스트가 부적절합니다. 권한 있는 컨테이너 실행이 가능합니다.' :
                            'Pod 보안 표준이 적절히 적용되어 있습니다.';
                        recommendations = [
                            'Pod Security Standards 적용',
                            'runAsNonRoot 설정',
                            'readOnlyRootFilesystem 활성화'
                        ];
                        break;
                    case 'secrets':
                        analysis = vulnerable ?
                            'Secret이 평문으로 저장되거나 과도하게 노출되어 있습니다.' :
                            'Secret 관리가 적절합니다. 암호화 및 접근 제어가 올바릅니다.';
                        recommendations = [
                            'etcd 암호화 활성화',
                            'External Secret Operator 사용',
                            'Secret 순환 정책 구현'
                        ];
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} Kubernetes 보안 테스트 결과:</strong><br>
                        ${analysis}<br><br>
                        <strong>보안 권장사항:</strong><br>
                        ${recommendations.map(rec => `• ${rec}`).join('<br>')}<br><br>
                        <strong>추가 보안 조치:</strong><br>
                        • Admission Controller 활용<br>
                        • 정기적인 보안 감사<br>
                        • 모니터링 및 로깅 강화
                    </div>
                `;
            }, 3000);
        }
        
        function testServiceMesh() {
            const meshType = document.getElementById('meshType').value;
            const attack = document.getElementById('meshAttack').value;
            const resultsDiv = document.getElementById('serviceMeshResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🕸️ Service Mesh 보안 테스트 실행 중...</strong><br>
                    메시 유형: ${meshType}<br>
                    공격 벡터: ${attack}
                </div>
            `;
            
            setTimeout(() => {
                let success = Math.random() > 0.7; // 30% 공격 성공률
                let alertClass = success ? 'warning' : 'success';
                let icon = success ? '⚠️' : '🔒';
                
                let result = '';
                switch (attack) {
                    case 'mtls_bypass':
                        result = success ?
                            'mTLS 우회에 성공했습니다. 인증서 검증이나 암호화 설정에 문제가 있습니다.' :
                            'mTLS가 올바르게 작동합니다. 모든 서비스 간 통신이 암호화되고 인증됩니다.';
                        break;
                    case 'traffic_interception':
                        result = success ?
                            '트래픽 가로채기가 가능합니다. 사이드카 프록시 설정을 검토해야 합니다.' :
                            '트래픽이 안전하게 보호됩니다. 사이드카 프록시가 모든 통신을 암호화합니다.';
                        break;
                    case 'policy_bypass':
                        result = success ?
                            '보안 정책을 우회했습니다. 정책 적용 범위나 우선순위에 문제가 있습니다.' :
                            '보안 정책이 효과적으로 적용됩니다. 정책 위반 시도가 차단되었습니다.';
                        break;
                    case 'sidecar_escape':
                        result = success ?
                            '사이드카 컨테이너 탈출에 성공했습니다. 컨테이너 격리에 문제가 있습니다.' :
                            '사이드카 격리가 유지됩니다. 탈출 시도가 차단되었습니다.';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} Service Mesh 보안 테스트 결과:</strong><br>
                        ${result}<br><br>
                        <strong>Service Mesh 보안 강화 방안:</strong><br>
                        • 강력한 mTLS 설정 (최소 TLS 1.3)<br>
                        • 세밀한 네트워크 정책 적용<br>
                        • 정기적인 인증서 순환<br>
                        • 트래픽 모니터링 및 이상 탐지<br>
                        • Envoy 프록시 보안 업데이트
                    </div>
                `;
            }, 3500);
        }
        
        function testCloudSecurity() {
            const provider = document.getElementById('cloudProvider').value;
            const service = document.getElementById('cloudService').value;
            const resultsDiv = document.getElementById('cloudResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>☁️ 클라우드 보안 검사 실행 중...</strong><br>
                    제공업체: ${provider}<br>
                    서비스: ${service}
                </div>
            `;
            
            setTimeout(() => {
                let issues = Math.floor(Math.random() * 5) + 1; // 1-5개 이슈
                let severity = issues > 3 ? 'danger' : issues > 1 ? 'warning' : 'success';
                let icon = issues > 3 ? '🚨' : issues > 1 ? '⚠️' : '✅';
                
                let providerSpecific = '';
                switch (provider) {
                    case 'aws':
                        providerSpecific = '• S3 버킷 공개 접근 검사<br>• IAM 권한 최소화<br>• CloudTrail 로깅 활성화';
                        break;
                    case 'gcp':
                        providerSpecific = '• Cloud Storage 권한 설정<br>• Cloud IAM 역할 검토<br>• Cloud Security Command Center 활용';
                        break;
                    case 'azure':
                        providerSpecific = '• Storage Account 보안<br>• Azure AD 권한 관리<br>• Azure Security Center 모니터링';
                        break;
                    case 'alibaba':
                        providerSpecific = '• OSS 버킷 보안 설정<br>• RAM 사용자 권한 관리<br>• ActionTrail 로깅 확인';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${severity}">
                        <strong>${icon} 클라우드 보안 검사 결과:</strong><br>
                        • 발견된 보안 이슈: ${issues}개<br>
                        • 심각도: ${issues > 3 ? '높음' : issues > 1 ? '중간' : '낮음'}<br>
                        • 검사 대상: ${service}<br><br>
                        
                        <strong>${provider.toUpperCase()} 특화 권장사항:</strong><br>
                        ${providerSpecific}<br><br>
                        
                        <strong>공통 클라우드 보안 권장사항:</strong><br>
                        • 최소 권한 원칙 적용<br>
                        • 네트워크 보안 그룹 강화<br>
                        • 암호화 키 관리 개선<br>
                        • 모든 리소스에 태그 적용<br>
                        • 정기적인 보안 감사 수행
                    </div>
                `;
            }, 4000);
        }
        
        function testServerless() {
            const platform = document.getElementById('serverlessType').value;
            const vuln = document.getElementById('serverlessVuln').value;
            const resultsDiv = document.getElementById('serverlessResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>⚡ 서버리스 보안 테스트 실행 중...</strong><br>
                    플랫폼: ${platform}<br>
                    취약점 유형: ${vuln}
                </div>
            `;
            
            setTimeout(() => {
                let exploitable = Math.random() > 0.6; // 40% 취약점 발견률
                let alertClass = exploitable ? 'warning' : 'success';
                let icon = exploitable ? '⚠️' : '🛡️';
                
                let analysis = '';
                switch (vuln) {
                    case 'function_injection':
                        analysis = exploitable ?
                            'Function Injection 취약점이 발견되었습니다. 사용자 입력이 실행 컨텍스트에 직접 반영됩니다.' :
                            'Function 입력 검증이 적절합니다. 코드 주입 시도가 차단되었습니다.';
                        break;
                    case 'cold_start_abuse':
                        analysis = exploitable ?
                            'Cold Start를 악용한 DoS 공격이 가능합니다. 함수 초기화 로직에 문제가 있습니다.' :
                            'Cold Start 처리가 안전합니다. 초기화 과정에서 보안이 유지됩니다.';
                        break;
                    case 'event_injection':
                        analysis = exploitable ?
                            'Event 데이터 조작으로 함수 로직을 우회할 수 있습니다. 이벤트 검증이 부족합니다.' :
                            'Event 데이터 검증이 적절합니다. 조작된 이벤트가 차단되었습니다.';
                        break;
                    case 'resource_exhaustion':
                        analysis = exploitable ?
                            '리소스 고갈 공격이 가능합니다. 함수 리소스 제한이 부적절합니다.' :
                            '리소스 제한이 적절히 설정되어 있습니다. 과도한 사용이 방지됩니다.';
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} 서버리스 보안 테스트 결과:</strong><br>
                        ${analysis}<br><br>
                        <strong>서버리스 보안 모범 사례:</strong><br>
                        • 최소 권한으로 IAM 역할 설정<br>
                        • 환경 변수로 비밀 정보 전달 금지<br>
                        • 함수 실행 시간 제한 설정<br>
                        • 입력 데이터 철저한 검증<br>
                        • 로깅 및 모니터링 활성화<br><br>
                        
                        <strong>플랫폼별 추가 권장사항:</strong><br>
                        • VPC 내부에서 함수 실행<br>
                        • 함수 레이어 보안 검증<br>
                        • Cold Start 최적화<br>
                        • 함수 버전 관리 및 롤백
                    </div>
                `;
            }, 3000);
        }
        
        function testIaC() {
            const tool = document.getElementById('iacTool').value;
            const vuln = document.getElementById('iacVuln').value;
            const resultsDiv = document.getElementById('iacResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>📋 IaC 보안 검사 실행 중...</strong><br>
                    도구: ${tool}<br>
                    검사 항목: ${vuln}
                </div>
            `;
            
            setTimeout(() => {
                let violations = Math.floor(Math.random() * 8) + 1; // 1-8개 위반
                let severity = violations > 5 ? 'danger' : violations > 2 ? 'warning' : 'success';
                let icon = violations > 5 ? '🚨' : violations > 2 ? '⚠️' : '✅';
                
                let specific_issues = [];
                switch (vuln) {
                    case 'hardcoded_secrets':
                        specific_issues = ['API 키가 코드에 하드코딩됨', '데이터베이스 패스워드 평문 저장', '프라이빗 키 노출'];
                        break;
                    case 'overprivileged_roles':
                        specific_issues = ['관리자 권한 과도 부여', '와일드카드 권한 사용', '불필요한 서비스 권한'];
                        break;
                    case 'public_resources':
                        specific_issues = ['S3 버킷 공개 설정', '데이터베이스 인터넷 노출', 'Load Balancer 무제한 접근'];
                        break;
                    case 'unencrypted_storage':
                        specific_issues = ['EBS 볼륨 암호화 미설정', 'RDS 백업 암호화 비활성화', '로그 파일 평문 저장'];
                        break;
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${severity}">
                        <strong>${icon} IaC 보안 검사 결과:</strong><br>
                        • 보안 위반 사항: ${violations}개<br>
                        • 심각도: ${violations > 5 ? '높음' : violations > 2 ? '중간' : '낮음'}<br><br>
                        
                        <strong>발견된 주요 문제:</strong><br>
                        ${specific_issues.slice(0, Math.min(violations, specific_issues.length)).map(issue => `• ${issue}`).join('<br>')}<br><br>
                        
                        <strong>IaC 보안 강화 권장사항:</strong><br>
                        • Pre-commit hooks으로 보안 스캔<br>
                        • 템플릿 매개변수화로 하드코딩 방지<br>
                        • 보안 정책을 코드로 관리<br>
                        • 정기적인 인프라 보안 감사<br>
                        • CI/CD 파이프라인에 보안 게이트 통합<br><br>
                        
                        <strong>${tool} 특화 보안 도구:</strong><br>
                        • Checkov (정적 분석)<br>
                        • Terrascan (Terraform 전용)<br>
                        • CloudSploit (클라우드 설정 검사)<br>
                        • Bridgecrew (통합 플랫폼)
                    </div>
                `;
            }, 4500);
        }
        
        function testSupplyChain() {
            const stage = document.getElementById('supplyChainStage').value;
            const attack = document.getElementById('supplyChainAttack').value;
            const resultsDiv = document.getElementById('supplyChainResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <strong>🔗 공급망 보안 테스트 실행 중...</strong><br>
                    공급망 단계: ${stage}<br>
                    공격 유형: ${attack}
                </div>
            `;
            
            setTimeout(() => {
                let risk_score = Math.floor(Math.random() * 100) + 1; // 1-100 위험 점수
                let alertClass = risk_score > 70 ? 'danger' : risk_score > 40 ? 'warning' : 'success';
                let icon = risk_score > 70 ? '🚨' : risk_score > 40 ? '⚠️' : '🛡️';
                
                let attack_scenario = '';
                switch (attack) {
                    case 'malicious_dependency':
                        attack_scenario = '악성 의존성 패키지가 발견되었습니다. 타이포스쿼팅 공격이나 의존성 혼동 공격의 위험이 있습니다.';
                        break;
                    case 'build_system_compromise':
                        attack_scenario = '빌드 시스템 침해 위험이 탐지되었습니다. CI/CD 파이프라인의 보안이 필요합니다.';
                        break;
                    case 'registry_poisoning':
                        attack_scenario = '컨테이너 레지스트리 오염 위험이 있습니다. 이미지 서명 검증이 필요합니다.';
                        break;
                    case 'deployment_manipulation':
                        attack_scenario = '배포 과정에서 조작 가능성이 발견되었습니다. 배포 파이프라인 보안 강화가 필요합니다.';
                        break;
                }
                
                let mitigation_strategies = [
                    'Software Bill of Materials (SBOM) 생성',
                    '의존성 보안 스캔 자동화',
                    '이미지 서명 및 검증 (Cosign)',
                    'Admission Controller로 정책 적용',
                    'Supply Chain Security 도구 (Tekton Chains)',
                    '정기적인 보안 감사 및 업데이트'
                ];
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-${alertClass}">
                        <strong>${icon} 공급망 보안 테스트 결과:</strong><br>
                        • 위험 점수: ${risk_score}/100<br>
                        • 위험 수준: ${risk_score > 70 ? '높음' : risk_score > 40 ? '중간' : '낮음'}<br><br>
                        
                        <strong>공격 시나리오 분석:</strong><br>
                        ${attack_scenario}<br><br>
                        
                        <strong>공급망 보안 강화 전략:</strong><br>
                        ${mitigation_strategies.map(strategy => `• ${strategy}`).join('<br>')}<br><br>
                        
                        <strong>SLSA Framework 준수 권장사항:</strong><br>
                        • Level 1: 빌드 과정 문서화<br>
                        • Level 2: 호스팅된 빌드 서비스 사용<br>
                        • Level 3: 소스/빌드 플랫폼 강화<br>
                        • Level 4: 재현 가능한 빌드 구현
                    </div>
                `;
            }, 5000);
        }
    </script>

    <?php include 'templates/footer.php'; ?>
</body>
</html>