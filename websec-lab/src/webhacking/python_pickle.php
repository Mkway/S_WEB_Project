<?php
session_start();
include_once '../db_connection.php';

class PythonPickleTest {
    private $nodeServerUrl = 'http://localhost:3001';
    
    public function __construct() {
        $this->ensureNodeServer();
    }
    
    private function ensureNodeServer() {
        // Node.js 서버가 실행되고 있는지 확인
        $response = @file_get_contents($this->nodeServerUrl . '/health');
        if ($response === false) {
            throw new Exception("Node.js 서버가 실행되고 있지 않습니다. 'npm start'로 서버를 시작해주세요.");
        }
    }
    
    public function vulnerablePickleLoad($pickleData) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🔓 취약한 Pickle 역직렬화</h4>";
            $result .= "<p><strong>입력 데이터:</strong> " . htmlspecialchars(substr($pickleData, 0, 100)) . "...</p>";
            
            // Node.js 서버로 Pickle 데이터 전송
            $postData = json_encode([
                'action' => 'pickle_load',
                'data' => base64_encode($pickleData),
                'safe' => false
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/json',
                    'content' => $postData,
                    'timeout' => 10
                ]
            ]);
            
            $response = file_get_contents($this->nodeServerUrl . '/pickle', false, $context);
            
            if ($response === false) {
                throw new Exception("Node.js 서버 통신 실패");
            }
            
            $responseData = json_decode($response, true);
            
            if ($responseData['success']) {
                $result .= "<p><strong>⚠️ 역직렬화 성공:</strong></p>";
                $result .= "<pre>" . htmlspecialchars($responseData['result']) . "</pre>";
                
                if (isset($responseData['executed_command'])) {
                    $result .= "<p class='alert-danger'><strong>🚨 명령어 실행 감지!</strong></p>";
                    $result .= "<p><strong>실행된 명령:</strong> " . htmlspecialchars($responseData['executed_command']) . "</p>";
                    $result .= "<p><strong>실행 결과:</strong> " . htmlspecialchars($responseData['command_output']) . "</p>";
                }
                
                if (isset($responseData['warning'])) {
                    $result .= "<p class='alert-warning'><strong>경고:</strong> " . htmlspecialchars($responseData['warning']) . "</p>";
                }
                
            } else {
                $result .= "<p class='alert-danger'><strong>❌ 역직렬화 실패:</strong> " . htmlspecialchars($responseData['error']) . "</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function safePickleLoad($pickleData) {
        $result = '';
        
        try {
            $result .= "<div class='safe-output'>";
            $result .= "<h4>🔒 안전한 Pickle 역직렬화</h4>";
            $result .= "<p><strong>입력 데이터:</strong> " . htmlspecialchars(substr($pickleData, 0, 100)) . "...</p>";
            
            // 안전한 역직렬화 요청
            $postData = json_encode([
                'action' => 'pickle_load',
                'data' => base64_encode($pickleData),
                'safe' => true,
                'allowed_modules' => ['builtins', 'collections', 'datetime']
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/json',
                    'content' => $postData,
                    'timeout' => 10
                ]
            ]);
            
            $response = file_get_contents($this->nodeServerUrl . '/pickle', false, $context);
            
            if ($response === false) {
                throw new Exception("Node.js 서버 통신 실패");
            }
            
            $responseData = json_decode($response, true);
            
            if ($responseData['success']) {
                $result .= "<p><strong>✅ 안전한 역직렬화 성공:</strong></p>";
                $result .= "<pre>" . htmlspecialchars($responseData['result']) . "</pre>";
                $result .= "<p class='alert-success'><strong>🔒 보안 검증 통과!</strong> 위험한 모듈 사용이 차단되었습니다.</p>";
                
            } else {
                $result .= "<p class='alert-warning'><strong>🛡️ 보안 정책으로 차단됨:</strong> " . htmlspecialchars($responseData['error']) . "</p>";
                $result .= "<p>이는 정상적인 보안 동작입니다. 위험한 Pickle 데이터가 실행되지 않았습니다.</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function generateMaliciousPickle($command = 'whoami') {
        $result = '';
        
        try {
            $result .= "<div class='info-output'>";
            $result .= "<h4>⚙️ 악성 Pickle 생성</h4>";
            
            // Node.js 서버에서 악성 Pickle 생성
            $postData = json_encode([
                'action' => 'generate_pickle',
                'command' => $command
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/json',
                    'content' => $postData,
                    'timeout' => 10
                ]
            ]);
            
            $response = file_get_contents($this->nodeServerUrl . '/pickle', false, $context);
            
            if ($response === false) {
                throw new Exception("Node.js 서버 통신 실패");
            }
            
            $responseData = json_decode($response, true);
            
            if ($responseData['success']) {
                $pickleData = base64_decode($responseData['pickle_data']);
                
                $result .= "<p><strong>명령어:</strong> " . htmlspecialchars($command) . "</p>";
                $result .= "<p><strong>생성된 Pickle 크기:</strong> " . strlen($pickleData) . " bytes</p>";
                $result .= "<p><strong>Pickle 데이터 (Base64):</strong></p>";
                $result .= "<textarea readonly style='width: 100%; height: 100px; font-family: monospace;'>" . base64_encode($pickleData) . "</textarea>";
                $result .= "<p><strong>Pickle 바이트 시퀀스:</strong></p>";
                $result .= "<pre style='background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px; overflow-x: auto;'>";
                $result .= htmlspecialchars($this->formatPickleBytes($pickleData));
                $result .= "</pre>";
                
            } else {
                $result .= "<p class='alert-danger'><strong>❌ Pickle 생성 실패:</strong> " . htmlspecialchars($responseData['error']) . "</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    private function formatPickleBytes($data) {
        $formatted = '';
        $opcodes = [
            "\x80" => "PROTO",
            "\x71" => "BINUNICODE", 
            "\x7d" => "EMPTY_DICT",
            "\x94" => "MEMOIZE",
            "\x8c" => "SHORT_BINUNICODE",
            "\x93" => "STACK_GLOBAL",
            "\x4e" => "NONE",
            "\x85" => "TUPLE1",
            "\x52" => "REDUCE",
            "\x2e" => "STOP"
        ];
        
        for ($i = 0; $i < strlen($data); $i++) {
            $byte = $data[$i];
            $hex = sprintf('%02x', ord($byte));
            
            if (isset($opcodes[$byte])) {
                $formatted .= sprintf("\\x%s (%s)\n", $hex, $opcodes[$byte]);
            } else if (ord($byte) >= 32 && ord($byte) <= 126) {
                $formatted .= sprintf("\\x%s ('%s')\n", $hex, $byte);
            } else {
                $formatted .= sprintf("\\x%s\n", $hex);
            }
        }
        
        return $formatted;
    }
    
    public function analyzePickle($pickleData) {
        $result = '';
        
        try {
            $result .= "<div class='info-output'>";
            $result .= "<h4>🔍 Pickle 구조 분석</h4>";
            
            // Node.js 서버에서 Pickle 분석
            $postData = json_encode([
                'action' => 'analyze_pickle',
                'data' => base64_encode($pickleData)
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/json',
                    'content' => $postData,
                    'timeout' => 10
                ]
            ]);
            
            $response = file_get_contents($this->nodeServerUrl . '/pickle', false, $context);
            
            if ($response === false) {
                throw new Exception("Node.js 서버 통신 실패");
            }
            
            $responseData = json_decode($response, true);
            
            if ($responseData['success']) {
                $analysis = $responseData['analysis'];
                
                $result .= "<p><strong>Pickle 버전:</strong> " . htmlspecialchars($analysis['version']) . "</p>";
                $result .= "<p><strong>위험도:</strong> <span class='alert-" . 
                          ($analysis['risk_level'] === 'high' ? 'danger' : 
                           ($analysis['risk_level'] === 'medium' ? 'warning' : 'success')) . 
                          "'>" . strtoupper($analysis['risk_level']) . "</span></p>";
                
                if (!empty($analysis['dangerous_operations'])) {
                    $result .= "<p><strong>🚨 위험한 연산 감지:</strong></p>";
                    $result .= "<ul>";
                    foreach ($analysis['dangerous_operations'] as $op) {
                        $result .= "<li>" . htmlspecialchars($op) . "</li>";
                    }
                    $result .= "</ul>";
                }
                
                if (!empty($analysis['modules_imported'])) {
                    $result .= "<p><strong>📦 가져온 모듈:</strong></p>";
                    $result .= "<ul>";
                    foreach ($analysis['modules_imported'] as $module) {
                        $result .= "<li>" . htmlspecialchars($module) . "</li>";
                    }
                    $result .= "</ul>";
                }
                
                if (isset($analysis['opcodes'])) {
                    $result .= "<p><strong>🔧 Pickle 오피코드:</strong></p>";
                    $result .= "<pre style='background: #f8f9fa; padding: 10px; border-radius: 4px; max-height: 200px; overflow-y: auto;'>";
                    $result .= htmlspecialchars(implode("\n", $analysis['opcodes']));
                    $result .= "</pre>";
                }
                
            } else {
                $result .= "<p class='alert-danger'><strong>❌ 분석 실패:</strong> " . htmlspecialchars($responseData['error']) . "</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
}

$pickleTest = new PythonPickleTest();
$result = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'vulnerable_load':
            $pickleData = base64_decode($_POST['pickle_data'] ?? '');
            if (!empty($pickleData)) {
                $result = $pickleTest->vulnerablePickleLoad($pickleData);
            } else {
                $result = "<div class='error-output'>❌ Pickle 데이터를 입력해주세요.</div>";
            }
            break;
            
        case 'safe_load':
            $pickleData = base64_decode($_POST['pickle_data'] ?? '');
            if (!empty($pickleData)) {
                $result = $pickleTest->safePickleLoad($pickleData);
            } else {
                $result = "<div class='error-output'>❌ Pickle 데이터를 입력해주세요.</div>";
            }
            break;
            
        case 'generate_malicious':
            $command = $_POST['command'] ?? 'whoami';
            $result = $pickleTest->generateMaliciousPickle($command);
            break;
            
        case 'analyze':
            $pickleData = base64_decode($_POST['pickle_data'] ?? '');
            if (!empty($pickleData)) {
                $result = $pickleTest->analyzePickle($pickleData);
            } else {
                $result = "<div class='error-output'>❌ 분석할 Pickle 데이터를 입력해주세요.</div>";
            }
            break;
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Python Pickle Deserialization 취약점 테스트</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        
        .container {
            background-color: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
            font-size: 2.5em;
        }
        
        .description {
            background-color: #e8f4fd;
            padding: 20px;
            border-left: 5px solid #2196F3;
            margin-bottom: 30px;
            border-radius: 5px;
        }
        
        .test-section {
            margin-bottom: 40px;
            padding: 20px;
            border: 2px solid #ddd;
            border-radius: 10px;
            background-color: #fafafa;
        }
        
        .test-section h3 {
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #555;
        }
        
        input, select, button, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
        }
        
        textarea {
            height: 120px;
            font-family: monospace;
            resize: vertical;
        }
        
        button {
            background-color: #4CAF50;
            color: white;
            border: none;
            cursor: pointer;
            font-weight: bold;
            margin-top: 10px;
            transition: background-color 0.3s;
        }
        
        button:hover {
            background-color: #45a049;
        }
        
        .dangerous-btn {
            background-color: #f44336;
        }
        
        .dangerous-btn:hover {
            background-color: #da190b;
        }
        
        .safe-btn {
            background-color: #2196F3;
        }
        
        .safe-btn:hover {
            background-color: #1976D2;
        }
        
        .analyze-btn {
            background-color: #FF9800;
        }
        
        .analyze-btn:hover {
            background-color: #F57C00;
        }
        
        .vulnerable-output {
            background-color: #ffebee;
            border: 2px solid #f44336;
            color: #c62828;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .safe-output {
            background-color: #e8f5e8;
            border: 2px solid #4caf50;
            color: #2e7d32;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .info-output {
            background-color: #e3f2fd;
            border: 2px solid #2196f3;
            color: #1565c0;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .error-output {
            background-color: #fff3e0;
            border: 2px solid #ff9800;
            color: #ef6c00;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .alert-danger {
            color: #d32f2f !important;
            font-weight: bold;
        }
        
        .alert-success {
            color: #2e7d32 !important;
            font-weight: bold;
        }
        
        .alert-warning {
            color: #f57c00 !important;
            font-weight: bold;
        }
        
        .two-column {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .code-block {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 15px;
            font-family: monospace;
            font-size: 14px;
            overflow-x: auto;
        }
        
        @media (max-width: 768px) {
            .two-column {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🐍 Python Pickle Deserialization 취약점</h1>
        
        <div class="description">
            <h3>🎯 Python Pickle Deserialization이란?</h3>
            <p><strong>Python Pickle</strong>은 Python 객체를 바이트 스트림으로 직렬화하고 역직렬화하는 모듈입니다. 신뢰할 수 없는 데이터를 역직렬화할 때 임의 코드 실행이 가능한 심각한 취약점이 발생할 수 있습니다.</p>
            
            <h4>🔍 주요 공격 메커니즘:</h4>
            <ul>
                <li><strong>__reduce__ 메소드 악용</strong>: 임의 함수 호출 가능</li>
                <li><strong>스택 조작</strong>: Pickle 가상 머신의 스택을 조작하여 RCE</li>
                <li><strong>모듈 가져오기</strong>: 위험한 모듈(os, subprocess) 동적 로드</li>
                <li><strong>Gadget Chain</strong>: 여러 객체를 연결한 복잡한 공격</li>
            </ul>
            
            <p><strong>⚠️ 실제 테스트:</strong> 이 페이지는 Node.js 서버를 통해 실제 Python Pickle 취약점을 시연합니다. 격리된 환경에서 안전하게 테스트됩니다.</p>
        </div>

        <div class="two-column">
            <!-- 악성 Pickle 생성 -->
            <div class="test-section">
                <h3>⚙️ 악성 Pickle 생성</h3>
                <p>시스템 명령을 실행하는 악성 Pickle 데이터를 생성합니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="command">실행할 명령어:</label>
                        <input type="text" name="command" id="command" value="whoami" placeholder="예: whoami, id, ls -la">
                    </div>
                    
                    <input type="hidden" name="action" value="generate_malicious">
                    <button type="submit" class="dangerous-btn">🔧 악성 Pickle 생성</button>
                </form>
            </div>

            <!-- Pickle 분석 -->
            <div class="test-section">
                <h3>🔍 Pickle 구조 분석</h3>
                <p>Pickle 데이터의 구조와 위험 요소를 분석합니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="analyze_data">분석할 Pickle 데이터 (Base64):</label>
                        <textarea name="pickle_data" id="analyze_data" placeholder="Base64로 인코딩된 Pickle 데이터를 입력하세요..."></textarea>
                    </div>
                    
                    <input type="hidden" name="action" value="analyze">
                    <button type="submit" class="analyze-btn">🔍 구조 분석</button>
                </form>
            </div>
        </div>

        <!-- Pickle 역직렬화 테스트 -->
        <div class="test-section">
            <h3>🧪 Pickle 역직렬화 테스트</h3>
            <p>생성된 Pickle 데이터를 취약한 방식과 안전한 방식으로 역직렬화해보세요.</p>
            
            <form method="post">
                <div class="form-group">
                    <label for="pickle_input">Pickle 데이터 (Base64):</label>
                    <textarea name="pickle_data" id="pickle_input" placeholder="위에서 생성된 Base64 Pickle 데이터를 복사해서 붙여넣으세요..."></textarea>
                </div>
                
                <div style="display: flex; gap: 10px;">
                    <button type="submit" name="action" value="vulnerable_load" class="dangerous-btn" style="flex: 1;">
                        🔓 취약한 역직렬화 (pickle.loads)
                    </button>
                    <button type="submit" name="action" value="safe_load" class="safe-btn" style="flex: 1;">
                        🔒 안전한 역직렬화 (제한된 모듈)
                    </button>
                </div>
            </form>
        </div>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="test-section">
                <h3>📋 테스트 결과</h3>
                <?php echo $result; ?>
            </div>
        <?php endif; ?>

        <!-- 보안 권장사항 -->
        <div class="test-section">
            <h3>🛡️ 보안 권장사항</h3>
            <div class="safe-output">
                <h4>Python Pickle 보안 방법:</h4>
                
                <h5>1. 안전한 직렬화 형식 사용:</h5>
                <div class="code-block">
# JSON 사용 (권장)
import json
data = {'name': 'user', 'role': 'admin'}
serialized = json.dumps(data)
deserialized = json.loads(serialized)

# 또는 구조화된 데이터 형식
import msgpack
serialized = msgpack.packb(data)
deserialized = msgpack.unpackb(serialized)
                </div>
                
                <h5>2. 제한된 역직렬화 (pickle 사용 시):</h5>
                <div class="code-block">
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # 허용된 모듈과 클래스만 허용
        if module in ['builtins', 'collections', 'datetime']:
            return getattr(__import__(module), name)
        raise pickle.UnpicklingError(f"Forbidden class: {module}.{name}")

def safe_pickle_loads(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
                </div>
                
                <h5>3. 데이터 서명 및 검증:</h5>
                <div class="code-block">
import hmac
import hashlib
import pickle

SECRET_KEY = b'your-secret-key'

def sign_data(data):
    signature = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return data + b'::' + signature.encode()

def verify_and_load(signed_data):
    data, signature = signed_data.rsplit(b'::', 1)
    expected_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature.decode(), expected_sig):
        raise ValueError("Invalid signature")
    return pickle.loads(data)
                </div>
                
                <h5>4. 샌드박스 환경:</h5>
                <div class="code-block">
# Docker 컨테이너에서 역직렬화 수행
# 제한된 권한으로 프로세스 실행
# 네트워크 접근 차단
# 파일 시스템 읽기 전용
                </div>
                
                <p><strong>✅ 핵심 원칙:</strong> 신뢰할 수 없는 소스의 pickle 데이터는 절대 역직렬화하지 마세요. 가능하면 JSON이나 다른 안전한 형식을 사용하세요.</p>
            </div>
        </div>
    </div>

    <script>
        // 생성된 Pickle 데이터를 자동으로 테스트 폼에 복사
        function copyToTest(data) {
            document.getElementById('pickle_input').value = data;
            document.getElementById('analyze_data').value = data;
        }
        
        // 페이지 로드 시 텍스트 영역에서 생성된 데이터 확인
        document.addEventListener('DOMContentLoaded', function() {
            const textareas = document.querySelectorAll('textarea[readonly]');
            textareas.forEach(textarea => {
                if (textarea.value) {
                    textarea.addEventListener('click', function() {
                        this.select();
                        navigator.clipboard.writeText(this.value).then(() => {
                            alert('Pickle 데이터가 클립보드에 복사되었습니다!');
                        });
                    });
                }
            });
        });
    </script>
</body>
</html>