const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs-extra');
const JavaDeserializationVulnerability = require('./java-deserialization');

const app = express();
const port = 3000;

// Multer configuration for file uploads
const uploadDir = process.env.NODE_ENV === 'development' ? './uploads/' : '/app/uploads/';
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
    <h3>📊 Prototype Pollution</h3>
    <ul>
        <li><code>POST /prototype_pollution</code> - Prototype pollution test</li>
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
    <h4>1. Generate Payload:</h4>
    <pre>
curl -X POST http://localhost:3000/java/generate_payload \\
  -H "Content-Type: application/json" \\
  -d '{"gadget": "CommonsBeanutils1", "command": "whoami"}'
    </pre>
    
    <h4>2. Test Vulnerable Deserialization:</h4>
    <pre>
# First generate a payload, then upload the .ser file
curl -X POST http://localhost:3000/java/vulnerable_deserialize \\
  -F "serialized_file=@payload.ser"
    </pre>
    
    <h4>3. Get Available Gadgets:</h4>
    <pre>
curl http://localhost:3000/java/gadgets
    </pre>
    `;
    
    res.send(html);
});

app.listen(port, () => {
    console.log(`🚀 Node.js Vulnerability Testing Suite listening at http://localhost:${port}`);
    console.log(`📊 Prototype Pollution endpoint: POST /prototype_pollution`);
    console.log(`☕ Java Deserialization endpoints: /java/*`);
});
