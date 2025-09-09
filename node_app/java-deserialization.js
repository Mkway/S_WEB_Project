const { exec, spawn } = require('child_process');
const fs = require('fs-extra');
const path = require('path');

/**
 * Java Deserialization Vulnerability Module
 * 
 * ysoserial을 이용한 Java 직렬화 취약점 테스트 모듈
 */

class JavaDeserializationVulnerability {
    constructor() {
        this.ysoserial = '/usr/local/bin/ysoserial.jar';
        this.payloadDir = '/app/java-payloads';
        this.supportedGadgets = [
            'CommonsBeanutils1',
            'CommonsCollections1',
            'CommonsCollections2',
            'CommonsCollections3',
            'CommonsCollections4',
            'CommonsCollections5',
            'CommonsCollections6',
            'Groovy1',
            'Spring1',
            'Spring2'
        ];
    }

    /**
     * ysoserial 페이로드 생성
     * 
     * @param {string} gadget - Gadget chain 이름
     * @param {string} command - 실행할 명령어
     * @returns {Promise<Object>}
     */
    async generatePayload(gadget, command) {
        return new Promise((resolve, reject) => {
            if (!this.supportedGadgets.includes(gadget)) {
                return reject(new Error(`지원하지 않는 gadget: ${gadget}`));
            }

            const payloadFile = path.join(this.payloadDir, `${gadget}_${Date.now()}.ser`);
            const ysoserial_cmd = `java -jar ${this.ysoserial} ${gadget} "${command}"`;

            exec(ysoserial_cmd, { encoding: 'buffer', maxBuffer: 1024 * 1024 }, async (error, stdout, stderr) => {
                if (error) {
                    console.error('ysoserial execution error:', error);
                    console.error('stderr:', stderr.toString());
                    return reject(error);
                }

                try {
                    // 바이너리 페이로드를 파일로 저장
                    await fs.writeFile(payloadFile, stdout);

                    const stats = await fs.stat(payloadFile);
                    
                    resolve({
                        success: true,
                        message: 'ysoserial 페이로드 생성 성공',
                        gadget: gadget,
                        command: command,
                        payloadFile: payloadFile,
                        payloadSize: stats.size,
                        payloadHex: stdout.toString('hex').substring(0, 100) + '...',
                        vulnerability: 'JAVA_DESERIALIZATION'
                    });
                } catch (fileError) {
                    reject(fileError);
                }
            });
        });
    }

    /**
     * 취약한 Java 직렬화 데이터 처리 시뮬레이션
     * 
     * @param {Buffer} serializedData - 직렬화된 데이터
     * @returns {Promise<Object>}
     */
    async vulnerableDeserialize(serializedData) {
        return new Promise(async (resolve, reject) => {
            try {
                // 임시 파일로 저장
                const tempFile = path.join(this.payloadDir, `temp_${Date.now()}.ser`);
                await fs.writeFile(tempFile, serializedData);

                // Java 직렬화 데이터 분석
                const analysis = await this.analyzeSerializedData(serializedData);

                // 실제로는 Java 애플리케이션에서 ObjectInputStream.readObject() 호출
                // 여기서는 시뮬레이션을 위한 안전한 분석만 수행
                
                const result = {
                    success: true,
                    message: '취약한 역직렬화 처리 완료',
                    dataSize: serializedData.length,
                    analysis: analysis,
                    tempFile: tempFile,
                    vulnerability: 'UNSAFE_DESERIALIZATION',
                    warning: '실제 환경에서는 RCE (Remote Code Execution) 발생 가능'
                };

                // Java 매직 바이트 확인
                if (serializedData.length >= 4) {
                    const magicBytes = serializedData.readUInt32BE(0);
                    if (magicBytes === 0xaced0005) {
                        result.javaSerialMagic = true;
                        result.riskLevel = 'CRITICAL';
                    }
                }

                resolve(result);

            } catch (error) {
                reject(error);
            }
        });
    }

    /**
     * 직렬화 데이터 분석
     * 
     * @param {Buffer} data - 직렬화된 데이터
     * @returns {Object}
     */
    async analyzeSerializedData(data) {
        const analysis = {
            format: 'Unknown',
            magicBytes: null,
            suspiciousClasses: [],
            riskFactors: []
        };

        if (data.length < 4) {
            analysis.format = 'Too short';
            return analysis;
        }

        // Java 직렬화 매직 바이트 확인 (0xaced0005)
        const magicBytes = data.readUInt32BE(0);
        analysis.magicBytes = `0x${magicBytes.toString(16).padStart(8, '0')}`;

        if (magicBytes === 0xaced0005) {
            analysis.format = 'Java Serialization';
            analysis.riskFactors.push('Java native serialization detected');

            // 데이터에서 클래스명 추출 시도
            const dataString = data.toString('ascii');
            const suspiciousPatterns = [
                'java/util/HashMap',
                'java/util/HashSet',
                'java/util/ArrayList',
                'org/apache/commons',
                'org/springframework',
                'org/codehaus/groovy',
                'com/sun/rowset'
            ];

            suspiciousPatterns.forEach(pattern => {
                if (dataString.includes(pattern.replace(/\//g, '.'))) {
                    analysis.suspiciousClasses.push(pattern);
                    analysis.riskFactors.push(`Suspicious class found: ${pattern}`);
                }
            });

            // 가젯 체인 특성 검사
            if (analysis.suspiciousClasses.length > 0) {
                analysis.riskFactors.push('Potential gadget chain detected');
            }
        }

        return analysis;
    }

    /**
     * 안전한 직렬화 데이터 처리
     * 
     * @param {Buffer} serializedData - 직렬화된 데이터
     * @param {Array} allowedClasses - 허용된 클래스 목록
     * @returns {Promise<Object>}
     */
    async safeDeserialize(serializedData, allowedClasses = []) {
        try {
            const analysis = await this.analyzeSerializedData(serializedData);

            // 안전성 검사
            if (analysis.format === 'Java Serialization') {
                // 화이트리스트 검사
                const hasUnallowedClass = analysis.suspiciousClasses.some(cls => 
                    !allowedClasses.includes(cls)
                );

                if (hasUnallowedClass || analysis.suspiciousClasses.length === 0) {
                    return {
                        success: false,
                        message: '허용되지 않은 클래스가 포함되어 있거나 의심스러운 데이터입니다.',
                        analysis: analysis,
                        security: 'BLOCKED_BY_WHITELIST'
                    };
                }
            }

            // JSON 등 안전한 형식으로 변환 권장
            return {
                success: true,
                message: '안전한 역직렬화 처리 완료',
                analysis: analysis,
                security: 'WHITELIST_VALIDATED',
                recommendation: 'JSON 등 안전한 데이터 형식 사용 권장'
            };

        } catch (error) {
            return {
                success: false,
                message: '안전한 역직렬화 처리 실패: ' + error.message
            };
        }
    }

    /**
     * 사용 가능한 Gadget 체인 목록
     * 
     * @returns {Promise<Object>}
     */
    async getAvailableGadgets() {
        return new Promise((resolve, reject) => {
            exec(`java -jar ${this.ysoserial} 2>&1`, (error, stdout, stderr) => {
                const output = stdout + stderr;
                
                // ysoserial 출력에서 사용 가능한 페이로드 파싱
                const lines = output.split('\n');
                const gadgets = [];
                let inPayloadList = false;

                for (const line of lines) {
                    if (line.includes('Available payload types:')) {
                        inPayloadList = true;
                        continue;
                    }
                    
                    if (inPayloadList && line.trim()) {
                        const match = line.match(/^\s*(\w+)\s+(.+)$/);
                        if (match) {
                            gadgets.push({
                                name: match[1],
                                description: match[2].trim(),
                                supported: this.supportedGadgets.includes(match[1])
                            });
                        }
                    }
                }

                resolve({
                    success: true,
                    message: 'ysoserial gadget 목록 조회 완료',
                    totalGadgets: gadgets.length,
                    supportedGadgets: this.supportedGadgets.length,
                    gadgets: gadgets
                });
            });
        });
    }

    /**
     * 미리 생성된 테스트 페이로드 목록
     * 
     * @returns {Promise<Array>}
     */
    async getTestPayloads() {
        try {
            const files = await fs.readdir(this.payloadDir);
            const payloads = [];

            for (const file of files) {
                if (file.endsWith('.ser')) {
                    const filePath = path.join(this.payloadDir, file);
                    const stats = await fs.stat(filePath);
                    
                    payloads.push({
                        filename: file,
                        path: filePath,
                        size: stats.size,
                        created: stats.birthtime,
                        modified: stats.mtime
                    });
                }
            }

            return payloads.sort((a, b) => b.modified - a.modified);
        } catch (error) {
            console.error('Error reading payloads directory:', error);
            return [];
        }
    }

    /**
     * 페이로드 디렉토리 정리
     * 
     * @returns {Promise<Object>}
     */
    async cleanupPayloads() {
        try {
            await fs.emptyDir(this.payloadDir);
            return {
                success: true,
                message: '페이로드 파일 정리 완료'
            };
        } catch (error) {
            return {
                success: false,
                message: '페이로드 정리 실패: ' + error.message
            };
        }
    }
}

module.exports = JavaDeserializationVulnerability;