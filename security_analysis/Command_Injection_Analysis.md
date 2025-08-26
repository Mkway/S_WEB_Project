# Command Injection 분석 보고서

## 1. Command Injection 이란?

**웹 서버의 운영체제(OS)에 임의의 명령어를 실행시키다**

- **정의:** 공격자가 취약한 웹 애플리케이션을 통해, 웹 서버의 운영체제(OS)에 직접 명령어를 실행시키는 공격입니다.
- **원리:** 웹 애플리케이션이 사용자로부터 입력받은 값을 검증 없이 시스템 명령어의 일부로 사용할 때 발생합니다.
- **영향:**
    - **시스템 장악:** 공격자가 웹 서버의 제어권을 완전히 탈취할 수 있습니다.
    - **데이터 유출 및 파괴:** 서버 내의 모든 파일을 읽거나, 수정하고, 삭제할 수 있습니다.
    - **내부망 침투:** 웹 서버를 거점으로 삼아 내부 네트워크의 다른 시스템을 공격할 수 있습니다.

---

## 2. 취약한 코드 분석 (예시)

**문제의 핵심: 사용자 입력값을 그대로 시스템 명령어에 포함**

```php
// 사용자가 입력한 IP 주소
$ip_address = $_POST['ip_address'];

// 취약한 코드
// 애플리케이션은 사용자가 입력한 IP 주소에 ping을 보내려고 의도했습니다.
system("ping -c 1 " . $ip_address);
```

**핵심 문제점:** `system()`, `exec()`, `shell_exec()` 와 같은 함수에 사용자 입력값을 안전하게 처리하지 않고 그대로 전달하는 것이 문제입니다.

---

## 3. 공격 시나리오: 시스템 정보 유출

**공격 목표:** 서버의 주요 파일 목록 확인하기

**공격 페이로드:** `127.0.0.1; ls -la`

**서버에서 실행되는 실제 명령어:**

```sh
ping -c 1 127.0.0.1; ls -la
```

- 셸(Shell)에서 `;` 문자는 앞선 명령어의 성공 여부와 관계없이 다음 명령어를 실행시킵니다.
- 따라서 서버는 `ping` 명령어를 실행한 후, 이어서 `ls -la` 명령어를 실행합니다.
- 공격자는 `ls -la`의 결과(현재 디렉터리의 파일 및 폴더 목록)를 응답으로 받아보게 되며, 이를 통해 추가 공격을 계획할 수 있습니다.

---

## 4. 해결책: `escapeshellarg()` 사용

**가장 안전한 방법: 사용자 입력을 단일 인자로 처리하기**

```php
// 사용자가 입력한 IP 주소
$ip_address = $_POST['ip_address'];

// escapeshellarg() 함수로 안전하게 이스케이프 처리
$safe_ip_address = escapeshellarg($ip_address);

// 안전하게 처리된 인자를 사용하여 명령어 실행
system("ping -c 1 " . $safe_ip_address);
```

**작동 원리:**
`escapeshellarg()` 함수는 사용자 입력값 전체를 작은따옴표(`'`)로 감싸고, 내부의 모든 특수문자를 이스케이프 처리합니다.
- `127.0.0.1; ls -la` → `'127.0.0.1; ls -la'`
- 결과적으로 셸은 이 전체 문자열을 `ping` 명령어의 **단 하나의 인자**로 인식하게 되어, `ls -la`는 명령어로 실행되지 않습니다.

---

## 5. Command Injection 방어 전략

1.  **시스템 명령어 직접 호출 피하기 (가장 중요):** 가능하면 OS 명령어 대신, 해당 프로그래밍 언어가 제공하는 내장 라이브러리나 API를 사용합니다.
2.  **`escapeshellarg()` 또는 `escapeshellcmd()` 사용:** 부득이하게 시스템 명령어를 사용해야 한다면, 반드시 이 함수들을 사용하여 사용자 입력을 안전하게 처리합니다.
3.  **입력값 검증 (화이트리스트 방식):** 허용할 문자와 형식(예: IP 주소 형식)을 미리 정의하고, 이 목록에 없는 입력은 모두 차단합니다.
4.  **최소 권한 원칙:** 웹 서버 데몬(e.g., Apache, Nginx)을 최소한의 권한을 가진 사용자 계정으로 실행하여, 공격이 성공하더라도 피해를 최소화합니다.

---

## 6. 다양한 언어별 Command Injection 방어 방법

### JavaScript/Node.js
```javascript
// 위험한 방법 - 절대 사용 금지
// const { exec } = require('child_process');
// exec(`ping -c 1 ${userInput}`, callback); // 취약함

// 안전한 방법 1: spawn 사용 (인자 분리)
const { spawn } = require('child_process');

function safePing(ipAddress) {
    // 입력값 검증
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipRegex.test(ipAddress)) {
        throw new Error('Invalid IP address format');
    }
    
    // spawn으로 명령어와 인자를 분리하여 실행
    const ping = spawn('ping', ['-c', '1', ipAddress]);
    
    ping.stdout.on('data', (data) => {
        console.log(`Output: ${data}`);
    });
    
    ping.stderr.on('data', (data) => {
        console.error(`Error: ${data}`);
    });
}

// 안전한 방법 2: execFile 사용
const { execFile } = require('child_process');

function safeExecute(command, args) {
    // 허용된 명령어 화이트리스트
    const allowedCommands = ['ping', 'nslookup', 'dig'];
    
    if (!allowedCommands.includes(command)) {
        throw new Error('Command not allowed');
    }
    
    execFile(command, args, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error: ${error}`);
            return;
        }
        console.log(`Output: ${stdout}`);
    });
}

// 더 안전한 방법: 네이티브 라이브러리 사용
const ping = require('ping');

async function safePingLib(host) {
    try {
        const result = await ping.promise.probe(host);
        return result;
    } catch (error) {
        throw new Error('Ping failed');
    }
}
```

### Python
```python
# 위험한 방법 - 절대 사용 금지
# import os
# os.system(f"ping -c 1 {user_input}")  # 취약함

# 안전한 방법 1: subprocess 사용
import subprocess
import re

def safe_ping(ip_address):
    # 입력값 검증
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if not re.match(ip_pattern, ip_address):
        raise ValueError("Invalid IP address format")
    
    try:
        # 명령어와 인자를 리스트로 분리
        result = subprocess.run(
            ['ping', '-c', '1', ip_address],
            capture_output=True,
            text=True,
            timeout=10,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise Exception(f"Ping failed: {e}")
    except subprocess.TimeoutExpired:
        raise Exception("Ping timeout")

# 안전한 방법 2: shlex 사용하여 명령어 이스케이프
import shlex

def safe_command_execution(command, user_input):
    # 허용된 명령어 검증
    allowed_commands = ['ping', 'nslookup', 'dig']
    
    if command not in allowed_commands:
        raise ValueError("Command not allowed")
    
    # shlex.quote로 인자 안전하게 이스케이프
    safe_input = shlex.quote(user_input)
    
    # 여전히 subprocess 사용 권장
    subprocess.run([command, safe_input], check=True)

# 더 안전한 방법: 전용 라이브러리 사용
import socket

def safe_ping_alternative(hostname):
    try:
        # 네트워크 연결 테스트 (ping 대신)
        socket.create_connection((hostname, 80), timeout=5)
        return True
    except socket.error:
        return False
```

### Java
```java
// 위험한 방법 - 절대 사용 금지
// Runtime.getRuntime().exec("ping -c 1 " + userInput); // 취약함

// 안전한 방법 1: ProcessBuilder 사용
import java.io.IOException;
import java.util.regex.Pattern;

public class SafeCommandExecution {
    private static final Pattern IP_PATTERN = 
        Pattern.compile("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    
    public static String safePing(String ipAddress) throws IOException {
        // 입력값 검증
        if (!IP_PATTERN.matcher(ipAddress).matches()) {
            throw new IllegalArgumentException("Invalid IP address format");
        }
        
        // ProcessBuilder로 안전하게 실행
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", ipAddress);
        pb.redirectErrorStream(true);
        
        Process process = pb.start();
        
        // 결과 읽기
        StringBuilder result = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\n");
            }
        }
        
        return result.toString();
    }
    
    // 화이트리스트 기반 명령어 실행
    private static final Set<String> ALLOWED_COMMANDS = 
        Set.of("ping", "nslookup", "dig");
    
    public static void safeExecute(String command, String... args) throws IOException {
        if (!ALLOWED_COMMANDS.contains(command)) {
            throw new SecurityException("Command not allowed: " + command);
        }
        
        String[] cmdArray = new String[args.length + 1];
        cmdArray[0] = command;
        System.arraycopy(args, 0, cmdArray, 1, args.length);
        
        ProcessBuilder pb = new ProcessBuilder(cmdArray);
        Process process = pb.start();
    }
}

// 더 안전한 방법: 자바 네이티브 API 사용
import java.net.InetAddress;

public class NetworkUtils {
    public static boolean isReachable(String hostname, int timeout) {
        try {
            InetAddress address = InetAddress.getByName(hostname);
            return address.isReachable(timeout);
        } catch (Exception e) {
            return false;
        }
    }
}
```

### C#/.NET
```csharp
// 위험한 방법 - 절대 사용 금지
// Process.Start($"ping -n 1 {userInput}"); // 취약함

using System;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.ComponentModel;

public class SafeCommandExecution
{
    private static readonly Regex IpPattern = 
        new Regex(@"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$");
    
    public static string SafePing(string ipAddress)
    {
        // 입력값 검증
        if (!IpPattern.IsMatch(ipAddress))
        {
            throw new ArgumentException("Invalid IP address format");
        }
        
        // ProcessStartInfo로 안전하게 실행
        var startInfo = new ProcessStartInfo
        {
            FileName = "ping",
            Arguments = $"-n 1 {ipAddress}",
            UseShellExecute = false, // 중요: shell 사용 안함
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        
        using (var process = Process.Start(startInfo))
        {
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            
            process.WaitForExit();
            
            if (process.ExitCode != 0)
            {
                throw new Exception($"Command failed: {error}");
            }
            
            return output;
        }
    }
    
    // 더 안전한 방법: .NET 네이티브 API 사용
    public static bool PingHost(string hostname, int timeout = 5000)
    {
        using (var ping = new System.Net.NetworkInformation.Ping())
        {
            try
            {
                var reply = ping.Send(hostname, timeout);
                return reply.Status == System.Net.NetworkInformation.IPStatus.Success;
            }
            catch
            {
                return false;
            }
        }
    }
}
```

### Go
```go
// 위험한 방법 - 절대 사용 금지
// cmd := exec.Command("sh", "-c", "ping -c 1 " + userInput) // 취약함

package main

import (
    "fmt"
    "os/exec"
    "regexp"
    "time"
)

// 안전한 방법 1: 명령어와 인자 분리
func safePing(ipAddress string) (string, error) {
    // 입력값 검증
    ipRegex := regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
    if !ipRegex.MatchString(ipAddress) {
        return "", fmt.Errorf("invalid IP address format")
    }
    
    // 명령어와 인자를 분리하여 실행
    cmd := exec.Command("ping", "-c", "1", ipAddress)
    
    // 타임아웃 설정
    cmd.Timeout = 10 * time.Second
    
    output, err := cmd.CombinedOutput()
    if err != nil {
        return "", fmt.Errorf("ping failed: %v", err)
    }
    
    return string(output), nil
}

// 화이트리스트 기반 명령어 실행
var allowedCommands = map[string]bool{
    "ping": true,
    "nslookup": true,
    "dig": true,
}

func safeExecute(command string, args ...string) error {
    if !allowedCommands[command] {
        return fmt.Errorf("command not allowed: %s", command)
    }
    
    cmd := exec.Command(command, args...)
    return cmd.Run()
}

// 더 안전한 방법: Go 네이티브 라이브러리 사용
import (
    "net"
    "time"
)

func checkConnectivity(host string, port string) error {
    timeout := time.Second * 5
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
    if err != nil {
        return err
    }
    defer conn.Close()
    return nil
}
```

### Ruby
```ruby
# 위험한 방법 - 절대 사용 금지
# system("ping -c 1 #{user_input}") # 취약함

# 안전한 방법 1: spawn 사용
def safe_ping(ip_address)
  # 입력값 검증
  unless ip_address.match?(/\A(?:[0-9]{1,3}\.){3}[0-9]{1,3}\z/)
    raise ArgumentError, "Invalid IP address format"
  end
  
  # spawn으로 안전하게 실행
  pid = spawn('ping', '-c', '1', ip_address)
  Process.wait(pid)
  
  $?.success?
end

# 안전한 방법 2: Open3 사용
require 'open3'

def safe_execute_command(command, *args)
  # 허용된 명령어 검증
  allowed_commands = %w[ping nslookup dig]
  
  unless allowed_commands.include?(command)
    raise SecurityError, "Command not allowed: #{command}"
  end
  
  # Open3로 안전하게 실행
  stdout, stderr, status = Open3.capture3(command, *args)
  
  unless status.success?
    raise RuntimeError, "Command failed: #{stderr}"
  end
  
  stdout
end

# 더 안전한 방법: Ruby 네이티브 라이브러리 사용
require 'socket'

def check_host_reachable?(hostname, port = 80, timeout = 5)
  Socket.tcp(hostname, port, connect_timeout: timeout) { true }
rescue
  false
end
```

### 추가 방어 기법

#### 입력값 검증 및 화이트리스트
```python
# Python 예시: 종합적인 입력값 검증
import re
from typing import List, Optional

class InputValidator:
    # 허용된 문자 패턴들
    PATTERNS = {
        'ip_address': r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$',
        'hostname': r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$',
        'alphanumeric': r'^[a-zA-Z0-9]+$',
        'filename': r'^[a-zA-Z0-9._-]+$'
    }
    
    @staticmethod
    def validate_input(value: str, pattern_type: str, max_length: int = 255) -> bool:
        # 길이 검증
        if len(value) > max_length:
            return False
        
        # 패턴 검증
        pattern = InputValidator.PATTERNS.get(pattern_type)
        if not pattern:
            raise ValueError(f"Unknown pattern type: {pattern_type}")
        
        return bool(re.match(pattern, value))
    
    @staticmethod
    def sanitize_for_command(value: str, allowed_chars: str = 'a-zA-Z0-9.-') -> str:
        # 허용된 문자만 유지
        sanitized = re.sub(f'[^{allowed_chars}]', '', value)
        return sanitized[:255]  # 길이 제한
```

#### 컨테이너/샌드박스 환경에서 실행
```bash
# Docker 컨테이너에서 명령어 실행
docker run --rm --network none alpine:latest ping -c 1 192.168.1.1

# 제한된 권한으로 실행
sudo -u nobody timeout 10 ping -c 1 192.168.1.1
```
