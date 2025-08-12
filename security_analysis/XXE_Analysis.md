# XXE (XML External Entity) Injection 분석 보고서

## 1. XXE 란?

**공격자를 위해 일하는 XML 파서**

- **XXE란?** XML External Entity Injection의 약자로, 애플리케이션이 XML 데이터를 처리하는 방식을 공격자가 악용하는 웹 보안 취약점입니다.
- **원리:** 많은 XML 파서는 외부 개체(External Entity) 참조를 지원합니다. 공격자는 이 기능을 악용하여 로컬 파일을 읽거나, 내부 네트워크에 요청을 보내거나, 서비스 거부(DoS) 공격을 유발하는 악의적인 XML 문서를 작성할 수 있습니다.
- **영향:**
    - **정보 유출:** 서버의 민감한 파일(예: `/etc/passwd`, 소스 코드)을 탈취합니다.
    - **서버 측 요청 위조 (SSRF):** 서버가 공격자가 원하는 곳으로 네트워크 요청을 보내게 하여, 내부 시스템을 스캔하거나 클라우드 메타데이터에 접근합니다.
    - **서비스 거부 (DoS):** 재귀적인 엔티티 확장을 통해 서버의 메모리나 CPU를 고갈시킵니다. (Billion Laughs Attack)

---

## 2. 취약한 코드 분석 (예시)

**문제의 핵심: 외부 개체를 해석하도록 설정된 XML 파서**

```php
// 사용자가 제출한 XML 데이터
$xml_data = $_POST['xml_data'];

// 취약한 코드
// LIBXML_NOENT 플래그는 엔티티를 치환하도록 지시하여 취약점을 유발합니다.
$dom = new DOMDocument();
$dom->loadXML($xml_data, LIBXML_NOENT);

// 애플리케이션은 이어서 XML 데이터를 처리합니다...
```

**핵심 문제점:** 오래된 XML 파서는 기본적으로 취약한 설정으로 동작하는 경우가 많습니다. 개발자가 명시적으로 안전하지 않은 기능을 비활성화해야 합니다.

---

## 3. 공격 시나리오: 로컬 파일 탈취

**공격 목표:** 서버의 `/etc/passwd` 파일 읽기

**공격용 악성 XML 페이로드:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
</stockCheck>
```

**공격 과정:**
1.  공격자는 `xxe`라는 이름의 XML 외부 개체를 정의하고, 그 값을 `file:///etc/passwd` 라는 시스템 파일 경로로 지정합니다.
2.  공격자는 `productId` 태그 내에서 `&xxe;` 형태로 개체를 참조합니다.
3.  취약한 XML 파서는 `&xxe;`를 만나는 순간, 이를 `/etc/passwd` 파일의 내용으로 치환합니다.
4.  애플리케이션이 처리 결과를 응답에 포함하면, `/etc/passwd` 파일의 내용이 공격자에게 노출됩니다.

---

## 4. 해결책: 외부 개체 처리 기능 비활성화

**가장 안전한 방법: 필요 없는 기능은 명시적으로 비활성화하기**

```php
// 사용자가 제출한 XML 데이터
$xml_data = $_POST['xml_data'];

// 안전한 코드
// 1. 외부 개체 로딩 기능을 비활성화합니다. (가장 중요)
libxml_disable_entity_loader(true);

// 2. DOMDocument 객체 생성
$dom = new DOMDocument();

// 3. LIBXML_NOENT 플래그 없이 XML을 파싱
$dom->loadXML($xml_data);

// 이제 애플리케이션은 안전하게 XML 데이터를 처리할 수 있습니다...
```

**작동 원리:** `libxml_disable_entity_loader(true)` 함수는 PHP가 사용하는 `libxml2` 라이브러리의 외부 개체 로딩 기능을 전역적으로 비활성화합니다. 이것이 PHP 환경에서 XXE 공격을 막는 가장 효과적이고 확실한 방법입니다.

---

## 5. XXE 공격 방어 전략

1.  **외부 개체 및 DTD 비활성화 (가장 중요):** 사용하는 XML 파서의 설정에서 외부 개체(External Entity)와 DTD(Document Type Definition) 처리 기능을 비활성화합니다.
2.  **단순한 데이터 포맷 사용:** 가능하다면 XML 대신, 구조가 단순하고 관련 위험이 적은 JSON 같은 데이터 포맷을 사용합니다.
3.  **입력값 검증:** 서버 측에서 허용된 XML 스키마를 정의하고, 모든 XML 입력이 이 스키마에 부합하는지 검증합니다.
4.  **XML 파서 패치 및 업데이트:** 사용하는 XML 파싱 라이브러리를 항상 최신 버전으로 유지하여 알려진 취약점을 패치합니다.
