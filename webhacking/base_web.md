웹 이란

HTTP 프로토콜을 이용하여 정보를 공유하는 서비스

정보 제공자는 웹 서버
정보를 공유 받는 자는 웹 클라이언트

HTTP 
웹상에서 서로 통신하기 위한 프로토콜, 규칙


초기 웹 서비스는 문서를 공유하는 형태, 현재는 웹 과 관련된 기술이 발전하여 금융, 쇼핑, 협업, 게임 ,영상

예를 등어 사용자가 제품을 구매하는 과정에서 사용자의 민감정보 공개
웹 보안의 중요

프론트 엔드  -  사용자에게 보여지는 부분, 웹의 자원 ( 웹 리소스, 폰트 ,이미지, 크기 )
백엔드  - 요청을 처리하는 부분

웹 리소스 - 웹에 있는 자산( assset ) - 404 not found ( 리소스 못 찾음 )

/index.html 

웹 리소스 - HTML, CSS, JS 

html - 구조
css - 시각화 ( 배경, 이미지 색상 )
JS - 동작 ( 사용자가 마우스 클릭)

클라이언트 사이드, 서버 사이드

모질라 - 자바스크립트 문서

- 웹 리소스 
	- URI ( 자원 지정)
	- URI, URL 
		- URL - URI의 하위 집합
		- 스키마 
			- HTTP, HTTPS
		- 유저
			- 이름과 비밀번호
		- 호스트
			- 도메인 이름, IP 주소
		- 포트 
			- 서비스 포트, 생략시 80(http), 443(https)
		- 패스
			- 리소스 경로
		- 파라미터
			- URL 파라미터
		- 프레그먼트 
			- # 해시 태그
		
HTTP 란 서버와 클라이언트의 데이터 교환의 

웹 서버는 HTTP 서비스 포트에 대기
Request, Response
헤더, 바디

HTTP 헤더의 각줄은 CRLF로 구분
CRLF(\\r\n)
헤더, 바디


TLS 프로토콜

DNS 
인터넷주소 -> IP 주소로 변환
접근 용이
www.domdomi.world( 도메인 - domdomi.world)

DNS 시스템
- 다층 구조
	- ![[Pasted image 20250713211511.png]]
	- A Record
		- ARecord 는 도메인에 각각 개별 IP가 매핑 된 것
	- CNAME 
		- CNAME 하나에 도메인에 다른 이름을 부여하는 방식으로 별칭이라는 표현
		- blog.domdomi.world -> domdomi.tistory.com


클라이언트 vs 서버

![[Pasted image 20250713211741.png]]

![[Pasted image 20250713211912.png]]

- 웹서버 
	- nginx - 라우팅 
	- 웹 애플리케이션 서버
		- 톰캣, 장고, 자바, 루비온 레일즈

- GET Request
	- 가장 기본적인 요청
	- 요청할려는 정보 URL에 포함
	- 쿼리 파라미터
	- key는 값
	- 데이터의 크기제한
		- URL 길이 제한 (2000 ~ 3000 제한)
	- 장점
		- GET 요청 캐싱 
		- 브라우저 히스토리 저장 
		- 서버입장 안전 ( 서버의 상태를 변경 X )
		- 북마크가 가능 하다 ( 공유 )
	- 조회
- HTTP Response
	- 상태코드
		- 응답의 첫부분 
		- 200 ( 성공 )
		- 404 ( 리소스 찾을 수 없음 )
		- 요청의 결과 알려줌
	- 헤더
		- 응답에 대한 메타데이터 전달
		- Content-Type
	- 응답 본문 
		- 실제 데이터
		- 데이터의 종류에 따라 달라짐
		- HTML 요청시 HTML 
		- JSON 요청시 JSON

- POST Request
	- 클라이언트에서 서버로 데이터 전달 
	- 서버의 상태 변경, 업데이트
	- 요청 본문, json, form-data
	- 데이터 크기 제한 있음
	- 회원가입 뒤로가기 -> (변경될 수 있음)
	- 멱등성 ( X )
		- 같은 글 작성 
		- 서버의 상태가 여러번 변경


- 버그헌팅  GET Method
	-  민감한 정보 노출, 예상치 못한 동작
- 버그헌팅 POST Method 
	- 요청 본문 조작
	- 잘못된 데이터 조작 
- 버그헌팅 PUT Method


- 다양한 메서드, 입력값 

- 쿠키, 세션 
	- 로그인 절차 
		- 고유한 아이디, 비밀번호 요청
		- 확인후 Set-Cookie 헤더를 포함한 응답
		- Set-Cookie - > 세션아이디나 토큰과 같이 사용자를 식별할 수 있는 정보 포함
		- 브라우저는 이 Set-Cookie 헤더의 지시를 받고 저장합니다.
		- 이 쿠키는 해당 사이트에 요청을 보낼 때 마다 자동으로 포함됩니다.
		- 서버가 사용자를 식별할 수 있게함
		- HTTP Only 옵션 
			- 쿠키가 자바스크립트를 통해 로드되는 것을 방지
			- 자바스크립트 제한
			- HTTP, HTTPS를 통해서만 전송
		- 해당 옵션이 설정되어 있는지
- User-Agent 
	- HTTP 요청 헤더
		- 클라이언트 종류, 버전정보, 운영체제 정보
		- 서버는 이를 통해 사용자의 환경에 맞는 응답
		- 모바일브라우저, 데스크탑 브라우저 구분
		- UX 향상
		- 특정 브라우저나 운영체제에서만 정상적인 요청 처리
		- 다른 User-Agent 변경시 속일 수 있음
- 응답 코드
	- 200 (성공)
	- 300 
		- 요청 완료를 위해 추가 작업 조치 필요
	- 400
		- 요청을 처리할 수 없는 상태
			- 401 
				- 인증 필요
	- 500
		- 서버가 명백히 유효한 요청에 대한 충족을 실패한 상태