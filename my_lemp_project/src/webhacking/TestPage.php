<?php

class TestPage {
    private string $page_title;
    private string $description;
    private array $payloads;
    private array $defense_methods;
    private array $references;
    private string $test_form_ui = '';
    private $test_logic_callback;

    private array $result = [];
    private string $base_path = '../';

    public function __construct(string $page_title, string $description, array $payloads, array $defense_methods, array $references) {
        $this->page_title = $page_title;
        $this->description = $description;
        $this->payloads = $payloads;
        $this->defense_methods = $defense_methods;
        $this->references = $references;

        // 기본 초기화
        $this->initialize();
    }

    private function initialize() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        require_once __DIR__ . '/../db.php';
        require_once __DIR__ . '/../utils.php';

        if (!is_logged_in()) {
            header('Location: ../login.php');
            exit();
        }
    }

    public function set_test_form(string $html): void {
        $this->test_form_ui = $html;
    }

    public function set_test_logic(callable $callback): void {
        $this->test_logic_callback = $callback;
    }

    public function run(): void {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($this->test_logic_callback)) {
            $this->result = call_user_func($this->test_logic_callback, $_POST, $_FILES);
        }
        $this->render();
    }

    private function render(): void {
        // 변수들을 템플릿에서 사용할 수 있도록 추출
        $page_title = $this->page_title;
        $base_path = $this->base_path;
        
        // 헤더
        include __DIR__ . '/templates/header.php';

        // 브레드크럼
        include __DIR__ . '/templates/breadcrumb.php';

        // 정보 박스
        $title = '🗃️ ' . $this->page_title . ' 테스트';
        $description = $this->description;
        include __DIR__ . '/templates/info_box.php';

        // 페이로드 섹션
        foreach ($this->payloads as $key => $payload_data) {
            $section_title = $payload_data['title'];
            $section_description = $payload_data['description'];
            $payloads_array = $payload_data['payloads'];
            $onclick_handler = 'setPayload'; // 기본 핸들러
            include __DIR__ . '/templates/payload_section.php';
        }

        // 커스텀 테스트 폼
        if (!empty($this->test_form_ui)) {
            echo $this->test_form_ui;
        }

        // 결과 표시
        $result = $this->result['result'] ?? '';
        $error = $this->result['error'] ?? '';
        include __DIR__ . '/templates/result_box.php';

        // 방어 방법
        $defense_methods = $this->defense_methods;
        include __DIR__ . '/templates/defense_box.php';

        // 참고 자료
        $references = $this->references;
        include __DIR__ . '/templates/reference_box.php';

        // 푸터
        include __DIR__ . '/templates/footer.php';
    }
}