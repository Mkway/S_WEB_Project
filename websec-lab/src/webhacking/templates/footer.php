    </div> <!-- .container -->

    <script>
        // 공통으로 사용될 수 있는 스크립트
        function setPayload(payload) {
            const payloadTextarea = document.getElementById('payload');
            if (payloadTextarea) {
                payloadTextarea.value = payload;
            }
        }

        const mainForm = document.querySelector('form.test-form');
        if (mainForm) {
            mainForm.addEventListener('submit', function(e) {
                const confirmed = confirm(
                    '테스트를 실행하시겠습니까?\n' +
                    '이 테스트는 교육 목적으로만 사용하세요.'
                );
                
                if (!confirmed) {
                    e.preventDefault();
                }
            });
        }
    </script>
</body>
</html>