<?php
/**
 * MongoDB 연결 테스트 스크립트
 */

require_once 'database/MongoDBConnection.php';

echo "<h2>🧪 MongoDB 연결 테스트</h2>\n";

try {
    echo "<p>MongoDB 연결 시도 중...</p>\n";
    
    $mongo = new MongoDBConnection();
    
    if ($mongo->isConnected()) {
        echo "<p style='color: green;'>✅ MongoDB 연결 성공!</p>\n";
        
        // 컬렉션 목록 확인
        $database = $mongo->getDatabase();
        $collections = $database->listCollections();
        
        echo "<h3>📋 사용 가능한 컬렉션:</h3>\n";
        echo "<ul>\n";
        foreach ($collections as $collection) {
            $name = $collection->getName();
            $count = $database->selectCollection($name)->countDocuments();
            echo "<li><strong>{$name}</strong>: {$count}개 문서</li>\n";
        }
        echo "</ul>\n";
        
        // 간단한 쿼리 테스트
        echo "<h3>🔍 간단한 쿼리 테스트:</h3>\n";
        
        $users = $mongo->getCollection('users');
        $user = $users->findOne(['username' => 'admin']);
        
        if ($user) {
            echo "<p style='color: green;'>✅ 사용자 조회 성공:</p>\n";
            echo "<pre>" . json_encode($user->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "</pre>\n";
        } else {
            echo "<p style='color: orange;'>⚠️ 관리자 사용자를 찾을 수 없습니다.</p>\n";
        }
        
        // NoSQL Injection 테스트
        echo "<h3>🚨 NoSQL Injection 테스트:</h3>\n";
        
        // 1. 정상 로그인
        $normal_result = $mongo->safeLogin('admin', 'admin123');
        if ($normal_result) {
            echo "<p style='color: green;'>✅ 정상 로그인 성공</p>\n";
        }
        
        // 2. 취약한 로그인 (배열 인젝션)
        $inject_result = $mongo->vulnerableLogin(['$ne' => null], ['$ne' => null]);
        if ($inject_result) {
            echo "<p style='color: red;'>🔥 NoSQL Injection 공격 성공! (취약점 확인)</p>\n";
            echo "<pre>" . json_encode($inject_result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "</pre>\n";
        }
        
    } else {
        echo "<p style='color: red;'>❌ MongoDB 연결 실패</p>\n";
    }
    
} catch (Exception $e) {
    echo "<p style='color: red;'>❌ 오류 발생: " . htmlspecialchars($e->getMessage()) . "</p>\n";
}

echo "<hr>\n";
echo "<p><a href='webhacking/nosql_injection_test.php'>🔗 NoSQL Injection 테스트 페이지로 이동</a></p>\n";
?>