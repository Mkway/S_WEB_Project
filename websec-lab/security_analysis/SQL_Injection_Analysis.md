# SQL Injection (SQLi) 분석 보고서

## 1. SQL Injection 이란?

**웹 애플리케이션의 가장 치명적인 취약점 중 하나**

- **정의:** 공격자가 웹 애플리케이션의 데이터베이스 쿼리를 조작하여, 의도치 않은 명령을 실행하게 만드는 공격 기법입니다.
- **원리:** 사용자 입력값을 제대로 검증하거나 처리하지 않고, 동적 데이터베이스 쿼리를 생성할 때 발생합니다.
- **영향:**
    - **데이터 유출:** 개인정보, 금융 정보 등 민감한 데이터가 외부에 노출됩니다.
    - **데이터 파괴:** 데이터베이스의 내용이 임의로 수정되거나 삭제될 수 있습니다.
    - **서버 장악:** 데이터베이스 서버의 제어권을 탈취하여 시스템 전체를 장악할 수 있습니다.

---

## 2. 취약한 코드 분석 (`sql_injection.php`)

**문제의 핵심: 사용자 입력값의 직접적인 쿼리 결합**

```php
// 사용자가 입력한 값 (페이로드)
$payload = $_POST['payload'];

// 취약한 쿼리 생성 (시뮬레이션된 코드)
$vulnerable_query = "SELECT id, username FROM users WHERE id = '$payload'";

// $payload 변수에 악의적인 SQL 구문이 포함되면 쿼리 전체가 조작됩니다.
```

**핵심 문제점:** 사용자 입력값을 신뢰하고, 아무런 필터링 없이 그대로 데이터베이스 쿼리문에 합쳐버리는 것이 문제입니다.

---

## 3. 공격 시나리오: 인증 우회

**공격 목표:** 비밀번호 없이 `admin` 계정으로 로그인하기

**공격 페이로드:** `admin'--`

**서버에서 실행되는 실제 쿼리:**

```sql
SELECT id, username FROM users WHERE id = 'admin'--'
```

- `--`는 SQL에서 주석을 의미합니다.
- 따라서 `'` 뒷부분은 모두 주석 처리되어, `id`가 `'admin'`인 사용자를 찾는 쿼리가 실행됩니다.
- 만약 `admin` 계정이 존재한다면, 비밀번호 검증 로직을 우회하고 로그인이 성공할 수 있습니다.

---

## 4. 해결책: 준비된 문 (Prepared Statements)

**가장 안전하고 효과적인 방어 방법**

```php
// 사용자가 입력한 값
$payload = $_POST['payload'];

// 안전한 쿼리 (준비된 문 사용)
$safe_query = "SELECT id, username FROM users WHERE id = ?";

// 1. 쿼리 템플릿을 먼저 데이터베이스에 보내 컴파일 요청
$stmt = $pdo->prepare($safe_query);

// 2. 사용자 입력값은 파라미터로 전달
$stmt->execute([$payload]);
```

**작동 원리:**
- 데이터베이스는 SQL 쿼리의 구조(`SELECT...WHERE id = ?`)를 먼저 파악하고,
- 이후에 전달되는 사용자 입력값(`$payload`)은 **데이터**로만 취급합니다.
- 결과적으로, 입력값에 포함된 악의적인 SQL 구문이 단순한 문자열로 처리되어 공격이 무력화됩니다.

---

## 5. SQL Injection 방어 전략

1.  **준비된 문 (Prepared Statements) 사용 (필수):** SQL 쿼리와 사용자 입력을 분리하여 근본적으로 공격을 차단합니다.
2.  **입력값 검증 (Validation):** 허용된 값의 형태, 타입, 길이인지 서버 측에서 항상 검증합니다.
3.  **저장 프로시저 (Stored Procedures):** 데이터베이스에 미리 정의된 프로시저를 사용하여 직접적인 쿼리 생성을 최소화합니다.
4.  **최소 권한 원칙 (Least Privilege):** 웹 애플리케이션이 사용하는 데이터베이스 계정에 꼭 필요한 권한만 부여합니다.
5.  **웹 방화벽 (WAF) 사용:** 알려진 SQL Injection 공격 패턴을 탐지하고 차단하는 보안 솔루션을 도입합니다.

---

## 6. 다양한 언어별 SQL Injection 방어 방법

### JavaScript/Node.js
```javascript
// MySQL2 라이브러리 사용 (prepared statements)
const mysql = require('mysql2');
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'user',
    password: 'password',
    database: 'test'
});

// 안전한 쿼리 실행
const userId = req.body.userId;
connection.execute(
    'SELECT * FROM users WHERE id = ?',
    [userId],
    (error, results) => {
        // 결과 처리
    }
);

// Sequelize ORM 사용
const { User } = require('./models');
const user = await User.findOne({
    where: { id: userId } // 자동으로 parameterized query 생성
});

// MongoDB (Mongoose) 사용
const User = require('./models/User');
const user = await User.findById(userId); // 자동으로 안전한 쿼리 생성
```

### Python/Django/SQLAlchemy
```python
# Django ORM (자동으로 prepared statements 사용)
from django.contrib.auth.models import User
user = User.objects.get(id=user_id)  # 안전함

# Django에서 raw SQL 사용시
from django.db import connection
cursor = connection.cursor()
cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])

# SQLAlchemy 사용
from sqlalchemy import text
result = session.execute(
    text("SELECT * FROM users WHERE id = :user_id"), 
    {"user_id": user_id}
)

# psycopg2 (PostgreSQL) 사용
import psycopg2
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# SQLite3 사용
import sqlite3
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### Java/Spring/JPA
```java
// JPA Repository 사용 (자동으로 prepared statements)
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.id = :userId")
    User findByUserId(@Param("userId") Long userId);
}

// JDBC Template 사용
@Autowired
private JdbcTemplate jdbcTemplate;

public User getUserById(Long userId) {
    String sql = "SELECT * FROM users WHERE id = ?";
    return jdbcTemplate.queryForObject(sql, new Object[]{userId}, new UserMapper());
}

// MyBatis 사용
@Select("SELECT * FROM users WHERE id = #{userId}")
User findUserById(@Param("userId") Long userId);

// Hibernate 사용
Query query = session.createQuery("FROM User u WHERE u.id = :userId");
query.setParameter("userId", userId);
User user = (User) query.getSingleResult();
```

### C#/.NET/Entity Framework
```csharp
// Entity Framework Core 사용
using (var context = new AppDbContext())
{
    var user = context.Users.FirstOrDefault(u => u.Id == userId); // 안전함
}

// ADO.NET with SqlCommand (parameterized queries)
using (var connection = new SqlConnection(connectionString))
{
    var command = new SqlCommand("SELECT * FROM Users WHERE Id = @userId", connection);
    command.Parameters.AddWithValue("@userId", userId);
    connection.Open();
    var reader = command.ExecuteReader();
}

// Dapper 사용
using (var connection = new SqlConnection(connectionString))
{
    var user = connection.QueryFirstOrDefault<User>(
        "SELECT * FROM Users WHERE Id = @userId", 
        new { userId = userId }
    );
}
```

### Go
```go
// database/sql 패키지 사용
import (
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
)

// Prepared statements 사용
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    log.Fatal(err)
}
defer stmt.Close()

rows, err := stmt.Query(userID)

// GORM 사용
import "gorm.io/gorm"

type User struct {
    ID   uint   `gorm:"primarykey"`
    Name string
}

var user User
db.First(&user, userID) // 자동으로 prepared statement 사용

// 동적 쿼리 안전하게 처리
db.Where("name = ?", name).First(&user)
```

### Ruby/Rails/ActiveRecord
```ruby
# ActiveRecord 사용 (자동으로 prepared statements)
user = User.find(user_id)  # 안전함
users = User.where(name: user_name)  # 안전함

# Raw SQL 사용시
users = User.find_by_sql(["SELECT * FROM users WHERE id = ?", user_id])

# PostgreSQL 어댑터 사용
result = ActiveRecord::Base.connection.exec_query(
  "SELECT * FROM users WHERE id = $1", 
  "User Query", 
  [user_id]
)

# Sequel gem 사용
DB[:users].where(id: user_id).first
```

### Rust
```rust
// sqlx 사용
use sqlx::postgres::PgPool;

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    let pool = PgPool::connect("postgres://...").await?;
    
    let user = sqlx::query!("SELECT * FROM users WHERE id = $1", user_id)
        .fetch_one(&pool)
        .await?;
    
    Ok(())
}

// diesel 사용
use diesel::prelude::*;

let user = users::table
    .filter(users::id.eq(user_id))
    .first::<User>(&connection)
    .expect("Error loading user");
```

### 추가 방어 기법

#### 입력값 검증 예시
```python
# Python에서 입력값 타입 검증
def get_user_by_id(user_id):
    # 정수형 검증
    try:
        user_id = int(user_id)
    except ValueError:
        raise ValueError("Invalid user ID")
    
    # 범위 검증
    if user_id < 1 or user_id > 999999:
        raise ValueError("User ID out of range")
    
    return User.objects.get(id=user_id)
```

#### 데이터베이스 권한 최소화
```sql
-- 애플리케이션 전용 사용자 생성
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'strong_password';

-- 필요한 최소 권한만 부여
GRANT SELECT, INSERT, UPDATE ON myapp.users TO 'webapp'@'localhost';
GRANT SELECT, INSERT, UPDATE ON myapp.posts TO 'webapp'@'localhost';

-- DROP, CREATE 등 DDL 권한 부여 안함
-- GRANT ALL PRIVILEGES 사용 금지
```
