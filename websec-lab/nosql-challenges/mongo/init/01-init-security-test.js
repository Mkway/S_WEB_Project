// MongoDB 초기화 스크립트 - 보안 테스트용 데이터베이스 및 컬렉션 설정

// 보안 테스트용 데이터베이스 선택
db = db.getSiblingDB('security_test');

// 1. 사용자 인증 컬렉션 (취약한 로그인 테스트용)
db.users.drop();
db.users.insertMany([
    {
        _id: ObjectId("507f1f77bcf86cd799439011"),
        username: "admin",
        password: "admin123", 
        role: "administrator",
        email: "admin@example.com",
        active: true,
        created: new Date("2024-01-01T00:00:00Z")
    },
    {
        _id: ObjectId("507f1f77bcf86cd799439012"),
        username: "user1",
        password: "user123",
        role: "user", 
        email: "user1@example.com",
        active: true,
        created: new Date("2024-01-15T00:00:00Z")
    },
    {
        _id: ObjectId("507f1f77bcf86cd799439013"),
        username: "guest",
        password: "guest123",
        role: "guest",
        email: "guest@example.com", 
        active: false,
        created: new Date("2024-02-01T00:00:00Z")
    },
    {
        _id: ObjectId("507f1f77bcf86cd799439014"),
        username: "test_user",
        password: "test_pass",
        role: "tester",
        email: "test@example.com",
        active: true,
        created: new Date("2024-02-15T00:00:00Z")
    }
]);

// 사용자 컬렉션 인덱스 생성
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true });

// 2. 제품 컬렉션 (검색 인젝션 테스트용)  
db.products.drop();
db.products.insertMany([
    {
        _id: ObjectId("607f1f77bcf86cd799439021"),
        name: "Laptop Computer",
        description: "High-performance laptop for professionals",
        price: 1299.99,
        category: "electronics",
        tags: ["computer", "laptop", "professional"],
        stock: 50,
        active: true,
        created: new Date("2024-01-10T00:00:00Z")
    },
    {
        _id: ObjectId("607f1f77bcf86cd799439022"), 
        name: "Smartphone",
        description: "Latest flagship smartphone with advanced features",
        price: 899.99,
        category: "electronics",
        tags: ["phone", "mobile", "smartphone"],
        stock: 100,
        active: true,
        created: new Date("2024-01-20T00:00:00Z")
    },
    {
        _id: ObjectId("607f1f77bcf86cd799439023"),
        name: "Programming Book",
        description: "Comprehensive guide to modern programming",
        price: 49.99,
        category: "books",
        tags: ["programming", "education", "development"],
        stock: 25,
        active: true,
        created: new Date("2024-02-05T00:00:00Z")
    },
    {
        _id: ObjectId("607f1f77bcf86cd799439024"),
        name: "Security Handbook", 
        description: "Essential cybersecurity practices and techniques",
        price: 79.99,
        category: "books",
        tags: ["security", "cybersecurity", "handbook"],
        stock: 15,
        active: false,
        created: new Date("2024-02-20T00:00:00Z")
    }
]);

// 제품 컬렉션 인덱스 생성
db.products.createIndex({ "name": "text", "description": "text" });
db.products.createIndex({ "category": 1 });
db.products.createIndex({ "price": 1 });

// 3. 게시물 컬렉션 (복합 쿼리 인젝션 테스트용)
db.posts.drop();
db.posts.insertMany([
    {
        _id: ObjectId("707f1f77bcf86cd799439031"),
        title: "Welcome to our platform",
        content: "This is the first post on our new platform!",
        author: "admin",
        status: "published",
        views: 150,
        likes: 25,
        comments: [
            {
                author: "user1",
                content: "Great platform!",
                date: new Date("2024-01-02T10:00:00Z")
            }
        ],
        created: new Date("2024-01-01T12:00:00Z")
    },
    {
        _id: ObjectId("707f1f77bcf86cd799439032"),
        title: "Security Best Practices",
        content: "Here are some important security guidelines...",
        author: "admin", 
        status: "published",
        views: 89,
        likes: 12,
        comments: [],
        created: new Date("2024-01-15T14:30:00Z")
    },
    {
        _id: ObjectId("707f1f77bcf86cd799439033"),
        title: "Draft Post",
        content: "This is a draft that shouldn't be visible",
        author: "user1",
        status: "draft", 
        views: 0,
        likes: 0,
        comments: [],
        created: new Date("2024-02-01T09:15:00Z")
    }
]);

// 게시물 컬렉션 인덱스 생성
db.posts.createIndex({ "title": "text", "content": "text" });
db.posts.createIndex({ "author": 1 });
db.posts.createIndex({ "status": 1 });
db.posts.createIndex({ "created": -1 });

// 4. 로그 컬렉션 (정보 수집 테스트용)
db.logs.drop();
db.logs.insertMany([
    {
        _id: ObjectId("807f1f77bcf86cd799439041"),
        timestamp: new Date("2024-01-01T12:00:00Z"),
        level: "INFO",
        message: "User login successful",
        user: "admin",
        ip: "192.168.1.100",
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    },
    {
        _id: ObjectId("807f1f77bcf86cd799439042"), 
        timestamp: new Date("2024-01-01T12:05:00Z"),
        level: "WARNING",
        message: "Failed login attempt",
        user: "unknown",
        ip: "10.0.0.50",
        userAgent: "curl/7.68.0"
    },
    {
        _id: ObjectId("807f1f77bcf86cd799439043"),
        timestamp: new Date("2024-01-01T12:10:00Z"),
        level: "ERROR", 
        message: "Database connection failed",
        user: "system",
        ip: "127.0.0.1",
        userAgent: "Internal"
    }
]);

// 로그 컬렉션 인덱스 생성
db.logs.createIndex({ "timestamp": -1 });
db.logs.createIndex({ "level": 1 });
db.logs.createIndex({ "user": 1 });

print("MongoDB 보안 테스트 데이터베이스 초기화 완료!");
print("컬렉션 수: " + db.getCollectionNames().length);
print("사용자 수: " + db.users.countDocuments());
print("제품 수: " + db.products.countDocuments());
print("게시물 수: " + db.posts.countDocuments());
print("로그 수: " + db.logs.countDocuments());