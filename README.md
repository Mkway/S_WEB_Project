# Comprehensive Web Security Testing Environment (S_WEB_Project)

[![PHP](https://img.shields.io/badge/PHP-8.2-777BB4?style=flat-square&logo=php)](https://php.net)
[![Nginx](https://img.shields.io/badge/Nginx-1.20-009639?style=flat-square&logo=nginx)](https://nginx.org)
[![MariaDB](https://img.shields.io/badge/MariaDB-10.6-003545?style=flat-square&logo=mariadb)](https://mariadb.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

**A comprehensive PHP-based web application for learning and practicing web security vulnerabilities and defense techniques.**

This project is an educational platform designed for web developers and security researchers to learn and test real-world web vulnerabilities in a safe environment. It provides both actual attack payloads based on PayloadsAllTheThings and defense mechanisms.

## 🎯 Project Objectives

- **Educational Purpose**: Learn the principles and defense methods of web security vulnerabilities.
- **Practical Application**: Provide real-world attack scenarios and defense code examples.
- **Safe Practice**: Conduct secure tests in an isolated Docker environment.
- **Comprehensive Coverage**: Includes major vulnerabilities based on the OWASP Top 10.

## ✨ Key Features

### 🏠 **Core Web Application**
- **User Authentication System**: Registration, login, session management.
- **Bulletin Board System**: CRUD functionality and file uploads.
- **Comment System**: Real-time comment creation and management.
- **Admin Panel**: User and content management.
- **Notification System**: Track user activities and provide notifications.

### 🔐 **Comprehensive Security Testing Environment (21 Completed)**
- **SQL Injection**: UNION, Boolean-based, Time-based, Error-based attacks.
- **XSS (Cross-Site Scripting)**: Reflected, Stored, DOM-based, Polyglot payloads.
- **Command Injection**: OS command execution and bypass techniques.
- **File Inclusion (LFI/RFI)**: Local/Remote file inclusion vulnerabilities.
- **Directory Traversal**: Directory traversal and system file access.
- **CSRF**: Cross-Site Request Forgery attacks and token bypass.
- **IDOR**: Insecure Direct Object References testing.
- **Authentication Bypass**: Various authentication bypass techniques.
- **JWT (JSON Web Token)**: Token manipulation, algorithm confusion, key leakage attacks.
- **XXE (XML External Entity)**: XML External Entity injection attacks.
- **SSRF (Server-Side Request Forgery)**: Server-side request forgery attacks.
- **SSTI (Server-Side Template Injection)**: Server-side template injection attacks.
- **HPP (HTTP Parameter Pollution)**: HTTP parameter pollution attacks.
- **NoSQL Injection**: Injection for NoSQL databases like MongoDB, CouchDB.
- **LDAP Injection**: LDAP directory service injection attacks.
- **XPath Injection**: Manipulating XML data through XPath expression injection.
- **Insecure Deserialization**: Code execution through insecure deserialization.
- **CORS Misconfiguration**: Cross-Origin Resource Sharing configuration errors.
- **GraphQL Injection**: GraphQL API query manipulation and information disclosure.
- **Business Logic Errors**: Exploiting flaws in business logic.
- **Open Redirect**: Phishing attacks through trusted domains.
- **Modern Bootstrap 5 UI**: Responsive design and intuitive interface.

### 📚 Web Vulnerability Analysis Documents
This project includes detailed analysis documents for the major web vulnerabilities implemented. Each document covers the principle of the vulnerability, attack scenarios, vulnerable code examples, and secure defense methods. Suitable for study presentations or learning materials.

- [**Go to Analysis Documents Directory**](security_analysis/)

### 🛡️ **Advanced Security Features**
- **Real-time Attack Detection**: Detects and warns about dangerous patterns in real-time.
- **Educational Feedback**: Detailed explanations and defense methods for each test.
- **Safe Simulation**: A testing environment that does not cause actual system damage.
- **Code Examples**: Provides a comparison of vulnerable and secure code.

## 🛠️ Tech Stack

### Backend
- **PHP 8.2**: Utilizing the latest PHP features.
- **MariaDB 10.6**: A stable database.
- **Nginx 1.28**: A high-performance web server.

### Frontend
- **Bootstrap 5.3**: A modern and responsive UI framework.
- **Bootstrap Icons**: An icon system.
- **Responsive Design**: Optimized for mobile/tablet/desktop.

### DevOps & Testing
- **Docker & Docker Compose**: A containerized development environment.
- **PHPUnit**: Comprehensive unit testing.
- **SSL/TLS**: Support for secure communication.

### Security Features
- **CSRF Protection**: Token-based request protection.
- **Session Security**: Secure session management.
- **Input Validation**: Comprehensive input validation.
- **XSS Protection**: Output encoding and CSP.

## 🚀 Getting Started

### 1. Quick Start (Using Docker - Recommended)

```bash
# Clone the project
git clone https://github.com/Mkway/S_WEB_Project.git
cd S_WEB_Project/my_lemp_project

# Run Docker containers
docker-compose up -d

# Access the application
# Main Application: http://localhost
# Security Testing Environment: http://localhost/webhacking
```

### 2. Initial Setup

1.  **Initialize Database**: Access `http://localhost/install.php`.
2.  **Create a Test User**: Register or use the default account.
3.  **Access Security Tests**: Log in and click the "Security Tests" menu.

### 3. Running Tests

```bash
# Run PHPUnit tests
docker-compose exec php ./vendor/bin/phpunit --testdox test/

# Run a specific security test
docker-compose exec php ./vendor/bin/phpunit test/SecurityTest.php
```

## 📂 Project Structure

```
S_WEB_Project/
├── security_analysis/              # Web vulnerability analysis documents
├── my_lemp_project/
│   ├── docker-compose.yml          # Docker service definitions
│   ├── nginx/                      # Nginx configuration and SSL
│   │   ├── default.conf
│   │   ├── ssl/
│   │   └── docker-entrypoint.sh
│   ├── src/                        # PHP Application
│   │   ├── webhacking/             # 🔥 Security Testing Environment
│   │   │   ├── index.php           # Main test page (Bootstrap 5)
│   │   │   ├── auth_bypass.php     # Authentication Bypass Test
│   │   │   ├── ...                 # Other vulnerability tests
│   │   ├── test/                   # PHPUnit Tests
│   │   ├── config.php              # Application configuration
│   │   ├── utils.php               # Security utilities
│   │   └── ...                     # Other PHP files
│   └── php.Dockerfile              # PHP Docker configuration
└── README.md
```

## 🧪 Security Testing Guide

### How to Access
1. Log into the main application.
2. Click the "Security Tests" menu.
3. Select the desired vulnerability test.
4. Click the provided payload buttons or enter your own.
5. Check the test results and defense methods.

### Key Test Scenarios

#### 🗃️ SQL Injection
```sql
-- UNION-based attack
' UNION SELECT null,username,password FROM users--

-- Boolean-based blind attack
' AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))>64--
```

#### 🚨 XSS (Cross-Site Scripting)
```html
<!-- Reflected XSS -->
<script>alert('XSS')</script>

<!-- DOM-based XSS -->
<img src="x" onerror="alert(1)">
```

#### 💻 Command Injection
```bash
# Basic command chaining
; ls -la

# Blind attack
; ping -c 4 127.0.0.1
```

#### 🔐 JWT (JSON Web Token)
```javascript
// None Algorithm Attack
{"typ":"JWT","alg":"none"}

// Algorithm Confusion (RS256 → HS256)
// Use the public key as the HMAC secret

// Weak Secret Attack
secret, 123456, password, key, jwt
```

### Safety Rules
⚠️ **Important**: All tests are for educational purposes only.
- Absolutely do not use in a real production environment.
- Test only in the isolated Docker environment.
- Do not conduct unauthorized tests on others' systems.

## 📊 Test Coverage

### Included Security Tests
- ✅ Covers major **OWASP Top 10** vulnerabilities.
- ✅ Real payloads based on **PayloadsAllTheThings**.
- ✅ **Real-time attack detection** system.
- ✅ **Defense code examples** and explanations.
- ✅ **Reference links** (OWASP, PortSwigger, etc.).

## 🤝 Contributing

This project is continuously evolving for educational and research purposes.

### How to Contribute
1.  **Issue Reports**: Suggest bugs or improvements.
2.  **Pull Requests**: Add new tests or features.
3.  **Documentation**: Improve usage or security guides.
4.  **Feedback**: Share opinions to enhance educational effectiveness.

## 🆕 Latest Updates (August 2025)

### Newly Added Features
- **JWT Vulnerability Tests**: JWT security tests based on PayloadsAllTheThings.
- **Bootstrap 5 UI Overhaul**: Modern and responsive interface.
- **Card-based Layout**: Intuitive test selection interface.
- **Real-time Attack Simulation**: Educational feedback and CVSS scoring.
- **Enhanced Security Logging**: Detailed attack pattern analysis.

## 📚 Learning Resources

### References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## ⚠️ Disclaimer

This project was created for **educational purposes only**. Unauthorized security testing on real production environments or others' systems may lead to legal issues. Users are responsible for complying with relevant laws and using this tool ethically.

**🎓 Happy Ethical Hacking & Secure Coding!**
