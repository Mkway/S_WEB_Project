# Contributing to S_WEB_Project

Thank you for considering contributing to S_WEB_Project! We appreciate your help in making this project better.

## How to Contribute

### 1. Set up Your Development Environment
This project uses a LEMP stack with Docker Compose. Follow these steps to get started:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/S_WEB_Project.git
    cd S_WEB_Project
    ```
2.  **Start Docker containers:**
    Navigate to the `my_lemp_project` directory and bring up the services:
    ```bash
    cd my_lemp_project
    docker-compose up -d
    ```
    This will start Nginx, PHP-FPM, and MariaDB.
3.  **Install PHP dependencies:**
    Access the PHP container and install Composer dependencies:
    ```bash
    docker-compose exec php composer install
    ```
4.  **Initialize the database:**
    Run the `install.php` script in your browser (e.g., `http://localhost/install.php`) to set up the database and initial data.

### 2. Coding Style

*   **PHP:** Follow PSR-12 coding style guidelines. Use 4 spaces for indentation.
*   **HTML/CSS/JavaScript:** Maintain consistency with the existing codebase. Use 4 spaces for indentation.
*   **Naming Conventions:** Use `snake_case` for PHP functions and variables, `PascalCase` for PHP classes.

### 3. Running Tests

This project uses PHPUnit for testing. To run the tests:

1.  Access the PHP container:
    ```bash
    docker-compose exec php bash
    ```
2.  Run PHPUnit from within the container:
    ```bash
    ./vendor/bin/phpunit
    ```

### 4. Submitting Changes

1.  **Create a new branch:**
    ```bash
    git checkout -b feature/your-feature-name
    ```
2.  **Make your changes:** Implement your feature or bug fix.
3.  **Run tests:** Ensure all existing tests pass and add new tests for your changes if applicable.
4.  **Commit your changes:** Write clear and concise commit messages.
    ```bash
    git commit -m "feat: Add new feature" # or "fix: Fix bug in X"
    ```
5.  **Push your branch:**
    ```bash
    git push origin feature/your-feature-name
    ```
6.  **Open a Pull Request:** Submit a pull request to the `main` branch of this repository.

## Code of Conduct

We are committed to providing a welcoming and inclusive environment for everyone. Please refer to our Code of Conduct (to be added) for more details.

Thank you for your contributions!