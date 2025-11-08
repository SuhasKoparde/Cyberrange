# Cyber Range - Comprehensive Project Documentation

## Table of Contents
1. [Introduction](#introduction)
2. [System Architecture](#system-architecture)
3. [Technical Stack](#technical-stack)
4. [Core Components](#core-components)
5. [Database Design](#database-design)
6. [Security Implementation](#security-implementation)
7. [API Documentation](#api-documentation)
8. [Frontend Structure](#frontend-structure)
9. [Virtual Machine Integration](#virtual-machine-integration)
10. [Deployment Guide](#deployment-guide)
11. [Development Workflow](#development-workflow)
12. [Testing Strategy](#testing-strategy)
13. [Troubleshooting](#troubleshooting)
14. [Future Enhancements](#future-enhancements)

## Introduction

### Project Overview
Cyber Range is an advanced cybersecurity training platform designed to provide hands-on experience in a controlled environment. It simulates real-world attack scenarios, allowing users to practice and enhance their cybersecurity skills.

### Key Objectives
- Provide a safe, isolated environment for cybersecurity training
- Offer a variety of challenges across different difficulty levels
- Track user progress and performance
- Support both individual and team-based training scenarios

## Project Structure

```
CyberRange/
├── app/                        # Main application package
│   ├── __init__.py            # Application factory and extensions
│   ├── models.py              # Database models (User, Challenge, etc.)
│   ├── routes/                # Route handlers
│   │   ├── __init__.py
│   │   ├── auth.py           # Authentication routes
│   │   ├── challenges.py     # Challenge-related routes
│   │   └── admin.py          # Admin panel routes
│   ├── static/                # Static files
│   │   ├── css/              # Stylesheets
│   │   ├── js/               # JavaScript files
│   │   └── img/              # Images and icons
│   └── templates/            # HTML templates
│       ├── base.html         # Base template
│       ├── auth/             # Authentication templates
│       ├── challenges/       # Challenge-related templates
│       └── admin/            # Admin panel templates
├── migrations/               # Database migration files
├── tests/                    # Test files
│   ├── unit/                # Unit tests
│   └── integration/         # Integration tests
├── vms/                      # Virtual machine configurations
│   ├── vulnerable-web/      # Web challenge VMs
│   └── linux-target/        # Linux target VMs
├── scripts/                  # Utility scripts
│   └── vm_manager.py        # VM management script
├── config.py                # Configuration settings
├── requirements.txt         # Python dependencies
├── run.py                   # Application entry point
└── README.md                # Project overview
```

### Key Directories Explained:

#### 1. `app/` - Core Application
- Contains all the main application logic
- Follows the standard Flask application structure
- Organized into models, routes, and templates

#### 2. `vms/` - Virtual Machines
- Contains configurations for different VM setups
- Each subdirectory represents a different VM environment
- Includes Vagrantfiles and provisioning scripts

#### 3. `scripts/` - Utility Scripts
- Helper scripts for common tasks
- VM management and automation
- Database utilities

#### 4. `tests/` - Testing
- Unit and integration tests
- Test fixtures and helpers
- End-to-end test scenarios

#### 5. Configuration Files
- `config.py`: Application configuration
- `requirements.txt`: Python dependencies
- `.env`: Environment variables (not version controlled)

This structure follows best practices for Flask applications, with clear separation of concerns and modular design.

## System Architecture

### High-Level Architecture
```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│    Frontend     │◄───►│    Backend      │◄───►│    Database     │
│  (HTML/CSS/JS)  │     |   (Flask/Python)│     |    (SQLite/    |
│                 │     │                 │     │    PostgreSQL)  │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  User Browser   │     │ Virtual Machine │     │  Authentication │
│                 │     │   Management    │     │      System     │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Technical Stack

### Backend
- **Framework**: Flask (Python 3.8+)
- **Database**: 
  - Development: SQLite
  - Production: PostgreSQL
- **Authentication**: Flask-Login
- **API**: RESTful
- **Templating**: Jinja2

### Frontend
- **UI Framework**: Bootstrap 5
- **JavaScript**: Vanilla JS with AJAX
- **Styling**: Custom CSS with CSS Variables
- **Icons**: Font Awesome

### Development Tools
- **Version Control**: Git
- **Package Management**: pip
- **Virtual Environment**: venv
- **Testing**: pytest
- **Code Quality**: flake8, black

## Core Components

### 1. User Management
- Registration and authentication
- Role-based access control
- Profile management
- Session handling

### 2. Challenge System
- Multiple difficulty levels
- Categorized challenges
- Flag submission and validation
- Progress tracking
- Hints and solutions

### 3. Virtual Machine Integration
- VM lifecycle management
- Resource allocation
- Network configuration
- Snapshot management

### 4. Admin Dashboard
- User management
- Challenge management
- System monitoring
- Analytics and reporting

## Database Design

### Users Table
```sql
CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(120) NOT NULL,
    role VARCHAR(20) DEFAULT 'student',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Challenges Table
```sql
CREATE TABLE challenge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    difficulty VARCHAR(20) NOT NULL,
    category VARCHAR(50) NOT NULL,
    points INTEGER DEFAULT 100,
    flag VARCHAR(100) NOT NULL,
    hints TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Security Implementation

### Authentication
- Password hashing with bcrypt
- Secure session management
- CSRF protection
- Rate limiting

### Data Protection
- Input validation
- Output encoding
- Secure headers
- SQL injection prevention

## API Documentation

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `GET /api/auth/logout` - User logout
- `GET /api/auth/status` - Check authentication status

### Challenges
- `GET /api/challenges` - List all challenges
- `GET /api/challenges/<id>` - Get challenge details
- `POST /api/challenges/<id>/submit` - Submit flag
- `GET /api/challenges/categories` - List challenge categories

## Frontend Structure

### Key Templates
- `base.html` - Base template with navigation
- `index.html` - Home page
- `challenges.html` - Challenge listing
- `challenge_detail.html` - Individual challenge view
- `dashboard.html` - User dashboard
- `admin.html` - Admin interface

### JavaScript Modules
- `auth.js` - Authentication handling
- `challenges.js` - Challenge interaction
- `ui.js` - UI components
- `api.js` - API communication

## Virtual Machine Integration

### VM Management
- Start/stop VMs
- Snapshot management
- Resource monitoring
- Network configuration

### Security Considerations
- Network isolation
- Resource limits
- Access controls
- Logging and monitoring

## Deployment Guide

### Prerequisites
- Python 3.8+
- pip
- Virtual environment
- Database server (SQLite/PostgreSQL)
- Web server (Nginx/Apache)

### Steps
1. Clone the repository
2. Set up virtual environment
3. Install dependencies
4. Configure environment variables
5. Initialize database
6. Run migrations
7. Start the application

## Development Workflow

### Getting Started
```bash
# Clone repository
git clone https://github.com/SuhasKoparde/Cyberrange.git
cd Cyberrange

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Initialize database
python -c "from app import app, db; app.app_context().push(); db.create_all()"
python -c "from app import init_db; init_db()"

# Run development server
python app.py
```

### Code Style
- Follow PEP 8 guidelines
- Use type hints
- Document all public methods
- Write meaningful commit messages

## Testing Strategy

### Unit Tests
- Test individual components
- Mock external dependencies
- Test edge cases

### Integration Tests
- Test component interactions
- Test API endpoints
- Test database operations

### Security Testing
- Penetration testing
- Vulnerability scanning
- Code review

## Troubleshooting

### Common Issues
1. **Database connection errors**
   - Verify database credentials
   - Check if database server is running
   - Ensure proper permissions

2. **Authentication issues**
   - Clear browser cookies
   - Check server logs
   - Verify password hashing

3. **VM connectivity problems**
   - Check network settings
   - Verify VM status
   - Check resource allocation

## Future Enhancements

### Short-term
- Add more challenge categories
- Improve UI/UX
- Enhance documentation
- Add more tests

### Long-term
- Multiplayer mode
- AI-powered challenges
- Mobile app
- Integration with security tools

---

This documentation provides a comprehensive overview of the Cyber Range project. For specific implementation details, refer to the inline code comments and API documentation.
