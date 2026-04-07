# Mail Merge Application

A Flask-based web application for sending bulk emails with personalized certificates to students. This application streamlines the process of certificate distribution by matching student names with PDF certificates and sending them via email with customizable messages.

## Table of Contents
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Database Setup](#database-setup)
- [Usage](#usage)
- [User Management](#user-management)
- [Audit Logging](#audit-logging)
- [Development](#development)

## Features

### Core Functionality
- **CSV-based Student Management**: Upload student data in CSV format with automatic column detection
- **Certificate Matching**: Intelligent PDF certificate matching using student names (supports full names, first/last names, and Unicode normalization)
- **Bulk Email Sending**: Thread-based email transmission with real-time progress tracking
- **Email Personalization**: Template-based email bodies with `{name}` and `{email}` placeholders
- **PDF Attachments**: Automatic certificate attachment to personalized emails

### User Management
- **Google OAuth Authentication**: Secure sign-in via Google accounts
- **Role-Based Access Control**: Admin and User roles with different permission levels
- **User Approval System**: Pending/Active/Suspended user statuses
- **Login Tracking**: Monitoring of login history and user activity

### Email Configuration
- **Multiple SMTP Profiles**: Store and switch between different email service configurations
- **Gmail & Custom SMTP Support**: Compatible with Gmail, custom mail servers, and other SMTP services
- **Secure Configuration**: SMTP credentials stored in database with environment variable fallback

### Security & Monitoring
- **Comprehensive Audit Logging**: Track all user actions with IP addresses and user agents
- **Access Control**: Login and admin-level decorators for route protection
- **Email Masking**: Secure display of email addresses in the interface

## Technology Stack

### Backend
- **Flask**: Lightweight Python web framework
- **SQLAlchemy**: ORM for database operations
- **PostgreSQL**: Primary production database (via psycopg2)
- **Flask-Migrate**: Database migration management using Alembic

### Authentication
- **Google OAuth 2.0**: Federated authentication via Google accounts
- **google-auth-oauthlib 1.3.0**: OAuth library for Google integration

### Data Processing
- **Pandas 3.0.2**: CSV parsing and data manipulation
- **NumPy 2.4.4**: Numerical computations (pandas dependency)

### Email
- **Python SMTP (built-in)**: Email sending functionality
- **Python-dotenv 1.2.2**: Environment variable management

### Frontend
- **Jinja2 3.1.6**: HTML templating engine
- **JavaScript**: Client-side functionality

### Additional Libraries
- **Cryptography 46.0.5**: Security operations
- **PyYAML 6.0.3**: YAML parsing (Alembic dependency)
- **Requests 2.32.5**: HTTP library
- **HTTPx/OAuthlib**: OAuth support

## Project Structure

```
mailmerge/
├── app.py                          # Main Flask application & routes
├── auth.py                         # Authentication & authorization logic
├── models.py                       # Database models & ORM definitions
├── activate_user.py               # CLI utility for user activation
├── requirements.txt               # Python dependencies
├── client_secret.json             # Google OAuth credentials
├── .env                           # Environment variables (not in repo)
├── env_mailmerge/                 # Virtual environment
├── migrations/                     # Database migrations (Alembic)
│   ├── alembic.ini
│   ├── env.py
│   └── versions/                  # Migration files
├── static/                        # Static assets
│   ├── css/
│   │   ├── main.css
│   │   ├── index.css
│   │   └── status.css
│   └── robots.txt
├── templates/                     # Jinja2 HTML templates
│   ├── index.html                # Main certificate sending interface
│   ├── login.html                # Google OAuth login page
│   ├── admin.html                # Admin dashboard
│   ├── account_status.html       # User account status page
│   ├── unauthorized.html         # Access denied page
│   └── 404.html                  # Not found page
└── uploads/                       # Temporary file storage
    ├── students.csv              # Uploaded student list
    └── certificates/             # Extracted certificate PDFs
```

## Prerequisites

- Python 3.8 or higher
- PostgreSQL database
- Google OAuth credentials (for authentication)
- pip (Python package manager)

## Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd mailmerge
```

### 2. Create Virtual Environment
```bash
python -m venv env_mailmerge
source env_mailmerge/Scripts/activate  # On Windows
# or
source env_mailmerge/bin/activate     # On macOS/Linux
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Set Up Google OAuth
1. Create a project in [Google Cloud Console](https://console.cloud.google.com/)
2. Create OAuth 2.0 credentials (Web application type)
3. Download the credentials JSON file
4. Save as `client_secret.json` in the project root

## Configuration

### Environment Variables
Create a `.env` file in the project root with the following variables:

```env
# Flask Configuration
SECRET_KEY=your-secret-key-here
DEBUG=false

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/mailmerge_db

# Google OAuth
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CALLBACK=http://localhost:5000/callback

# Default SMTP (fallback if not configured in database)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_EMAIL=your-email@gmail.com
SMTP_TLS=true
```

### Important Security Notes
- **PASSWORD_STORAGE**: SMTP passwords are stored in plaintext in the database. Restrict OS-level database file access (chmod 600 on Linux/macOS)
- **SECRET_KEY**: Generate a strong, random secret key for Flask
- **ENVIRONMENT**: Set `DEBUG=false` in production

## Database Setup

### Initial Setup
```bash
# Create database
createdb mailmerge_db

# Initialize database schema
flask db upgrade
```

### Create Admin User
1. Start Flask shell:
   ```bash
   flask shell
   exec(open("activate_user.py").read())
   ```
2. Enter the email of the user to activate as admin
3. The user must have logged in at least once before activation

### Database Migrations
When making model changes:
```bash
flask db migrate -m "Description of changes"
flask db upgrade
```

## Usage

### Starting the Application
```bash
# Development
flask run

# Production (use a proper WSGI server)
gunicorn app:app
```

The application will be available at `http://localhost:5000`

### Typical Workflow

#### 1. User Login
- Click "Login with Google"
- Authorize the application with your Google account
- Account status: Initially "pending", must be approved by an admin

#### 2. Admin Approval
- Admin accesses the admin dashboard
- Approves pending users to "active" status
- Optionally assigns roles (admin/user)

#### 3. Configure SMTP (Admin Only)
- Access SMTP configuration page
- Add email service credentials (Gmail, custom SMTP, etc.)
- Activate the desired configuration
- Test connection with status check

#### 4. Upload Student Data
- Prepare CSV file with columns:
  - `email` (required): Student email addresses
  - `name` OR (`first_name` + `last_name`): Student names
  - Additional columns ignored
- Prepare ZIP file containing certificate PDFs
- Upload both files via web interface
- Application automatically matches certificates to names

#### 5. Compose & Send Emails
- Customize email subject and body
- Use `{name}` and `{email}` placeholders
- Preview matched students
- Click send to transmit emails with attachments
- Monitor progress in real-time

## User Management

### User Lifecycle

```
New Account
    ↓
[LOGIN] → Database record created with status='pending'
    ↓
[ADMIN APPROVAL] → Status changed to 'active'
    ↓
[READY TO USE] → User can access full application
```

### CLI User Activation
For initial admin setup or user activation without web UI:

```bash
flask shell
exec(open("activate_user.py").read())
# Enter email and role when prompted
```

### User Status Values
- **pending**: Account created but not yet approved by admin
- **active**: Approved user with full access
- **suspended**: Temporarily disabled account (can be reactivated)

### User Roles
- **user**: Standard user - can use mail merge features
- **admin**: Administrator - can manage users, SMTP configs, view audit logs

## Audit Logging

Every user action is logged with:
- Timestamp (UTC timezone)
- User identity (Google ID and email)
- Action type and details
- Source IP address
- User agent (browser/application info)
- Success/failure status


## Development

### Running Locally
```bash
# With virtual environment activated
flask run

# Access at http://localhost:5000
```

### Debugging
Set `DEBUG=true` in `.env` for:
- Live code reloading
- Interactive debugger
- Detailed error pages

### Database Inspection
```bash
# PostgreSQL command line
psql mailmerge_db

# Common queries
SELECT * FROM users;
SELECT * FROM "audit_logs" ORDER BY "timestamp" DESC LIMIT 20;
SELECT * FROM "smtp_configs";
```

### Testing Files
For development/testing:
- Sample CSV: `uploads/students.csv`
- Certificate directory: `uploads/certificates/`

### Building from Source
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

## License & Support

For issues, feature requests, or contributions, please contact the development team.

---

**Last Updated**: April 2025
