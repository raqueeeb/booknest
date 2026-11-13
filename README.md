# 📚 BookNest

A modern **full-stack library management system** built with **React, Spring Boot, and PostgreSQL**.

BookNest is a digital library platform that allows students to explore books, manage their borrowing activity, and provides administrators with tools to manage books, students, and library operations.

🌐 **Live Demo:** https://booknestx.vercel.app/
📘 **Case study:** [raqueeb.dev/projects/booknest](https://raqueeb.dev/projects/booknest)

---

# ✨ Features

## 👨‍🎓 Student Features

- 🔐 Student registration and login
- 📚 Browse available books
- 🔍 Search books by title and author
- 🏷️ Filter books by category
- ⭐ View book ratings and details
- 📖 Borrow books
- 📋 View borrowing history
- 🔖 Bookmark favourite books
- 💰 Track fines and due dates


## 🛡️ Admin Features

- 🔐 Admin authentication
- 📊 Library overview dashboard
- 📚 Add, edit, and delete books
- 👥 Manage registered students
- 🔄 Manage borrowing records
- ✅ Mark returned books
- 📈 View library statistics

---

# 🛠️ Tech Stack

## Frontend

<p>
<img src="https://skillicons.dev/icons?i=react,vite,tailwind,js" />
</p>

- React.js
- Vite
- Tailwind CSS
- JavaScript


## Backend

<p>
<img src="https://skillicons.dev/icons?i=java,spring" />
</p>

- Java
- Spring Boot
- Spring Data JPA
- Spring Security


## Database

<p>
<img src="https://skillicons.dev/icons?i=postgres" />
</p>

- PostgreSQL (production and local)
- Optional MySQL profile for local development
- Hibernate ORM

---

# 📸 Screenshots

## 🔐 Login Page

<img width="1915" height="933" alt="image" src="https://github.com/user-attachments/assets/296a7245-fb37-4875-b439-edc2cbb8709e" />



## 👨‍🎓 Student Dashboard

<img width="1916" height="940" alt="image" src="https://github.com/user-attachments/assets/53e401b1-13d7-4144-abff-685af08dc47d" />



## 📚 Browse Books

<img width="1912" height="863" alt="image" src="https://github.com/user-attachments/assets/5e5aa172-3749-4522-82b1-bc2f3cf0814d" />



## 📖 My Borrowings

<img width="1918" height="937" alt="image" src="https://github.com/user-attachments/assets/d520dab1-55cd-4497-8660-f6b76c3d3484" />



## 🛡️ Admin Dashboard

<img width="1895" height="798" alt="image" src="https://github.com/user-attachments/assets/dde14e9f-6874-48e6-b0b2-a275013b0d1e" />



## 📚 Manage Books

<img width="1902" height="709" alt="image" src="https://github.com/user-attachments/assets/7a676fe0-5210-47e6-adb0-3cd078549613" />



## 🔄 Borrow Management

<img width="1898" height="568" alt="image" src="https://github.com/user-attachments/assets/d48cd3c4-8994-438d-bbde-dbe9a35d1182" />
)

---

# 🏗️ Project Structure

```
BookNest
│
├── frontend
│   ├── React
│   ├── Vite
│   └── Tailwind CSS
│
└── backend
    ├── Spring Boot
    ├── Java
    └── PostgreSQL
```

---

# 🚀 Installation & Setup

## Prerequisites

Make sure you have installed:

- Java JDK 17+
- Node.js
- Maven


## Frontend Setup

```bash
cd frontend

npm install

npm run dev
```


## Backend Setup

```bash
cd backend

mvn spring-boot:run
```

---

# ⚙️ Configuration

Every credential comes from the environment. Nothing is committed, and no
setting has a fallback value, so the application fails to start rather than run
on a credential baked into the source.

Copy `.env.example` to `.env`, fill it in locally, and keep it out of Git
(`.env` is already ignored). In production these are set in the hosting
dashboard's environment settings instead.

| Variable | Required | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | yes | PostgreSQL connection string |
| `DATABASE_USERNAME` | yes | Database user |
| `DATABASE_PASSWORD` | yes | Database password |
| `JWT_SECRET` | yes | Token signing key, **at least 32 characters** |
| `ADMIN_USERNAME` | first run only | Username for the initial administrator |
| `ADMIN_PASSWORD` | first run only | Password for the initial administrator |
| `ADMIN_PASSWORD_RESET` | emergency only | Administrator username whose password should be reset to `ADMIN_PASSWORD` at startup |
| `APP_CORS_ALLOWED_ORIGINS` | no | Comma-separated browser origins; defaults to the deployed frontend and localhost |
| `MYSQL_URL`, `MYSQL_USERNAME`, `MYSQL_PASSWORD` | `mysql` profile only | Optional local MySQL |

Generate a signing key with:

```bash
openssl rand -base64 48
```

The administrator settings are used **only when the database contains no
administrator**. Once one exists they are ignored, and an account that already
exists under that username is never promoted. Leave them unset on an instance
that already has an administrator.

To run against local MySQL instead of PostgreSQL:

```bash
cd backend
MYSQL_URL=... MYSQL_USERNAME=... MYSQL_PASSWORD=... \
  ./mvnw spring-boot:run -Dspring-boot.run.profiles=mysql
```


## Changing the administrator password

Sign in as the administrator, open **My account** in the console sidebar, and
use **Change password**. The current password is required, and changing it signs
out every existing session for that account.

If nobody can sign in, reset it from the hosting dashboard instead:

1. Set `ADMIN_PASSWORD` to the new password and `ADMIN_PASSWORD_RESET` to the
   administrator's username.
2. Restart the service. The password is reset and existing sessions end.
3. **Delete both variables** and restart again. While they remain set, a later
   restart would undo a password changed inside the application.

The reset only ever touches an existing administrator: it will not create an
account and will not promote a student.

---

# 🔐 Security notes

- **Authentication** is a stateless bearer token signed with HMAC-SHA256 by a
  maintained JWT library, which verifies the signature and the algorithm rather
  than trusting the token's own header.
- **Authorization never trusts the token.** A token identifies the account; the
  role is read from the database on every request. A tampered token therefore
  cannot grant privileges, and a role change applies to the very next request.
- **Tokens can be invalidated.** Each account carries a token version that a
  password change increments, which retires every token issued before it. A
  token for a deleted account is refused.
- **Passwords** are stored as bcrypt hashes and never appear in API responses.
  Changing a username, email or password requires the current password.
- **CORS** allows only the configured origins.

Run the security regression suite with:

```bash
cd backend
./mvnw test
```

It runs against an in-memory database and needs no credentials.

# 📚 Application Modules

## Student Module

Handles:
- Student authentication
- Book browsing
- Searching and filtering
- Borrowing books
- Borrow history tracking
- Bookmark management


## Admin Module

Handles:
- Dashboard statistics
- Book management
- Student management
- Borrow management
- Library monitoring

---

# 🔮 Future Improvements

- 📱 Mobile application
- 📖 Online book reading system
- ☁️ Cloud database migration
- 📧 Email notifications
- 📊 Advanced analytics dashboard
- 🔔 Due date reminders
- 🤖 AI-based book recommendations

---

# 👨‍💻 Author

**Mohammed Abdul Raqueeb**

GitHub:
https://github.com/raqueeeb

---

# 📄 License

This project is created for educational and portfolio purposes.
