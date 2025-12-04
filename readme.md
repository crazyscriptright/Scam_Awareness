# Scam Awareness Platform - JWT Authentication

A full-stack web application for reporting and managing scam incidents with JWT-based authentication. The platform consists of a React frontend deployed on Vercel and an Express.js backend deployed on Heroku.

## 🏗️ Architecture

```
Frontend (React - Vercel) ←→ JWT Auth ←→ Backend (Express - Heroku) ←→ PostgreSQL
```

## Features

- **JWT Authentication**: Secure token-based authentication (24h expiry)
- **User Management**: Registration, login, profile management
- **Scam Reporting**: Submit and track scam reports with proof attachments
- **Admin Dashboard**: Manage users, review reports, analytics
- **External Resource Portal**: Investigation and report management
- **Real-time Analytics**: Track scam trends and statistics
- **Role-Based Access**: Three user types (Normal User, Admin, External Resource)

## Demo

![Hero Section](.github/Hero_section.gif)
![Project Overview](.github/All_Project.gif)
![Admin Dashboard](.github/Admin.gif)
![External Portal](.github/External.gif)


## Prerequisites

- Node.js (v18+)
- PostgreSQL (v13+)
- npm or yarn
- Heroku CLI (for backend deployment)
- Vercel CLI (for frontend deployment)

## 📁 Project Structure

```
new_scam_awarenss/
├── front-scam/              # Frontend (Vercel)
│   ├── src/
│   │   ├── Components/      # React components
│   │   ├── utils/           # Auth utilities & axios config
│   │   └── config/          # API configuration
│   └── package.json
│
└── my-server/               # Backend (Heroku)
    ├── middleware/          # JWT authentication middleware
    ├── index.js             # Main server file
    ├── Procfile             # Heroku deployment
    ├── .env.example         # Environment template
    └── package.json
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/crazyscriptright/scam_awareness.git
cd scam_awareness
```

2. Set up the backend:
```bash
cd my-server
npm install
cp .env.example .env
# Edit .env with your database credentials and JWT secret
```

3. Generate JWT Secret:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

4. Set up the database:
- Create a PostgreSQL database
- Run the SQL commands from database.txt:
```sql
psql -U postgres -h localhost -p 5432 -d Scam_Awareness -f database.txt
```

5. Configure environment variables:
Create .env file in my-server directory:
```env
DB_USER=postgres
DB_HOST=localhost
DB_NAME=Scam_Awareness
DB_PASSWORD=your_password
DB_PORT=5432
JWT_SECRET=your_generated_jwt_secret_here
PORT=5000
ALLOWED_ORIGINS=http://localhost:3000
NODE_ENV=development
```

6. Install frontend dependencies:
```bash
cd ../front-scam
npm install
cp .env.example .env
# Set REACT_APP_API_URL=http://localhost:5000
```

## Running the Application

### Development Mode

1. Start the backend server:
```bash
cd my-server
npm start
```

2. Start the frontend development server:
```bash
cd front-scam
npm start
```

The application will be available at:
- Frontend: http://localhost:3000
- Backend: http://localhost:5000

### Production Deployment

**Backend (Heroku)** - See [my-server/HEROKU_DEPLOYMENT.md](my-server/HEROKU_DEPLOYMENT.md)
```bash
cd my-server
heroku create scam-awareness-api
heroku addons:create heroku-postgresql:mini
heroku config:set JWT_SECRET="your_jwt_secret_here"
heroku config:set ALLOWED_ORIGINS="https://scam-awareness.vercel.app"
git push heroku main
```

**Frontend (Vercel)**
```bash
cd front-scam
npm i -g vercel
vercel --prod
# Set REACT_APP_API_URL in Vercel dashboard
```

## 🔐 Authentication System

### JWT Token Flow
1. User logs in with credentials
2. Server validates and generates JWT token (24h expiry)
3. Client stores token in localStorage
4. All API requests include: `Authorization: Bearer <token>`
5. Server validates token and extracts user data
6. Protected routes check user role (userType)

### Frontend Auth Utilities (`front-scam/src/utils/auth.js`)
- `setToken(token, user)` - Store authentication data
- `getToken()` - Retrieve stored token
- `isAuthenticated()` - Check if user is logged in
- `getUserRole()` - Get user type (0/1/2)

### Backend Middleware (`my-server/middleware/auth.js`)
- `verifyToken` - Validates JWT token
- `requireAdmin` - Ensures userType === 1
- `requireExternal` - Ensures userType === 2
- `generateToken(user)` - Creates JWT token

## User Roles

1. **Normal User (userType: 0)**
   - Submit scam reports with proof attachments
   - Track report status
   - Update profile and password
   - Contact support
   - View scam awareness resources

2. **Admin (userType: 1)**
   - User management (block/unblock users)
   - Report review and approval
   - Analytics dashboard
   - Create external resource accounts
   - View and manage contact submissions
   - System configuration

3. **External Resource (userType: 2)**
   - Review assigned scam reports
   - Update investigation status
   - Add comments to reports
   - Access specialized tools
   - Profile management
   - Collaborate with admin

## 🔧 API Endpoints

### Public Endpoints
- `POST /signin` - User login (returns JWT token)
- `POST /signup` - User registration
- `POST /forgot-password` - Password reset

### Protected Endpoints (JWT Required)
- `GET /profile` - Get user profile
- `POST /scam-reports` - Submit scam report
- `GET /api/reports` - Get user's reports
- `POST /api/contact` - Submit contact form
- `POST /update-profile-picture` - Update profile picture
- `POST /update-password` - Change password

### Admin Endpoints (Requires userType: 1)
- `GET /api/scam-reports` - Get all scam reports
- `PUT /admin-approval/:report_id` - Approve/reject report
- `POST /api/create_external_user` - Create external user
- `PUT /api/users/status` - Block/unblock users
- `GET /api/contacts` - View contact submissions
- `GET /api/users/registration-stats` - Analytics

### External Resource Endpoints (Requires userType: 2)
- `GET /api/scam-reports-modified` - Get assigned reports
- `PUT /external-report-update/:report_id` - Update report status
- `GET /external-profile-picture` - Get profile picture
- `POST /external-profile-picture` - Update profile picture

## 🛠️ Technology Stack

### Frontend
- React 18.x
- Material-UI (MUI)
- Ant Design
- Axios (configured with JWT)
- React Router v7

### Backend
- Node.js 18.x
- Express.js
- PostgreSQL
- JSON Web Tokens (JWT)
- bcrypt (password hashing)
- Helmet, CORS, Morgan

### DevOps
- Vercel (Frontend hosting)
- Heroku (Backend hosting)
- Heroku Postgres (Database)

## 📚 Documentation

- [HEROKU_DEPLOYMENT.md](my-server/HEROKU_DEPLOYMENT.md) - Complete Heroku deployment guide
- [JWT_MIGRATION_SUMMARY.md](my-server/JWT_MIGRATION_SUMMARY.md) - JWT migration details
- [database.txt](database.txt) - Database schema and setup

## 🔒 Security Features

- ✅ JWT token authentication (24h expiry)
- ✅ Password hashing with bcrypt
- ✅ CORS configuration with specific origins
- ✅ Helmet middleware for security headers
- ✅ SQL injection prevention (parameterized queries)
- ✅ HTTPS enforcement (automatic on Vercel/Heroku)
- ✅ Role-based access control
- ✅ Environment variable protection

## 🐛 Troubleshooting

### Backend Issues
- **CORS errors**: Verify `ALLOWED_ORIGINS` includes your frontend URL
- **Database connection**: Check `DATABASE_URL` or DB credentials in Heroku config
- **JWT errors**: Ensure `JWT_SECRET` is set and consistent
- **Deployment**: Check `heroku logs --tail` for errors

### Frontend Issues
- **API calls failing**: Verify `REACT_APP_API_URL` is set correctly
- **Token expired**: Login again to get a new token
- **Protected routes not working**: Check token in localStorage and userType

## 📊 Project Status

- ✅ Frontend: Complete with JWT authentication
- ✅ Backend: Complete with JWT authentication
- ✅ Database: Schema defined and tested
- ✅ Deployment: Ready for Heroku + Vercel
- ✅ Documentation: Comprehensive guides created
- ✅ Security: JWT-based auth fully implemented

## Repository

Main repository: https://github.com/crazyscriptright/scam_awareness.git

## Contact

Email: crazyscriptright@gmail.com
Project Link: https://github.com/crazyscriptright/scam_awareness
