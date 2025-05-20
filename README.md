
# Flask + Authentik SSO App

This is a secure, production-ready Flask application integrated with Authentik using OAuth2 + OpenID Connect for Single Sign-On (SSO). It supports role-based access, dynamic group assignment, and Redis-backed session handling.


Features:

* OAuth2 + OIDC integration with Authentik
* Login/logout flow with secure CSRF protection
* Role/group-based access control
* Redis session/state backup support
* Custom error handling and debug routes
* Docker & Docker Compose support for easy deployment

Tech Stack:

* Python 3.12+
* Flask + Flask-Login
* Flask-Session
* Redis (optional)
* Authentik as Identity Provider
* Docker / Docker Compose

Project Structure:

.
├── app.py
├── templates/
├── static/
├── .env
├── Dockerfile
├── docker-compose.yml
└── README.md


Setup Instructions:

1. Clone the Repo

   git clone [https://github.com/madiha-ahmed-chowdhury/Flask-application-with-SSO.git](https://github.com/madiha-ahmed-chowdhury/Flask-application-with-SSO.git)
   cd flask-authentik-sso

2. Add .env Configuration

   FLASK\_SECRET\_KEY=your\_super\_secret\_key
   FLASK\_ENV=development
   FLASK\_DEBUG=True
   AUTHENTIK\_URL=[http://localhost:9000](http://localhost:9000)
   AUTHENTIK\_CLIENT\_ID=your-client-id
   AUTHENTIK\_CLIENT\_SECRET=your-client-secret
   REDIRECT\_URI=[http://localhost:5000/auth/callback](http://localhost:5000/auth/callback)
   REDIS\_HOST=redis
   REDIS\_PORT=6379

3. Run with Docker Compose

   docker-compose up --build

   Access the app at: [http://localhost:5000](http://localhost:5000)


Authentik Setup:

1. Create OAuth2 Provider

   * Redirect URI: [http://localhost:5000/auth/callback](http://localhost:5000/auth/callback)

2. Create Application

   * Link it to the provider
   * Restrict with group policy if needed

3. Create Users & Groups

   * Example groups: admin, manager, qa
   * Assign users to roles via group membership

Login Flow:

1. Visit /login
2. Redirected to Authentik
3. After login, Authentik redirects back
4. App verifies state, fetches tokens, and logs user in

Developer Tools:

* /test-session: Debug session storage
* /auth-status: View login state
* /debug/env: View environment variables (dev only)


Logout Flow:

* Flask session is cleared
* User is redirected to Authentik logout:
  /application/o/logout/?redirect\_uri=[http://localhost:5000](http://localhost:5000)

Docker Compose:

Includes:

* Flask app
* Redis (for session/state)

Command:
docker-compose up --build

