# User API Server

A REST API server for managing user accounts. Handles user registration, authentication, and profile management.

## Endpoints

- POST /api/register - Create new account
- POST /api/login - Authenticate user
- GET /api/profile/:id - Get user profile
- PUT /api/profile/:id - Update profile
- GET /api/search - Search users

## Stack

- Node.js + Express
- SQLite database
- JWT authentication
