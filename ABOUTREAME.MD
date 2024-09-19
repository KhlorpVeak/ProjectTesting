# node.js
- version v18.20.4
- npm v10.7.0
- nvm v1.1.12

# Create a project node.js
npx create-react-app name_project

# Run the project node.js
- npm init -y
- npm i express
- npm i nodemon -D
- npm install @hapi/joi

# port on Server
port 8090

# Hash Passwords for Security
- npm install bcryptjs

# Session Management or Token-Based Authentication
- npm install jsonwebtoken
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');