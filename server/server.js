const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Use environment variable for port, fallback to 8090
const PORT = process.env.PORT || 8090;
const secretKey = process.env.JWT_SECRET || 'your_secret_key'; // Store this securely

const app = express();
app.use(cors());
app.use(express.json()); // Middleware to parse JSON bodies

// Connect to MySQL database
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'test',
});

// Check MySQL connection
db.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err);
    } else {
        console.log('Connected to the MySQL database.');
    }
});

// Register a new user
app.post('/users/register', async (req, res) => {
    const { first_name, last_name, phone_number, password } = req.body;

    // Ensure required fields are present
    if (!first_name || !last_name || !phone_number || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = "INSERT INTO users (first_name, last_name, phone_number, password) VALUES (?, ?, ?, ?)";
        db.query(sql, [first_name, last_name, phone_number, hashedPassword], (err, result) => {
            if (err) {
                console.error('Error inserting data into the database:', err);
                return res.status(500).json({ error: 'Database insertion error' });
            }
            return res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        return res.status(500).json({ error: 'Error while registering user' });
    }
});

// User login
app.post('/users/login', (req, res) => {
    const { first_name, last_name, password } = req.body;

    if (!first_name || !last_name || !password) {
        return res.status(400).json({ error: 'First name, last name, and password are required' });
    }

    const sql = "SELECT * FROM users WHERE first_name = ? AND last_name = ?";
    db.query(sql, [first_name, last_name], async (err, users) => {
        if (err) {
            console.error('Error fetching user from database:', err);
            return res.status(500).json({ error: 'Database query error' });
        }

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = users[0];

        // Compare hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user.id, first_name: user.first_name, last_name: user.last_name }, secretKey, { expiresIn: '1h' });

        return res.status(200).json({ message: 'Login successful', token });
    });
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res.status(403).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1]; // Extract token from "Bearer <token>"

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Unauthorized access' });
        }

        // Save the decoded user info (like id) in the request object
        req.user = decoded;
        next();
    });
};

// Example of a protected route to get user profile
app.get('/users/profile', verifyToken, (req, res) => {
    const userId = req.user.id; // Extract user ID from the decoded JWT

    const sql = "SELECT id, first_name, last_name, phone_number FROM users WHERE id = ?";
    db.query(sql, [userId], (err, users) => {
        if (err) {
            console.error('Error fetching user profile from database:', err);
            return res.status(500).json({ error: 'Database query error' });
        }

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Return user profile details
        const userProfile = users[0];
        return res.json({ 
            message: 'Profile fetched successfully', 
            profile: userProfile 
        });
    });
});

// Define /users route to get all users
app.get("/users", (req, res) => {
    const sql = "SELECT * FROM users";
    db.query(sql, (err, data) => {
        if (err) return res.json(err);
        return res.json(data);
    });
});

// Update user (PUT or PATCH)
app.put('/users/update/:id', (req, res) => {
    const { id } = req.params;
    const { first_name, last_name, phone_number, password } = req.body;

    // Ensure required fields are present
    if (!first_name || !last_name || !phone_number || !password) {
        return res.status(400).json({ error: 'First name, last name, and phone number are required' });
    }

    const sql = "UPDATE users SET first_name = ?, last_name = ?, phone_number = ?, password = ? WHERE id = ?";
    db.query(sql, [first_name, last_name, phone_number, password, id], (err, result) => {
        if (err) {
            console.error('Error updating data in the database:', err);
            return res.status(500).json({ error: 'Database update error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        return res.status(200).json({ message: 'User updated successfully' });
    });
});

// Delete user (DELETE)
app.delete('/users/delete/:id', (req, res) => {
    const { id } = req.params;

    const sql = "DELETE FROM users WHERE id = ?";
    db.query(sql, [id], (err, result) => {
        if (err) {
            console.error('Error deleting data from the database:', err);
            return res.status(500).json({ error: 'Database deletion error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        return res.status(200).json({ message: 'User deleted successfully' });
    });
});

// Define /users/:id/posts route to get all posts for a specific user
app.get('/users/:id/posts', (req, res) => {
    const { id } = req.params;

    const sql = "SELECT * FROM posts WHERE user_id = ?";
    db.query(sql, [id], (err, data) => {
        if (err) return res.json(err);
        return res.json(data);
    });
});

// Define /posts route to get all posts for a specific user
app.get('/get/post', (req, res)=> {
    const sql = "SELECT * FROM posts";
    db.query(sql, (err, data) => {
        if (err) return res.json(err);
        return res.json(data);
    });
})

// Define /posts/create route to create a new post
app.post('/posts/create', (req, res) => {
    const { title, content, user_id } = req.body;

    // Ensure required fields are present
    if (!title || !content || !user_id) {
        return res.status(400).json({ error: 'Title, content, and user ID are required' });
    }

    const sql = "INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)";
    db.query(sql, [title, content, user_id], (err, result) => {
        if (err) {
            console.error('Error inserting data into the database:', err);
            return res.status(500).json({ error: 'Database insertion error' });
        }
        return res.status(201).json({ message: 'Post created successfully', postId: result.insertId });
    });
});

// Define /posts/update/:id route to update a post
app.put('/posts/update/:id', (req, res) => {
    const { id } = req.params;
    const { title, content, user_id } = req.body;

    // Ensure required fields are present
    if (!title || !content || !user_id) {
        return res.status(400).json({ error: 'Title, content, and user ID are required' });
    }

    const sql = "UPDATE posts SET title = ?, content = ?, user_id = ? WHERE id = ?";
    db.query(sql, [title, content, user_id, id], (err, result) => {
        if (err) {
            console.error('Error updating data in the database:', err);
            return res.status(500).json({ error: 'Database update error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Post not found' });
        }

        return res.status(200).json({ message: 'Post updated successfully' });
    });
});

// Define /posts/delete/:id route to delete a post
app.delete('/posts/delete/:id', (req, res) => {
    const { id } = req.params;

    const sql = "DELETE FROM posts WHERE id = ?";
    db.query(sql, [id], (err, result) => {
        if (err) {
            console.error('Error deleting data from the database:', err);
            return res.status(500).json({ error: 'Database deletion error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Post not found' });
        }

        return res.status(200).json({ message: 'Post deleted successfully' });
    });
});

// Define /comments route to get all posts
app.get('/get/comments', (req, res)=> {
    const sql = "SELECT * FROM comments";
    db.query(sql, (err, data) => {
        if (err) return res.json(err);
        return res.json(data);
    });
})

// Define /comments/create route to create a comment for a post by a user
app.post('/comments/create', (req, res) => {
    const { comment, user_id, post_id } = req.body;

    // Ensure required fields are present
    if (!comment || !user_id || !post_id) {
        return res.status(400).json({ error: 'Comment, user ID, and post ID are required' });
    }

    const sql = "INSERT INTO comments (comment, user_id, post_id) VALUES (?, ?, ?)";
    db.query(sql, [comment, user_id, post_id], (err, result) => {
        if (err) {
            console.error('Error inserting data into the database:', err);
            return res.status(500).json({ error: 'Database insertion error' });
        }
        return res.status(201).json({ message: 'Comment created successfully', commentId: result.insertId });
    });
});

// Define /posts/:id/comments route to get all comments for a specific post
app.get('/posts/:id/comments', (req, res) => {
    const { id } = req.params;

    const sql = `
        SELECT comments.id, comments.comment, users.first_name, users.last_name
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.post_id = ?
    `;
    db.query(sql, [id], (err, data) => {
        if (err) return res.json(err);
        return res.json(data);
    });
});

// Define /users/:id/comments route to get all comments made by a specific user
app.get('/users/:id/comments', (req, res) => {
    const { id } = req.params;

    const sql = `
        SELECT comments.id, comments.comment, posts.title
        FROM comments
        JOIN posts ON comments.post_id = posts.id
        WHERE comments.user_id = ?
    `;
    db.query(sql, [id], (err, data) => {
        if (err) return res.json(err);
        return res.json(data);
    });
});

// Define /comments/update/:id route to update a comment
app.put('/comments/update/:id', (req, res) => {
    const { id } = req.params;
    const { comment } = req.body;

    if (!comment) {
        return res.status(400).json({ error: 'Comment text is required' });
    }

    const sql = "UPDATE comments SET comment = ? WHERE id = ?";
    db.query(sql, [comment, id], (err, result) => {
        if (err) {
            console.error('Error updating comment:', err);
            return res.status(500).json({ error: 'Database update error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Comment not found' });
        }

        return res.status(200).json({ message: 'Comment updated successfully' });
    });
});

// Define /comments/delete/:id route to delete a comment
app.delete('/comments/delete/:id', (req, res) => {
    const { id } = req.params;

    const sql = "DELETE FROM comments WHERE id = ?";
    db.query(sql, [id], (err, result) => {
        if (err) {
            console.error('Error deleting comment:', err);
            return res.status(500).json({ error: 'Database deletion error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Comment not found' });
        }

        return res.status(200).json({ message: 'Comment deleted successfully' });
    });
});

// Get the total number of likes for a post
app.get('/posts/:postId/likes', (req, res) => {
    const postId = req.params.postId;

    const sql = "SELECT COUNT(*) as likeCount FROM post_likes WHERE post_id = ?";
    db.query(sql, [postId], (err, result) => {
        if (err) {
            console.error('Error fetching post like count:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        return res.status(200).json({ likeCount: result[0].likeCount });
    });
});

// Like a post
app.post('/posts/:postId/like', verifyToken, (req, res) => {
    const userId = req.user.id; // Get user ID from JWT
    const postId = req.params.postId;

    const sql = "INSERT INTO post_likes (user_id, post_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE user_id = user_id";
    db.query(sql, [userId, postId], (err, result) => {
        if (err) {
            console.error('Error liking post:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        return res.status(200).json({ message: 'Post liked successfully' });
    });
});

// Unlike a post
app.delete('/posts/:postId/unlike', verifyToken, (req, res) => {
    const userId = req.user.id;
    const postId = req.params.postId;

    const sql = "DELETE FROM post_likes WHERE user_id = ? AND post_id = ?";
    db.query(sql, [userId, postId], (err) => {
        if (err) {
            console.error('Error unliking post:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        return res.status(200).json({ message: 'Post unliked successfully' });
    });
});

// Get the total number of likes for a comment
app.get('/comments/:commentId/likes', (req, res) => {
    const commentId = req.params.commentId;

    const sql = "SELECT COUNT(*) as likeCount FROM comment_likes WHERE comment_id = ?";
    db.query(sql, [commentId], (err, result) => {
        if (err) {
            console.error('Error fetching comment like count:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        return res.status(200).json({ likeCount: result[0].likeCount });
    });
});

// Like a comment
app.post('/comments/:commentId/like', verifyToken, (req, res) => {
    const userId = req.user.id; // Get user ID from JWT
    const commentId = req.params.commentId;

    const sql = "INSERT INTO comment_likes (user_id, comment_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE user_id = user_id";
    db.query(sql, [userId, commentId], (err) => {
        if (err) {
            console.error('Error liking comment:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        return res.status(200).json({ message: 'Comment liked successfully' });
    });
});

// Unlike a comment
app.delete('/comments/:commentId/unlike', verifyToken, (req, res) => {
    const userId = req.user.id;
    const commentId = req.params.commentId;

    const sql = "DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?";
    db.query(sql, [userId, commentId], (err, result) => {
        if (err) {
            console.error('Error unliking comment:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        return res.status(200).json({ message: 'Comment unliked successfully' });
    });
})

// Start the server
app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
