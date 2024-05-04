const express = require("express");
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require("cors");

const app = express();
const mySecretKey = "NEVERGIVEUP";



app.use(cors());
app.use(bodyParser.json());

const db = new sqlite3.Database('emipax.db');

// Create tables if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    email TEXT UNIQUE,
    password TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS Tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,
    status TEXT,
    assignee_id INTEGER,
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY(assignee_id) REFERENCES users(id)
);`);

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized: Missing token' });
    }
    jwt.verify(token, mySecretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Forbidden: Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Register endpoint
app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;
    try {
        // Check if email already exists
        const dbUser = await db.get(`SELECT email FROM users WHERE email = ?`, [email]);
        if (!dbUser) {
            // If email doesn't exist, hash the password and insert into database
            const hashedPassword = await bcrypt.hash(password, 10);
            await db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
                [username, email, hashedPassword]);
            res.json("User Registered Successfully");
        } else {
            // If email already exists, return error
            res.status(400).json("User Email Already Exists");
        }
    } catch (error) {
        console.error('Error registering user:', error.message);
        res.status(500).json("Internal Server Error");
    }
});

// Login endpoint
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const dbUser = await db.get(`SELECT * FROM users WHERE username = ?`, [username]);
        if (!dbUser) {
            return res.status(400).json("Invalid User");
        }
        const result = await bcrypt.compare(password, dbUser.password);
        if (result) {
            const payload = { username: dbUser.username };
            const jwtToken = jwt.sign(payload, mySecretKey);
            return res.json({ jwtToken });
        } else {
            return res.status(400).json("Invalid Password");
        }
    } catch (error) {
        console.error('Error logging in:', error.message);
        return res.status(500).json("Internal Server Error");
    }
});

// Other endpoints (add-task, getalltasks, delete, put, search) can be added as needed...

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

// Other endpoints (add-task, getalltasks, delete, put, search) can be added as needed...

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});


app.post("/add-task", authenticateToken, async (req, res) => {
    const { title, loginUserName, description, status } = req.body;
    const createdAt = new Date().toLocaleString();
    const updatedAt = new Date().toLocaleString();
    try {
        const userId = await getUserId(loginUserName);
        const sql = `INSERT INTO Tasks (title, description, status, assignee_id, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?)`;
        await db.run(sql, [title, description, status, userId, createdAt, updatedAt]);
        res.json("Data Added Successfully.");
    } catch (error) {
        console.error("Error adding task:", error);
        res.status(500).json("Internal Server Error");
    }
});

async function getUserId(loginUserName) {
    return new Promise((resolve, reject) => {
        db.get(`SELECT id FROM users WHERE username = ?`, [loginUserName], (err, row) => {
            if (err) {
                reject(err);
            } else if (row) {
                resolve(row.id);
            } else {
                reject(new Error("User not found"));
            }
        });
    });
}

app.get("/getalltasks", authenticateToken, async (req, res) => {
    try {
        const rows = await db.all('SELECT * FROM Tasks');
        res.json({ rows });
    } catch (error) {
        console.error("Error fetching tasks:", error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete("/tasks/:id", authenticateToken, (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM Tasks WHERE id = ?`, [id], (err) => {
        if (err) {
            res.status(500).json("Error deleting task");
        } else {
            res.json("Task Deleted Successfully.");
        }
    });
});

app.put("/tasks/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title, description, status } = req.body;
    const time = new Date().toLocaleString();
    db.run(`UPDATE Tasks SET title = ?, description = ?, status = ?, updated_at = ? WHERE id = ?`,
        [title, description, status, time, id], (err) => {
            if (err) {
                console.error(err);
                res.status(500).json("Internal Server Error");
            } else {
                res.json("Task Updated Successfully.");
            }
        });
});

app.get('/tasks/search', authenticateToken, async (req, res) => {
    const { query } = req.query;
    db.get(`SELECT id FROM users WHERE username = ?`, [query], (err, row) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (!row) {
            return res.status(404).json({ error: 'User not found' });
        }
        const userId = row.id;
        db.all(`SELECT *, (SELECT COUNT(*) FROM Tasks WHERE assignee_id = ?) AS count
                 FROM Tasks WHERE assignee_id = ?`, [userId, userId], (err, rows) => {
            if (err) {
                console.error(err.message);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            res.json({ tasks: rows, count: rows.length > 0 ? rows[0].count : 0 });
        });
    });
});

app.listen(3001, () => {
    console.log(`Server is running on port http://localhost:3001`);
});
