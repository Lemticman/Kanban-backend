const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

// AUTO DATABASE SETUP FUNCTION
async function setupDatabaseOnStartup() {
  try {
    console.log('🔧 Checking database setup...');

    // Check if users table exists
    const tableCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'users'
      );
    `);

    if (!tableCheck.rows[0].exists) {
      console.log('📊 Creating database tables...');
      
      // Create business_units table
      await pool.query(`
        CREATE TABLE business_units (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL UNIQUE,
          description TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

      // Create users table
      await pool.query(`
        CREATE TABLE users (
          id SERIAL PRIMARY KEY,
          username VARCHAR(50) NOT NULL UNIQUE,
          password_hash VARCHAR(255) NOT NULL,
          name VARCHAR(255) NOT NULL,
          role VARCHAR(50) NOT NULL DEFAULT 'user',
          business_unit VARCHAR(50) DEFAULT 'corporate',
          is_active BOOLEAN DEFAULT true,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

      // Create tasks table
      await pool.query(`
        CREATE TABLE tasks (
          id SERIAL PRIMARY KEY,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          status VARCHAR(20) DEFAULT 'todo' CHECK (status IN ('todo', 'inprogress', 'review', 'done')),
          priority VARCHAR(10) DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high')),
          assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
          created_by_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          due_date DATE,
          completed_at TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

      // Create indexes
      await pool.query(`
        CREATE INDEX idx_tasks_status ON tasks(status);
        CREATE INDEX idx_tasks_assignee ON tasks(assignee_id);
        CREATE INDEX idx_tasks_created_by ON tasks(created_by_id);
        CREATE INDEX idx_users_username ON users(username);
        CREATE INDEX idx_users_active ON users(is_active);
      `);

      console.log('✅ Database tables created successfully');

      // Insert business units
      await pool.query(`
        INSERT INTO business_units (name, description) VALUES
          ('Corporate', 'Corporate headquarters'),
          ('Leasing', 'Property leasing division'),
          ('Abattoir', 'Meat processing facility'),
          ('GenMeat', 'General meat products'),
          ('Porkland', 'Pork processing division'),
          ('RANC', 'Regional agricultural network'),
          ('GreenAtom', 'Sustainable agriculture division');
      `);

      // Hash passwords for demo users
      const adminPassword = await bcrypt.hash('admin123', 10);
      const userPassword = await bcrypt.hash('user123', 10);

      // Insert demo users
      await pool.query(`
        INSERT INTO users (username, password_hash, name, role, business_unit) VALUES
          ('admin', $1, 'System Administrator', 'admin', 'corporate'),
          ('john', $2, 'John Smith', 'user', 'corporate'),
          ('jane', $2, 'Jane Doe', 'business-manager', 'leasing'),
          ('mike', $2, 'Mike Johnson', 'user', 'abattoir'),
          ('sarah', $2, 'Sarah Wilson', 'business-manager', 'genmeat');
      `, [adminPassword, userPassword]);

      // Insert sample tasks
      await pool.query(`
        INSERT INTO tasks (title, description, status, priority, assignee_id, created_by_id, due_date, completed_at) VALUES
          ('Welcome to Railway Kanban!', 'This is your first task. You can drag it between columns or use the buttons below.', 'todo', 'medium', 1, 1, CURRENT_DATE + INTERVAL '7 days', NULL),
          ('Set up Railway database', 'Connect your application to Railway PostgreSQL for persistent storage.', 'done', 'high', 1, 1, CURRENT_DATE - INTERVAL '1 day', NOW()),
          ('Test drag and drop functionality', 'Make sure tasks can be moved between columns smoothly.', 'inprogress', 'medium', 2, 1, CURRENT_DATE + INTERVAL '3 days', NULL),
          ('Review user permissions', 'Ensure users can only see and modify appropriate tasks.', 'review', 'high', 3, 1, CURRENT_DATE + INTERVAL '5 days', NULL),
          ('Create your first real task', 'Use the form above to create a new task and assign it to a team member.', 'todo', 'low', 2, 1, CURRENT_DATE + INTERVAL '10 days', NULL);
      `);

      console.log('🎉 Demo data inserted successfully!');
      console.log('👥 Demo accounts created:');
      console.log('   admin / admin123 (Administrator)');
      console.log('   john / user123 (User)');
      console.log('   jane / user123 (Business Manager)');
      console.log('   mike / user123 (User)');
      console.log('   sarah / user123 (Business Manager)');

    } else {
      console.log('✅ Database tables already exist');
    }

  } catch (error) {
    console.error('❌ Database setup error:', error);
    // Don't exit - let the server start anyway
  }
}

// Test database connection and setup
pool.connect(async (err, client, release) => {
  if (err) {
    console.error('❌ Error connecting to PostgreSQL:', err);
    process.exit(1);
  } else {
    console.log('✅ Connected to Railway PostgreSQL');
    release();
    
    // Run database setup after successful connection
    await setupDatabaseOnStartup();
  }
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ===== ROUTES =====

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    service: 'Kanban API',
    version: '1.0.0'
  });
});

// ===== AUTHENTICATION ROUTES =====

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1 AND is_active = true',
      [username.toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Remove password from response
    delete user.password_hash;

    res.json({
      message: 'Login successful',
      token,
      user
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===== USER ROUTES =====

// Get all users
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, name, role, business_unit, is_active, created_at FROM users WHERE is_active = true ORDER BY name'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get current user info
app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, name, role, business_unit, is_active, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ error: 'Failed to fetch user info' });
  }
});

// ===== TASK ROUTES =====

// Get all tasks
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    let query = `
      SELECT t.*, 
             u1.name as assignee_name,
             u2.name as created_by_name
      FROM tasks t
      LEFT JOIN users u1 ON t.assignee_id = u1.id
      LEFT JOIN users u2 ON t.created_by_id = u2.id
      ORDER BY t.created_at DESC
    `;
    
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Get tasks error:', error);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

// Get task by ID
app.get('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT t.*, 
              u1.name as assignee_name,
              u2.name as created_by_name
       FROM tasks t
       LEFT JOIN users u1 ON t.assignee_id = u1.id
       LEFT JOIN users u2 ON t.created_by_id = u2.id
       WHERE t.id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get task error:', error);
    res.status(500).json({ error: 'Failed to fetch task' });
  }
});

// Create new task
app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const {
      title,
      description,
      priority,
      assignee_id,
      due_date
    } = req.body;

    if (!title || !priority) {
      return res.status(400).json({ error: 'Title and priority are required' });
    }

    const result = await pool.query(
      `INSERT INTO tasks (title, description, priority, assignee_id, created_by_id, due_date, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'todo')
       RETURNING *`,
      [title, description, priority, assignee_id || null, req.user.id, due_date || null]
    );

    res.status(201).json({
      message: 'Task created successfully',
      task: result.rows[0]
    });

  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

// Update task
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      title,
      description,
      priority,
      assignee_id,
      due_date,
      status
    } = req.body;

    // Build dynamic update query
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (title !== undefined) {
      updates.push(`title = $${paramCount++}`);
      values.push(title);
    }
    if (description !== undefined) {
      updates.push(`description = $${paramCount++}`);
      values.push(description);
    }
    if (priority !== undefined) {
      updates.push(`priority = $${paramCount++}`);
      values.push(priority);
    }
    if (assignee_id !== undefined) {
      updates.push(`assignee_id = $${paramCount++}`);
      values.push(assignee_id);
    }
    if (due_date !== undefined) {
      updates.push(`due_date = $${paramCount++}`);
      values.push(due_date);
    }
    if (status !== undefined) {
      updates.push(`status = $${paramCount++}`);
      values.push(status);
      
      // If status is 'done', set completed_at
      if (status === 'done') {
        updates.push(`completed_at = $${paramCount++}`);
        values.push(new Date());
      } else if (status !== 'done') {
        updates.push(`completed_at = NULL`);
      }
    }

    updates.push(`updated_at = $${paramCount++}`);
    values.push(new Date());

    values.push(id);

    const query = `
      UPDATE tasks 
      SET ${updates.join(', ')}
      WHERE id = $${paramCount}
      RETURNING *
    `;

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    res.json({
      message: 'Task updated successfully',
      task: result.rows[0]
    });

  } catch (error) {
    console.error('Update task error:', error);
    res.status(500).json({ error: 'Failed to update task' });
  }
});

// Delete task
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM tasks WHERE id = $1 RETURNING *',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    res.json({ message: 'Task deleted successfully' });

  } catch (error) {
    console.error('Delete task error:', error);
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

// ===== BUSINESS UNITS ROUTES =====

// Get all business units
app.get('/api/business-units', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM business_units ORDER BY name'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get business units error:', error);
    res.status(500).json({ error: 'Failed to fetch business units' });
  }
});

// ===== ERROR HANDLING =====

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚂 Railway Kanban API server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});
