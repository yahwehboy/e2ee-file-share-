const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '')));

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// Initialize SQLite database
const db = new sqlite3.Database('secure_file_share.db');

// Encryption/Decryption helper functions
function encryptFile(buffer, encryptionKey) {
  const algorithm = 'aes-256-cbc';
  const iv = crypto.randomBytes(16); // Initialization vector
  const key = crypto.createHash('sha256').update(encryptionKey).digest(); // Create a 32-byte key
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(buffer);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return { data: encrypted, iv: iv };
}

function decryptFile(encryptedData, iv, encryptionKey) {
  const algorithm = 'aes-256-cbc';
  const key = crypto.createHash('sha256').update(encryptionKey).digest(); // Create a 32-byte key
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encryptedData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted;
}

// Generate a random encryption key for each file
function generateFileEncryptionKey() {
  return crypto.randomBytes(32).toString('hex'); // 256-bit key
}

// Create tables if they don't exist
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Files table
  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    type TEXT NOT NULL,
    path TEXT NOT NULL,
    encryption_key TEXT NOT NULL,
    iv TEXT NOT NULL,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Shared files table
  db.run(`CREATE TABLE IF NOT EXISTS shared_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    shared_with_user_id INTEGER NOT NULL,
    permission TEXT DEFAULT 'read',
    shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES files (id),
    FOREIGN KEY (shared_with_user_id) REFERENCES users (id),
    UNIQUE(file_id, shared_with_user_id)
  )`);
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Register new user
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // In a real application, you would generate actual RSA key pairs
    // For this demo, we'll use placeholder values
    const publicKey = `dummy_public_key_${Date.now()}`;
    const privateKey = `dummy_private_key_${Date.now()}`;

    // Insert user into database
    const stmt = db.prepare('INSERT INTO users (username, email, password, public_key, private_key) VALUES (?, ?, ?, ?, ?)');
    stmt.run(username, email, hashedPassword, publicKey, privateKey, function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          res.status(400).json({ message: 'Username or email already exists.' });
        } else {
          res.status(500).json({ message: err.message });
        }
      } else {
        // Generate JWT token
        const token = jwt.sign(
          { userId: this.lastID, username },
          process.env.JWT_SECRET || 'fallback_secret_key',
          { expiresIn: '24h' }
        );
        
        res.status(201).json({ 
          message: 'User registered successfully',
          token,
          user: { id: this.lastID, username, email }
        });
      }
    });
    stmt.finalize();
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Login user
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  // Get user from database
  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  stmt.get([email], async (err, user) => {
    if (err) {
      res.status(500).json({ message: err.message });
      return;
    }

    if (!user) {
      res.status(400).json({ message: 'Invalid email or password.' });
      return;
    }

    // Check password
    try {
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        res.status(400).json({ message: 'Invalid email or password.' });
        return;
      }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, username: user.username },
        process.env.JWT_SECRET || 'fallback_secret_key',
        { expiresIn: '24h' }
      );

      res.json({
        message: 'Login successful',
        token,
        user: { id: user.id, username: user.username, email: user.email }
      });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  });
  stmt.finalize();
});

// Get current user's files
app.get('/api/files', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  
  // Get files owned by the user or shared with the user
  const query = `
    SELECT f.*, u.username as owner_name 
    FROM files f
    JOIN users u ON f.user_id = u.id
    WHERE f.user_id = ?
    UNION
    SELECT f.*, u.username as owner_name
    FROM files f
    JOIN shared_files sf ON f.id = sf.file_id
    JOIN users u ON f.user_id = u.id
    JOIN users shared_user ON sf.shared_with_user_id = shared_user.id
    WHERE sf.shared_with_user_id = ?
  `;
  
  db.all(query, [userId, userId], (err, rows) => {
    if (err) {
      res.status(500).json({ message: err.message });
      return;
    }
    
    // For each file, get the sharing information
    const filesWithSharing = rows.map(file => {
      // Get sharing information for the file
      return new Promise((resolve) => {
        const sharingQuery = `
          SELECT sf.permission, u.username, u.email
          FROM shared_files sf
          JOIN users u ON sf.shared_with_user_id = u.id
          WHERE sf.file_id = ?
        `;
        
        db.all(sharingQuery, [file.id], (err, sharedWith) => {
          if (err) {
            console.error(err);
            file.sharedWith = [];
            resolve(file);
          } else {
            file.sharedWith = sharedWith;
            resolve(file);
          }
        });
      });
    });
    
    Promise.all(filesWithSharing).then(completedRows => {
      res.json(completedRows);
    });
  });
});

// Upload file
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded.' });
  }

  const userId = req.user.userId;
  const { originalname, size, mimetype } = req.file;
  const filePath = req.file.path;
  
  // Sanitize the original filename to remove any trailing spaces or special characters
  const sanitizedOriginalName = originalname.trim();
  
  // Read the file content
  fs.readFile(filePath, (err, fileBuffer) => {
    if (err) {
      return res.status(500).json({ message: 'Error reading file.' });
    }
    
    // Generate a unique encryption key for this file
    const encryptionKey = generateFileEncryptionKey();
    
    // Encrypt the file content
    const encryptedResult = encryptFile(fileBuffer, encryptionKey);
    const encryptedBuffer = encryptedResult.data;
    const iv = encryptedResult.iv;
    
    // Generate a unique filename for the encrypted file
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const encryptedFilename = uniqueSuffix + '.enc';
    const encryptedFilePath = path.join(__dirname, 'uploads', encryptedFilename);
    
    // Save encrypted file to disk
    fs.writeFile(encryptedFilePath, encryptedBuffer, (err) => {
      if (err) {
        return res.status(500).json({ message: 'Error saving encrypted file.' });
      }
      
      // Delete the original unencrypted file
      fs.unlink(filePath, (err) => {
        if (err) {
          console.error('Error deleting original file:', err);
        }
      });
      
      // Store file metadata in the database (including IV for decryption)
      const stmt = db.prepare(`
        INSERT INTO files (user_id, filename, original_name, size, type, path, encryption_key, iv)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      
      stmt.run(userId, encryptedFilename, sanitizedOriginalName, size, mimetype, encryptedFilePath, encryptionKey, iv.toString('hex'), function(err) {
        if (err) {
          // Clean up the encrypted file if database insertion fails
          fs.unlink(encryptedFilePath, () => {}); // Ignore errors during cleanup
          res.status(500).json({ message: err.message });
        } else {
          res.status(201).json({
            message: 'File uploaded and encrypted successfully',
            fileId: this.lastID,
            filename: originalname,
            size: size
          });
        }
      });
      stmt.finalize();
    });
  });
});

// Get file details
app.get('/api/files/:id', authenticateToken, (req, res) => {
  const fileId = req.params.id;
  const userId = req.user.userId;
  
  // Check if user owns the file or has access to it
  const query = `
    SELECT f.*, u.username as owner_name
    FROM files f
    JOIN users u ON f.user_id = u.id
    WHERE f.id = ?
    AND (f.user_id = ? OR f.id IN (
      SELECT sf.file_id FROM shared_files sf WHERE sf.shared_with_user_id = ?
    ))
  `;
  
  db.get(query, [fileId, userId, userId], (err, row) => {
    if (err) {
      res.status(500).json({ message: err.message });
      return;
    }
    
    if (!row) {
      res.status(404).json({ message: 'File not found or access denied.' });
      return;
    }
    
    // Get sharing information
    const sharingQuery = `
      SELECT sf.permission, u.username, u.email
      FROM shared_files sf
      JOIN users u ON sf.shared_with_user_id = u.id
      WHERE sf.file_id = ?
    `;
    
    db.all(sharingQuery, [row.id], (err, sharedWith) => {
      if (err) {
        console.error('Error fetching sharing info:', err);
        row.sharedWith = [];
      } else {
        row.sharedWith = sharedWith;
      }
      
      res.json(row);
    });
  });
});

// Download file - decrypts the file before sending to user
app.get('/api/files/:id/download', (req, res) => {
  // Check if token is provided in query parameters or headers
  let token = req.headers['authorization'];
  if (!token && req.query.token) {
    token = req.query.token;
    if (typeof token === 'string' && !token.startsWith('Bearer ')) {
      token = `Bearer ${token}`;
    }
  }
  
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  // Extract token from header format if needed  
  if (typeof token === 'string' && token.startsWith('Bearer ')) {
    token = token.split(' ')[1];
  }

  // Verify JWT token
  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }
    
    const userId = user.userId;
    const fileId = req.params.id;
    
    // Check if user owns the file or has access to it
    const query = `
      SELECT f.*, u.username as owner_name
      FROM files f
      JOIN users u ON f.user_id = u.id
      WHERE f.id = ?
      AND (f.user_id = ? OR f.id IN (
        SELECT sf.file_id FROM shared_files sf WHERE sf.shared_with_user_id = ?
      ))
    `;
    
    db.get(query, [fileId, userId, userId], (err, row) => {
      if (err) {
        res.status(500).json({ message: err.message });
        return;
      }
      
      if (!row) {
        res.status(404).json({ message: 'File not found or access denied.' });
        return;
      }
      
      // The row.path already contains the full path to the encrypted file
      const encryptedFilePath = row.path;
      
      if (!fs.existsSync(encryptedFilePath)) {
        res.status(404).json({ message: 'File not found on disk.' });
        return;
      }
      
      // Read the encrypted file content
      fs.readFile(encryptedFilePath, (err, encryptedBuffer) => {
        if (err) {
          res.status(500).json({ message: 'Error reading encrypted file.' });
          return;
        }
        
        try {
          // Extract the IV from the database record
          const iv = Buffer.from(row.iv, 'hex');
          
          // Decrypt the file content
          const decryptedBuffer = decryptFile(encryptedBuffer, iv, row.encryption_key);
          
          // Create a temporary file with a unique name and proper extension
          const fileExt = path.extname(row.original_name);
          const tempFileName = path.join(__dirname, 'uploads', `temp_${Date.now()}_${Math.random().toString(36).substring(2, 10)}${fileExt}`);
          
          // Write the decrypted content to the temp file
          fs.writeFile(tempFileName, decryptedBuffer, (err) => {
            if (err) {
              res.status(500).json({ message: 'Error creating temporary file for download.' });
              return;
            }
            
            // Use res.download to properly handle the filename
            res.download(tempFileName, row.original_name, (err) => {
              // Clean up the temporary file after download
              fs.unlink(tempFileName, (cleanupErr) => {
                if (cleanupErr) {
                  console.error('Error deleting temporary file:', cleanupErr);
                }
              });
            });
          });
        } catch (decryptErr) {
          console.error('Decryption error:', decryptErr);
          res.status(500).json({ message: 'Error decrypting file.' });
        }
      });
    });
  });


// Share file with another user
app.post('/api/files/:id/share', authenticateToken, (req, res) => {
  const fileId = req.params.id;
  const { userId: targetUserId, permission, isEmail } = req.body;
  const requestingUserId = req.user.userId;
  
  // If the userId is actually an email, find the user ID
  let actualTargetUserId = targetUserId;
  
  if (isEmail) {
    const findUserStmt = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?');
    findUserStmt.get([targetUserId, requestingUserId], (err, user) => {
      if (err) {
        res.status(500).json({ message: err.message });
        return;
      }
      
      if (!user) {
        res.status(404).json({ message: 'User not found with that email.' });
        return;
      }
      
      actualTargetUserId = user.id;
      proceedWithSharing(actualTargetUserId);
    });
  } else {
    proceedWithSharing(actualTargetUserId);
  }
  
  function proceedWithSharing(targetUserId) {
    // Check if the file exists and the requesting user is the owner
    const checkStmt = db.prepare(`
      SELECT id FROM files WHERE id = ? AND user_id = ?
    `);
    
    checkStmt.get([fileId, requestingUserId], (err, row) => {
      if (err) {
        res.status(500).json({ message: err.message });
        return;
      }
      
      if (!row) {
        res.status(403).json({ message: 'Access denied. You can only share files you own.' });
        return;
      }
      
      // Insert the share record
      const shareStmt = db.prepare(`
        INSERT OR REPLACE INTO shared_files (file_id, shared_with_user_id, permission)
        VALUES (?, ?, ?)
      `);
      
      shareStmt.run([fileId, targetUserId, permission || 'read'], function(err) {
        if (err) {
          res.status(500).json({ message: err.message });
        } else {
          res.json({ message: 'File shared successfully' });
        }
      });
      shareStmt.finalize();
    });
    checkStmt.finalize();
  }
});

// Delete a file
app.delete('/api/files/:id', authenticateToken, (req, res) => {
  const fileId = req.params.id;
  const userId = req.user.userId;
  
  // Check if the user owns the file (only owners can delete)
  const checkStmt = db.prepare(`
    SELECT id, path FROM files WHERE id = ? AND user_id = ?
  `);
  
  checkStmt.get([fileId, userId], (err, row) => {
    if (err) {
      res.status(500).json({ message: err.message });
      return;
    }
    
    if (!row) {
      res.status(403).json({ message: 'Access denied. You can only delete files you own.' });
      return;
    }
    
    // Delete from shared_files table first (due to foreign key constraint)
    const deleteSharedStmt = db.prepare(`
      DELETE FROM shared_files WHERE file_id = ?
    `);
    
    deleteSharedStmt.run([fileId], function(sharedErr) {
      if (sharedErr) {
        res.status(500).json({ message: sharedErr.message });
        return;
      }
      
      // Delete the file record
      const deleteFileStmt = db.prepare(`
        DELETE FROM files WHERE id = ?
      `);
      
      deleteFileStmt.run([fileId], function(fileErr) {
        if (fileErr) {
          res.status(500).json({ message: fileErr.message });
          return;
        }
        
        // Also delete the physical file if it exists
        const filePath = path.join(__dirname, row.path);
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
        
        res.json({ message: 'File deleted successfully' });
      });
      
      deleteFileStmt.finalize();
    });
    
    deleteSharedStmt.finalize();
  });
  
  checkStmt.finalize();
});

// Search users by email or username
app.get('/api/users/search', authenticateToken, (req, res) => {
  const query = req.query.query;
  const userId = req.user.userId;
  
  if (!query) {
    return res.status(400).json({ message: 'Query parameter is required' });
  }
  
  // Search for users by email or username (excluding current user)
  const searchStmt = db.prepare(`
    SELECT id, username, email 
    FROM users 
    WHERE (username LIKE ? OR email LIKE ?) AND id != ?
    LIMIT 10
  `);
  
  searchStmt.all(['%' + query + '%', '%' + query + '%', userId], (err, rows) => {
    if (err) {
      res.status(500).json({ message: err.message });
      return;
    }
    
    res.json(rows);
  });
  
  searchStmt.finalize();
});

// Main route to serve the HTML page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Access the application at http://localhost:${PORT}`);
});
