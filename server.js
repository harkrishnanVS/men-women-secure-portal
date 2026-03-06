console.log('IMPORT: Start of server.js');
require('dotenv').config();
console.log('IMPORT: dotenv loaded');
const express = require('express');
console.log('IMPORT: express loaded');
const cors = require('cors');
console.log('IMPORT: cors loaded');
const bcrypt = require('bcryptjs');
console.log('IMPORT: bcryptjs loaded');
const jwt = require('jsonwebtoken');
console.log('IMPORT: jsonwebtoken loaded');
const db = require('./database');
console.log('IMPORT: database loaded');
const crypto = require('crypto');
console.log('IMPORT: crypto loaded');
const nodemailer = require('nodemailer');
console.log('IMPORT: nodemailer loaded');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-tn-portal';
console.log('CONFIG: PORT=' + PORT);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files (assuming they are in the same or 'public' directory)
// For now, let's just serve the root directory where html files are
app.use(express.static(__dirname));

// Utility: Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
};

// Utility: Optional Authentication Middleware (for public routes that can also accept logged-in users)
const optionalAuthenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        req.user = null;
        return next();
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (!err) {
            req.user = user;
        } else {
            req.user = null;
        }
        next();
    });
};

// ==========================================
// ROUTES: AUTHENTICATION
// ==========================================

// In-memory OTP store for simulated local testing
const otpStore = new Map();

// 1. Send Simulated OTP
app.post('/api/auth/send-otp', async (req, res) => {
    const { mobile } = req.body;
    if (!mobile) return res.status(400).json({ error: 'Mobile number is required.' });

    // Generate a 6 digit code
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store it with a 5 minute expiry
    otpStore.set(mobile, { otp, expires: Date.now() + 5 * 60 * 1000 });

    console.log(`\n========================================`);
    console.log(`🔥 SIMULATED OTP FOR ${mobile}: ${otp} 🔥`);
    console.log(`========================================\n`);

    // In a real app we'd trigger a Twilio/Msg91 API here
    res.json({ message: 'OTP sent successfully (Check server terminal)' });
});

// 2. Register (Verify OTP and Create Account)
app.post('/api/auth/register', async (req, res) => {
    const { name, mobile, password, otp } = req.body;

    if (!name || !mobile || !password || !otp) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    // Verify OTP
    const storedOtpData = otpStore.get(mobile);
    if (!storedOtpData) {
        return res.status(400).json({ error: 'No OTP requested or OTP expired.' });
    }
    if (Date.now() > storedOtpData.expires) {
        otpStore.delete(mobile);
        return res.status(400).json({ error: 'OTP has expired.' });
    }
    if (storedOtpData.otp !== otp) {
        return res.status(400).json({ error: 'Invalid OTP.' });
    }

    // Check if user exists
    db.get('SELECT mobile FROM users WHERE mobile = ?', [mobile], async (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (row) return res.status(400).json({ error: 'Mobile number is already registered.' });

        try {
            const hashedPassword = await bcrypt.hash(password, 10);

            db.run('INSERT INTO users (name, mobile, password) VALUES (?, ?, ?)', [name, mobile, hashedPassword], function (err) {
                if (err) {
                    return res.status(500).json({ error: 'Could not create account in database.' });
                }
                
                // Clear OTP after successful registration
                otpStore.delete(mobile);
                
                res.status(201).json({ message: 'Account Created Successfully!' });
            });
        } catch (error) {
            console.error('Error generating request:', error);
            res.status(500).json({ error: 'Server error generating request' });
        }
    });
});

// 3. Login
app.post('/api/auth/login', (req, res) => {
    const { mobile, password } = req.body;

    db.get('SELECT * FROM users WHERE mobile = ?', [mobile], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign({ id: user.id, mobile: user.mobile, name: user.name }, JWT_SECRET, { expiresIn: '2h' });

        res.json({ message: 'Login successful', token, name: user.name, mobile: user.mobile });
    });
});

// 4. Password Reset Modify (OTP verified by backend now)
app.post('/api/auth/reset-password', async (req, res) => {
    const { mobile, newPassword, otp } = req.body;

    if (!mobile || !newPassword || !otp) return res.status(400).json({ error: 'All fields required.' });

    // Verify OTP
    const storedOtpData = otpStore.get(mobile);
    if (!storedOtpData) {
        return res.status(400).json({ error: 'No OTP requested or OTP expired.' });
    }
    if (Date.now() > storedOtpData.expires) {
        otpStore.delete(mobile);
        return res.status(400).json({ error: 'OTP has expired.' });
    }
    if (storedOtpData.otp !== otp) {
        return res.status(400).json({ error: 'Invalid OTP.' });
    }

    db.get('SELECT mobile FROM users WHERE mobile = ?', [mobile], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(404).json({ error: 'Mobile number not registered.' });

        try {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            db.run('UPDATE users SET password = ? WHERE mobile = ?', [hashedPassword, mobile], function (err) {
                if (err) return res.status(500).json({ error: 'Error updating password.' });
                
                // Clear OTP after successful reset
                otpStore.delete(mobile);
                
                res.json({ message: 'Password updated successfully.' });
            });
        } catch (e) {
            res.status(500).json({ error: 'Internal server error.' });
        }
    });
});


// ==========================================
// ROUTES: COMPLAINTS 
// ==========================================

// 1. Submit a generic complaint
app.post('/api/complaints', optionalAuthenticateToken, (req, res) => {
    // Note: This API accepts non-authenticated requests for anonymity if needed, but attaches mobile if user is authenticated
    const { type, location, date, description } = req.body;
    const user_mobile = req.user ? req.user.mobile : null;
    const trackingId = crypto.randomUUID().slice(0, 10).toUpperCase();

    // Verify fields
    if (!type || !location || !date || !description) {
        return res.status(400).json({ error: 'Missing required complaint fields.' });
    }

    db.run(
        'INSERT INTO complaints (tracking_id, user_mobile, type, location, date, description) VALUES (?, ?, ?, ?, ?, ?)',
        [trackingId, user_mobile, type, location, date, description],
        function (err) {
            if (err) return res.status(500).json({ error: 'Failed to submit complaint.' });
            res.status(201).json({ message: 'Complaint filed securely.', tracking_id: trackingId });
        }
    );
});

// 2. Track complaint by ID (Public Access)
app.get('/api/complaints/:trackingId', (req, res) => {
    const trackingId = req.params.trackingId.toUpperCase();
    db.get('SELECT tracking_id, status, submitted_at FROM complaints WHERE tracking_id = ?', [trackingId], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!row) return res.status(404).json({ error: 'Tracking ID not found.' });

        res.json(row);
    });
});

// 3. User's specific complaints (Protected)
app.get('/api/user/complaints', authenticateToken, (req, res) => {
    const mobile = req.user.mobile;
    db.all('SELECT * FROM complaints WHERE user_mobile = ? ORDER BY submitted_at DESC', [mobile], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});


// ==========================================
// ROUTES: COUNSELING APPOINTMENTS
// ==========================================

// 1. Book an appointment (Protected)
app.post('/api/appointments', authenticateToken, (req, res) => {
    const { date, time, counselor } = req.body;
    const mobile = req.user.mobile;

    if (!date || !time) {
        return res.status(400).json({ error: 'Date and time are required.' });
    }

    db.run(
        'INSERT INTO appointments (user_mobile, counselor, date, time) VALUES (?, ?, ?, ?)',
        [mobile, counselor || 'Unassigned', date, time],
        function (err) {
            if (err) return res.status(500).json({ error: 'Failed to book appointment.' });
            res.status(201).json({ message: 'Appointment Confirmed.', id: this.lastID });
        }
    );
});

// 2. Fetch user's appointments (Protected)
app.get('/api/user/appointments', authenticateToken, (req, res) => {
    const mobile = req.user.mobile;
    db.all('SELECT * FROM appointments WHERE user_mobile = ? ORDER BY booked_at DESC', [mobile], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});


// ==========================================
// SERVER START
// ==========================================
app.listen(PORT, () => {
    console.log(`Backend Server running securely on http://localhost:${PORT}`);
    console.log(`Static file paths mapping to: ${__dirname}`);
});
