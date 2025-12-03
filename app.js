// app.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- MongoDB Connection ---
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(()=> console.log('MongoDB Connected'))
  .catch(err=> console.log(err));

// --- Models ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    dailyIncome: { type: Number, default: 0 },
    rank: { type: String, default: 'LV1' },
    referCode: { type: String, unique: true },
});

const adminSchema = new mongoose.Schema({
    adminId: { type: String, required: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);

// --- Middleware ---
const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// --- Routes ---
// User Register
app.post('/api/register', async (req, res) => {
    const { username, password, referCode } = req.body;
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ msg: 'Username already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, referCode });
        await newUser.save();
        res.json({ msg: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ msg: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid password' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, user });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// Protected User Dashboard
app.get('/api/dashboard', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.json({ user });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// Admin Setup (Run Once)
app.post('/api/admin/setup', async (req, res) => {
    const { adminId, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const admin = new Admin({ adminId, password: hashedPassword });
        await admin.save();
        res.json({ msg: 'Admin created' });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    const { adminId, password } = req.body;
    try {
        const admin = await Admin.findOne({ adminId });
        if (!admin) return res.status(400).json({ msg: 'Admin not found' });

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid password' });

        const token = jwt.sign({ id: admin._id, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, admin });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// Protected Admin Dashboard
app.get('/api/admin/dashboard', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Access denied' });
        const users = await User.find();
        res.json({ users });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// --- Server Start ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
