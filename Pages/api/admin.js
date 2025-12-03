import connectDB from '../../utils/connectDB';
import Admin from '../../models/Admin';
import User from '../../models/User';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

connectDB();

export default async function handler(req, res) {
  const { action, adminId, password } = req.body;

  if(action === 'setup') {
    try {
      const existing = await Admin.findOne({ adminId });
      if(existing) return res.status(400).json({ msg: 'Admin exists' });
      const admin = new Admin({ adminId, password });
      await admin.save();
      return res.status(201).json({ msg: 'Admin created' });
    } catch(err) { return res.status(500).json({ msg: err.message }); }
  }

  if(action === 'login') {
    try {
      const admin = await Admin.findOne({ adminId });
      if(!admin) return res.status(400).json({ msg: 'Admin not found' });
      const isMatch = await bcrypt.compare(password, admin.password);
      if(!isMatch) return res.status(400).json({ msg: 'Invalid password' });
      const token = jwt.sign({ id: admin._id, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '7d' });
      return res.status(200).json({ token, admin });
    } catch(err) { return res.status(500).json({ msg: err.message }); }
  }

  if(action === 'dashboard') {
    try {
      const users = await User.find();
      return res.status(200).json({ users });
    } catch(err) { return res.status(500).json({ msg: err.message }); }
  }

  res.status(400).json({ msg: 'Invalid action' });
}
