import connectDB from '../../utils/connectDB';
import User from '../../models/User';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

connectDB();

export default async function handler(req, res) {
  if (req.method === 'POST') {
    const { action, username, password, referCode } = req.body;

    if(action === 'register') {
      try {
        const existingUser = await User.findOne({ username });
        if(existingUser) return res.status(400).json({ msg: 'Username exists' });
        const user = new User({ username, password, referCode });
        await user.save();
        return res.status(201).json({ msg: 'User registered' });
      } catch(err) { return res.status(500).json({ msg: err.message }); }
    }

    if(action === 'login') {
      try {
        const user = await User.findOne({ username });
        if(!user) return res.status(400).json({ msg: 'User not found' });
        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch) return res.status(400).json({ msg: 'Invalid password' });
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        return res.status(200).json({ token, user });
      } catch(err) { return res.status(500).json({ msg: err.message }); }
    }

    return res.status(400).json({ msg: 'Invalid action' });
  }

  res.status(405).end();
}
