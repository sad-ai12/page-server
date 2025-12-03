import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const AdminSchema = new mongoose.Schema({
  adminId: { type: String, required: true },
  password: { type: String, required: true },
});

AdminSchema.pre('save', async function(next){
  if(!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

export default mongoose.models.Admin || mongoose.model('Admin', AdminSchema);
