// models/User.js
import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  securityQuestion: { type: String, required: true },
  securityAnswer: { type: String, required: true }
}, {
  collection: 'usuarios'  // Nombre explícito de la colección
});

const User = mongoose.model('User', userSchema);
export default User;


