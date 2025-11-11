const mongoose = require('mongoose');

const studentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  rollNumber: { type: String, required: true, unique: true },
  photo: { type: String },
});

// ✅ Prevent OverwriteModelError
module.exports = mongoose.models.Student || mongoose.model('Student', studentSchema);
