const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const Student = require('../models/student');

// Set up file upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/student_photos');
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});
const upload = multer({ storage });

// Route: Add student
router.post('/add', upload.single('photo'), async (req, res) => {
  try {
    const { name, rollNumber } = req.body;
    const photo = req.file ? req.file.path : null;

    const student = new Student({ name, rollNumber, photo });
    await student.save();

    res.status(201).json({ message: 'Student added successfully', student });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Route: Get all students
router.get('/', async (req, res) => {
  try {
    const students = await Student.find();
    res.json(students);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
