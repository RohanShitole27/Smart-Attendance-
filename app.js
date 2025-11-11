const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Load environment variables
dotenv.config();

const app = express();

// ==================== CONFIGURATION ====================

const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/attendance-system';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Create upload directory if it doesn't exist
const uploadDir = path.join(__dirname, 'uploads/student_photos');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// ==================== MIDDLEWARE ====================

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use('/uploads', express.static('uploads'));

const studentRoutes = require('./routes/studentroutes');
app.use('/api/students', studentRoutes);


fetch("http://localhost:5000/api/attendance", {
  method: "POST",
//   body: formData
})
.then(res => res.json())
.then(data => {
  console.log("Server response:", data);
  alert("Image uploaded successfully!");
})
.catch(err => {
  console.error("Upload error:", err);
});



// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'student-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Images only (JPEG, JPG, PNG)'));
        }
    }
});

// ==================== MONGOOSE SCHEMAS ====================

// User Schema (for teachers/admin)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: String,
    role: { type: String, enum: ['teacher', 'admin', 'parent'], default: 'teacher' },
    assignedClasses: [String],
    createdAt: { type: Date, default: Date.now }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        return next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Method to compare password
userSchema.methods.matchPassword = async function(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

// Student Schema
const studentSchema = new mongoose.Schema({
    studentId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    rollNo: { type: Number, required: true },
    class: { type: String, required: true },
    email: String,
    parentEmail: String,
    photoPath: String,
    faceDescriptor: [Number], // Store 128 descriptor values from Face-API
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Class Schema
const classSchema = new mongoose.Schema({
    classCode: { type: String, required: true, unique: true }, // e.g., "10A"
    className: String,
    teacherId: mongoose.Schema.Types.ObjectId,
    studentCount: Number,
    createdAt: { type: Date, default: Date.now }
});

// Attendance Schema
const attendanceSchema = new mongoose.Schema({
    studentId: { type: String, required: true, index: true },
    date: { type: Date, required: true, index: true },
    subject: { type: String, required: true },
    class: { type: String, required: true, index: true },
    period: String,
    status: { 
        type: String, 
        enum: ['present', 'absent', 'leave', 'sick', 'not-verified'],
        default: 'not-verified'
    },
    method: { 
        type: String, 
        enum: ['manual', 'camera', 'qrcode', 'biometric'],
        default: 'manual'
    },
    confidence: { type: Number, default: 0 }, // For camera: 0-100
    remarks: String,
    markedBy: mongoose.Schema.Types.ObjectId, // Teacher who marked
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Create compound indexes for faster queries
attendanceSchema.index({ studentId: 1, date: 1, subject: 1 }, { unique: true });
attendanceSchema.index({ class: 1, date: 1 });

// Report Schema (cached reports)
const reportSchema = new mongoose.Schema({
    class: { type: String, required: true },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    totalStudents: Number,
    presentCount: Number,
    absentCount: Number,
    leaveCount: Number,
    data: mongoose.Schema.Types.Mixed, // Detailed report data
    generatedAt: { type: Date, default: Date.now },
    generatedBy: mongoose.Schema.Types.ObjectId
});

// ==================== MODELS ====================

// const User = mongoose.model('User', userSchema);
// const Student = mongoose.model('Student', studentSchema);
// const Class = mongoose.model('Class', classSchema);
// const Attendance = mongoose.model('Attendance', attendanceSchema);
// const Report = mongoose.model('Report', reportSchema);
const Student = mongoose.models.Student || mongoose.model('Student', studentSchema);

// ==================== AUTHENTICATION MIDDLEWARE ====================

const authenticate = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        req.userRole = decoded.role;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// ==================== AUTH ENDPOINTS ====================

/**
 * POST /api/auth/register
 * Register new user (teacher/admin)
 */
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, name, role } = req.body;

        // Validate
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password required' });
        }

        // Check if user exists
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Create user
        const user = new User({
            username,
            email,
            password,
            name,
            role: role || 'teacher'
        });

        await user.save();

        // Generate JWT
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/auth/login
 * User login
 */
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isMatch = await user.matchPassword(password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user._id, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== STUDENT ENDPOINTS ====================

/**
 * POST /api/students/photo
 * Upload student reference photo for facial recognition
 */
app.post('/api/students/photo', authenticate, upload.single('photo'), async (req, res) => {
    try {
        const { studentId, faceDescriptor } = req.body;

        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        if (!studentId) {
            return res.status(400).json({ error: 'studentId required' });
        }

        // Parse face descriptor if provided
        let descriptor = [];
        if (faceDescriptor) {
            try {
                descriptor = JSON.parse(faceDescriptor);
            } catch (e) {
                descriptor = [];
            }
        }

        // Update student record
        const student = await Student.findOneAndUpdate(
            { studentId: studentId },
            {
                photoPath: `/uploads/${req.file.filename}`,
                faceDescriptor: descriptor,
                updatedAt: new Date()
            },
            { upsert: true, new: true }
        );

        res.status(201).json({
            success: true,
            message: 'Photo uploaded successfully',
            student: {
                studentId: student.studentId,
                name: student.name,
                photoPath: student.photoPath,
                descriptorLoaded: descriptor.length > 0
            }
        });
    } catch (error) {
        console.error('Photo upload error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/students/:studentId/photo
 * Get student reference photo
 */
app.get('/api/students/:studentId/photo', async (req, res) => {
    try {
        const student = await Student.findOne({ studentId: req.params.studentId });

        if (!student || !student.photoPath) {
            return res.status(404).json({ error: 'Photo not found' });
        }

        res.sendFile(path.join(__dirname, student.photoPath));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/classes/:className/students
 * Get all students in a class
 */
app.get('/api/classes/:className/students', async (req, res) => {
    try {
        const students = await Student.find(
            { class: req.params.className, isActive: true },
            { name: 1, studentId: 1, rollNo: 1, photoPath: 1, faceDescriptor: 1 }
        ).sort({ rollNo: 1 });

        res.json({
            success: true,
            class: req.params.className,
            count: students.length,
            students: students
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/classes/:className/descriptors
 * Get face descriptors for all students in a class (for facial recognition)
 */
app.get('/api/classes/:className/descriptors', async (req, res) => {
    try {
        const students = await Student.find(
            { class: req.params.className, isActive: true },
            { studentId: 1, name: 1, rollNo: 1, faceDescriptor: 1 }
        );

        const descriptors = students
            .filter(s => s.faceDescriptor && s.faceDescriptor.length > 0)
            .map(s => ({
                studentId: s.studentId,
                name: s.name,
                rollNo: s.rollNo,
                descriptor: s.faceDescriptor
            }));

        res.json({
            success: true,
            class: req.params.className,
            descriptorsAvailable: descriptors.length,
            totalStudents: students.length,
            descriptors: descriptors
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== ATTENDANCE ENDPOINTS ====================

/**
 * POST /api/attendance
 * Save single attendance record
 */
app.post('/api/attendance', authenticate, async (req, res) => {
    try {
        const { studentId, date, subject, class: classStr, status, method, confidence, remarks } = req.body;

        // Validate required fields
        if (!studentId || !date || !status || !method) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Check if attendance already exists for this record
        const dateObj = new Date(date);
        dateObj.setHours(0, 0, 0, 0);

        const existing = await Attendance.findOne({
            studentId: studentId,
            date: dateObj,
            subject: subject
        });

        let result;
        if (existing) {
            // Update existing record
            result = await Attendance.findByIdAndUpdate(
                existing._id,
                {
                    status,
                    method,
                    confidence: confidence || existing.confidence,
                    remarks,
                    markedBy: req.userId,
                    updatedAt: new Date()
                },
                { new: true }
            );
        } else {
            // Create new record
            const attendance = new Attendance({
                studentId,
                date: dateObj,
                subject,
                class: classStr,
                status,
                method,
                confidence: confidence || 0,
                remarks,
                markedBy: req.userId
            });
            result = await attendance.save();
        }

        res.status(201).json({
            success: true,
            message: existing ? 'Attendance updated' : 'Attendance saved',
            attendance: result
        });
    } catch (error) {
        console.error('Save attendance error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/attendance/bulk
 * Save multiple attendance records at once (from camera system)
 */
app.post('/api/attendance/bulk', authenticate, async (req, res) => {
    try {
        const { records, date, subject, class: classStr } = req.body;

        if (!Array.isArray(records) || records.length === 0) {
            return res.status(400).json({ error: 'Invalid records format' });
        }

        const dateObj = new Date(date);
        dateObj.setHours(0, 0, 0, 0);

        const results = [];
        const errors = [];

        for (const record of records) {
            try {
                const { studentId, status, method, confidence } = record;

                const existing = await Attendance.findOne({
                    studentId: studentId,
                    date: dateObj,
                    subject: subject
                });

                let result;
                if (existing) {
                    result = await Attendance.findByIdAndUpdate(
                        existing._id,
                        {
                            status,
                            method,
                            confidence: confidence || 0,
                            markedBy: req.userId,
                            updatedAt: new Date()
                        },
                        { new: true }
                    );
                } else {
                    const attendance = new Attendance({
                        studentId,
                        date: dateObj,
                        subject,
                        class: classStr,
                        status,
                        method,
                        confidence: confidence || 0,
                        markedBy: req.userId
                    });
                    result = await attendance.save();
                }

                results.push(result);
            } catch (error) {
                errors.push({ studentId: record.studentId, error: error.message });
            }
        }

        res.status(201).json({
            success: true,
            message: `${results.length} records saved successfully`,
            saved: results.length,
            failed: errors.length,
            errors: errors.length > 0 ? errors : undefined
        });
    } catch (error) {
        console.error('Bulk save error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/attendance
 * Get attendance records for a specific date/class/subject
 */
app.get('/api/attendance', async (req, res) => {
    try {
        const { date, class: classStr, subject } = req.query;

        let query = {};
        if (date) {
            const dateObj = new Date(date);
            dateObj.setHours(0, 0, 0, 0);
            query.date = dateObj;
        }
        if (classStr) query.class = classStr;
        if (subject) query.subject = subject;

        const attendance = await Attendance.find(query)
            .populate('markedBy', 'name email')
            .sort({ studentId: 1 });

        res.json({
            success: true,
            query: { date, class: classStr, subject },
            count: attendance.length,
            records: attendance
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/students/:studentId/attendance
 * Get attendance history for a specific student
 */
app.get('/api/students/:studentId/attendance', async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        const studentId = req.params.studentId;

        let query = { studentId: studentId };

        if (startDate && endDate) {
            const start = new Date(startDate);
            const end = new Date(endDate);
            end.setHours(23, 59, 59, 999);

            query.date = {
                $gte: start,
                $lte: end
            };
        }

        const records = await Attendance.find(query).sort({ date: -1 });

        // Calculate statistics
        const stats = {
            total: records.length,
            present: records.filter(r => r.status === 'present').length,
            absent: records.filter(r => r.status === 'absent').length,
            leave: records.filter(r => r.status === 'leave').length,
            sick: records.filter(r => r.status === 'sick').length
        };

        stats.percentage = stats.total > 0
            ? ((stats.present / stats.total) * 100).toFixed(2)
            : 0;

        res.json({
            success: true,
            studentId: studentId,
            statistics: stats,
            records: records,
            period: { startDate, endDate }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== REPORT ENDPOINTS ====================

/**
 * GET /api/reports/attendance
 * Generate attendance report for a class/date range
 */
app.get('/api/reports/attendance', async (req, res) => {
    try {
        const { startDate, endDate, class: classStr } = req.query;

        if (!startDate || !endDate) {
            return res.status(400).json({ error: 'startDate and endDate required' });
        }

        const start = new Date(startDate);
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);

        let query = {
            date: {
                $gte: start,
                $lte: end
            }
        };

        if (classStr) query.class = classStr;

        const records = await Attendance.find(query);

        // Calculate statistics
        const stats = {};
        const studentStats = {};

        records.forEach(record => {
            const key = record.studentId;
            if (!studentStats[key]) {
                studentStats[key] = {
                    present: 0,
                    absent: 0,
                    leave: 0,
                    sick: 0,
                    total: 0
                };
            }
            studentStats[key][record.status]++;
            studentStats[key].total++;
        });

        // Build report
        const report = Object.entries(studentStats).map(([studentId, data]) => ({
            studentId,
            presentCount: data.present,
            absentCount: data.absent,
            leaveCount: data.leave,
            sickCount: data.sick,
            totalClasses: data.total,
            attendancePercentage: data.total > 0
                ? ((data.present / data.total) * 100).toFixed(2)
                : 0
        }));

        // Overall statistics
        const overallStats = {
            totalRecords: records.length,
            totalPresent: records.filter(r => r.status === 'present').length,
            totalAbsent: records.filter(r => r.status === 'absent').length,
            totalLeave: records.filter(r => r.status === 'leave').length,
            totalSick: records.filter(r => r.status === 'sick').length,
            averageAttendance: records.length > 0
                ? (((records.filter(r => r.status === 'present').length) / records.length) * 100).toFixed(2)
                : 0
        };

        res.json({
            success: true,
            period: { startDate, endDate },
            class: classStr,
            overallStats: overallStats,
            studentReport: report,
            exportUrl: `/api/reports/attendance/export?startDate=${startDate}&endDate=${endDate}&class=${classStr}`
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/reports/trends
 * Get attendance trends over time
 */
app.get('/api/reports/trends', async (req, res) => {
    try {
        const { class: classStr, days = 30 } = req.query;

        const startDate = new Date();
        startDate.setDate(startDate.getDate() - parseInt(days));
        startDate.setHours(0, 0, 0, 0);

        let query = { date: { $gte: startDate } };
        if (classStr) query.class = classStr;

        const records = await Attendance.find(query);

        // Group by date
        const trends = {};
        records.forEach(record => {
            const dateStr = record.date.toISOString().split('T')[0];
            if (!trends[dateStr]) {
                trends[dateStr] = {
                    present: 0,
                    absent: 0,
                    leave: 0,
                    sick: 0
                };
            }
            trends[dateStr][record.status]++;
        });

        // Convert to array and sort
        const trendData = Object.entries(trends)
            .sort(([dateA], [dateB]) => dateA.localeCompare(dateB))
            .map(([date, data]) => ({
                date,
                present: data.present,
                absent: data.absent,
                leave: data.leave,
                sick: data.sick,
                total: data.present + data.absent + data.leave + data.sick
            }));

        res.json({
            success: true,
            class: classStr,
            days: parseInt(days),
            trendData: trendData
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/reports/at-risk
 * Get students with low attendance
 */
app.get('/api/reports/at-risk', async (req, res) => {
    try {
        const { class: classStr, threshold = 75 } = req.query;

        let query = {};
        if (classStr) query.class = classStr;

        const records = await Attendance.find(query);

        // Calculate attendance per student
        const studentStats = {};
        records.forEach(record => {
            const key = record.studentId;
            if (!studentStats[key]) {
                studentStats[key] = { present: 0, total: 0 };
            }
            if (record.status === 'present') studentStats[key].present++;
            studentStats[key].total++;
        });

        // Filter at-risk students
        const atRisk = Object.entries(studentStats)
            .map(([studentId, data]) => ({
                studentId,
                presentCount: data.present,
                totalClasses: data.total,
                attendancePercentage: ((data.present / data.total) * 100).toFixed(2),
                risk: ((data.present / data.total) * 100) < threshold ? 'critical' : 'warning'
            }))
            .filter(s => s.attendancePercentage < threshold)
            .sort((a, b) => a.attendancePercentage - b.attendancePercentage);

        res.json({
            success: true,
            class: classStr,
            threshold: threshold,
            atRiskCount: atRisk.length,
            students: atRisk
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== CLASS ENDPOINTS ====================

/**
 * POST /api/classes
 * Create a new class
 */
app.post('/api/classes', authenticate, async (req, res) => {
    try {
        const { classCode, className, teacherId } = req.body;

        if (!classCode) {
            return res.status(400).json({ error: 'classCode required' });
        }

        const classRecord = new Class({
            classCode,
            className,
            teacherId: teacherId || req.userId
        });

        await classRecord.save();

        res.status(201).json({
            success: true,
            message: 'Class created',
            class: classRecord
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/classes
 * Get all classes
 */
app.get('/api/classes', async (req, res) => {
    try {
        const classes = await Class.find().populate('teacherId', 'name email');

        res.json({
            success: true,
            count: classes.length,
            classes: classes
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        error: err.message || 'Internal server error'
    });
});

// ==================== MONGODB CONNECTION ====================

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(() => {
        console.log('✓ MongoDB connected successfully');
        
        // Start server
        app.listen(PORT, () => {
            console.log(`✓ Server running on port ${PORT}`);
            console.log(`✓ API Base URL: http://localhost:${PORT}/api`);
            console.log(`✓ Health Check: http://localhost:${PORT}/api/health`);
        });
    })
    .catch(err => {
        console.error('✗ MongoDB connection error:', err);
        process.exit(1);
    });

module.exports = app;