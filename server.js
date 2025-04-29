require('dotenv').config(); // Load environment variables

const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based version
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const WebSocket = require('ws');
const http = require('http');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const multer = require('multer');
const PDFDocument = require('pdfkit');
const fs = require('fs');


const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

const port = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Email transporter configuration for Gmail
const emailTransporter = nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER || 'limkokwingvirtualconnect@gmail.com',
        pass: process.env.EMAIL_PASS || 'ncfl eirb hcuv yxzw' // Use the app password here
    },
    tls: {
        // Do not fail on invalid certs
        rejectUnauthorized: false
    }
});

// Verify email transporter connection
emailTransporter.verify((error, success) => {
    if (error) {
        console.error('Email transporter verification failed:', error);
    } else {
        console.log('Server is ready to send emails');
    }
});

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
const sessionMiddleware = session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
});
app.use(sessionMiddleware);

// Database connection pool
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '1234',
    database: process.env.DB_NAME || 'limkokwing_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test database connection
db.getConnection()
    .then(connection => {
        console.log('Connected to MySQL database');
        connection.release();
    })
    .catch(err => {
        console.error('Error connecting to MySQL:', err);
        process.exit(1);
    });

// Middleware to check login
const requireLogin = (req, res, next) => {
    if (req.session.loggedIn) {
        next();
    } else {
        res.status(401).redirect('/login.html');
    }
};

const requireAdmin = (req, res, next) => {
    if (req.session.loggedIn && req.session.isAdmin) {
        next();
    } else {
        res.status(403).redirect('/login.html');
    }
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'payment.html'));
});
// Enhanced Signup Endpoint with Application ID Email
app.post('/api/signup', async (req, res) => {
    try {
        const { fullName, email, phone, password, confirmPassword } = req.body;

        // Validate inputs
        if (!fullName || !email || !phone || !password || !confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'All fields are required' 
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Passwords do not match' 
            });
        }

        if (password.length < 8) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 8 characters' 
            });
        }

        // Check if email exists
        const [emailCheck] = await db.query(
            'SELECT email FROM sign_up WHERE email = ?', 
            [email]
        );

        if (emailCheck.length > 0) {
            return res.status(409).json({ 
                success: false, 
                message: 'Email already registered' 
            });
        }

        // Generate applicant ID (LKW + random 6-digit number)
        const applicantId = 'LKW' + Math.floor(100000 + Math.random() * 900000);
        const username = email.split('@')[0] + Math.floor(10 + Math.random() * 90);
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert into database
        await db.query(
            `INSERT INTO sign_up 
            (applicant_id, full_name, email, phone, username, password, verification_token) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [applicantId, fullName, email, phone, username, hashedPassword, verificationToken]
        );

        // Send email with applicant ID
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your Limkokwing University Application ID',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
                    <h2 style="color: #ffcc00;">Welcome to Limkokwing University Lesotho!</h2>
                    <p>Dear ${fullName},</p>
                    
                    <h3 style="color: #ffcc00;">Your Application Details</h3>
                    <p>Thank you for signing up with us. Here are your important details:</p>
                    
                    <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #ffcc00; margin: 20px 0;">
                        <p><strong>Application ID:</strong> ${applicantId}</p>
                        <p><strong>Username:</strong> ${username}</p>
                        <p><strong>Registered Email:</strong> ${email}</p>
                    </div>
                    
                    <p>Please keep this information safe as you'll need it to access your account.</p>
                    
                    <p>You can now proceed with your application by clicking the button below:</p>
                    
                    <p style="text-align: center; margin: 25px 0;">
                        <a href="${req.protocol}://${req.get('host')}/application.html" 
                           style="background-color: #ffcc00; color: #000; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
                            Continue Application
                        </a>
                    </p>
                    
                    <p style="margin-top: 30px;">Best regards,<br>
                    <strong>Limkokwing University Lesotho</strong></p>
                </div>
            `
        };

        await emailTransporter.sendMail(mailOptions);

        res.json({
            success: true,
            message: 'Registration successful! Your Application ID has been sent to your email.',
            applicantId,
            username
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Registration failed. Please try again.' 
        });
    }
});



// Email verification endpoint
app.get('/verify-email', async (req, res) => {
    try {
        const { token, email } = req.query;

        if (!token || !email) {
            return res.status(400).send('Invalid verification link');
        }

        // Check if token matches
        const [user] = await db.query(
            'SELECT * FROM students WHERE email = ? AND verification_token = ?', 
            [email, token]
        );

        if (user.length === 0) {
            return res.status(400).send('Invalid or expired verification link');
        }

        // Update user as verified
        await db.query(
            'UPDATE students SET is_verified = TRUE, verification_token = NULL WHERE email = ?',
            [email]
        );

        // Redirect to success page
        res.send(`
            <html>
                <head>
                    <title>Email Verified</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            text-align: center;
                            padding: 50px;
                            background-color: #f5f5f5;
                        }
                        .success-message {
                            background-color: white;
                            padding: 30px;
                            border-radius: 10px;
                            box-shadow: 0 0 10px rgba(0,0,0,0.1);
                            max-width: 600px;
                            margin: 0 auto;
                        }
                        h1 {
                            color: #ffcc00;
                        }
                        .btn {
                            display: inline-block;
                            background-color: #ffcc00;
                            color: black;
                            padding: 10px 20px;
                            text-decoration: none;
                            border-radius: 5px;
                            margin-top: 20px;
                            font-weight: bold;
                        }
                    </style>
                </head>
                <body>
                    <div class="success-message">
                        <h1>Email Verified Successfully!</h1>
                        <p>Your email address has been verified. You can now log in to your account.</p>
                        <a href="/newU2login.html" class="btn">Go to Login Page</a>
                    </div>
                </body>
            </html>
        `);

    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).send('Email verification failed');
    }
});


// Lesotho-specific payment processors
const LESOTHO_BANKS = {
    'standard_bank': {
        name: 'Standard Lesotho Bank',
        accountNumber: '9087654321',
        branchCode: '12345',
        swiftCode: 'SBZCLSML'
    },
    'nedbank': {
        name: 'Nedbank Lesotho',
        accountNumber: '7123456789',
        branchCode: '67890',
        swiftCode: 'NEDCLSML'
    },
    'first_national_bank': {
        name: 'First National Bank Lesotho',
        accountNumber: '6123456789',
        branchCode: '34567',
        swiftCode: 'FIRNLSML'
    }
};

// Process payment endpoint with Lesotho-specific options
app.post('/api/process-payment', async (req, res) => {
    try {
        const { applicantId, paymentMethod, transactionDetails } = req.body;

        // Get applicant details
        const [applicant] = await db.query(
            'SELECT * FROM applicants WHERE applicant_id = ?',
            [applicantId]
        );

        if (applicant.length === 0) {
            return res.status(404).json({ success: false, message: 'Applicant not found' });
        }

        const email = applicant[0].email;
        const fullName = `${applicant[0].first_name} ${applicant[0].last_name}`;
        const phone = applicant[0].phone;

        // Generate transaction ID with Lesotho prefix
        const transactionId = `LKWPAY${Date.now().toString().slice(-8)}`;
        const paymentDate = new Date();
        const amount = 200; // M200 application fee

        // Create payment record
        await db.query(
            'INSERT INTO payments (applicant_id, transaction_id, amount, method, status, payment_date) VALUES (?, ?, ?, ?, ?, ?)',
            [applicantId, transactionId, amount, paymentMethod, 'completed', paymentDate]
        );

        // Generate PDF receipt with Lesotho-specific design
        const receiptPath = await generateLesothoReceipt({
            applicantId,
            fullName,
            email,
            phone,
            transactionId,
            paymentMethod,
            amount,
            date: paymentDate,
            details: transactionDetails
        });

        // Send email with PDF attachment
        await sendLesothoPaymentEmail(email, fullName, receiptPath, {
            transactionId,
            paymentMethod,
            amount,
            date: paymentDate
        });

        res.json({
            success: true,
            message: 'Payment processed successfully',
            transactionId
        });

    } catch (error) {
        console.error('Payment processing error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Payment processing failed' 
        });
    }
});

// Generate Lesotho-style receipt
async function generateLesothoReceipt(paymentData) {
    return new Promise((resolve, reject) => {
        try {
            const receiptDir = path.join(__dirname, 'receipts');
            if (!fs.existsSync(receiptDir)) {
                fs.mkdirSync(receiptDir, { recursive: true });
            }

            const fileName = `LKW_Receipt_${paymentData.transactionId}.pdf`;
            const filePath = path.join(receiptDir, fileName);
            const doc = new PDFDocument({ size: 'A4', margin: 50 });

            const stream = fs.createWriteStream(filePath);
            doc.pipe(stream);

            // Lesotho-themed header
            doc.fillColor('#00247D') // Lesotho blue
               .rect(0, 0, doc.page.width, 100)
               .fill()
               .fillColor('white')
               .fontSize(20)
               .text('Limkokwing University Lesotho', 50, 30)
               .fontSize(14)
               .text('Official Payment Receipt', 50, 60);

            // University address
            doc.fillColor('black')
               .fontSize(10)
               .text('Maseru 100, Lesotho | Phone: +266 2231 2650', 50, 90, { align: 'left' });

            // Receipt details
            doc.fontSize(14)
               .text('PAYMENT RECEIPT', 50, 130)
               .moveDown(0.5);

            doc.fontSize(12)
               .text(`Receipt No: ${paymentData.transactionId}`, { continued: true })
               .text(`Date: ${paymentData.date.toLocaleDateString('en-GB')}`, { align: 'right' })
               .moveDown();

            // Applicant information
            doc.font('Helvetica-Bold').text('Applicant Information:').font('Helvetica');
            doc.text(`Name: ${paymentData.fullName}`);
            doc.text(`Applicant ID: ${paymentData.applicantId}`);
            doc.text(`Phone: ${paymentData.phone}`);
            doc.text(`Email: ${paymentData.email}`);
            doc.moveDown();

            // Payment details
            doc.font('Helvetica-Bold').text('Payment Details:').font('Helvetica');
            doc.text(`Method: ${paymentData.paymentMethod}`);
            
            // Add specific details based on payment method
            if (paymentData.paymentMethod.includes('Bank')) {
                doc.text(`Bank: ${paymentData.details.bankName}`);
                doc.text(`Reference: ${paymentData.details.reference}`);
            } else if (paymentData.paymentMethod.includes('Card')) {
                doc.text(`Card Type: ${paymentData.details.cardType}`);
                doc.text(`Last 4 Digits: •••• ${paymentData.details.lastFourDigits}`);
            } else if (paymentData.paymentMethod.includes('Mobile Money')) {
                doc.text(`Mobile Network: ${paymentData.details.network}`);
                doc.text(`Transaction ID: ${paymentData.details.momoTransactionId}`);
            }

            doc.text(`Amount: M${paymentData.amount.toFixed(2)}`);
            doc.moveDown();

            // University stamp area
            doc.moveTo(50, doc.y)
               .lineTo(200, doc.y)
               .stroke()
               .fontSize(10)
               .text('University Official Stamp', 50, doc.y + 5)
               .rect(50, doc.y + 25, 150, 80)
               .stroke()
               .moveDown(5);

            // Footer with Lesotho context
            doc.fontSize(10)
               .text('Thank you for your payment to Limkokwing University Lesotho.', 50, doc.page.height - 60)
               .text('For any queries, please contact finance@limkokwing.co.ls or call +266 2231 2650.', 50, doc.page.height - 45)
               .text('This is an official receipt for tax purposes.', 50, doc.page.height - 30);

            doc.end();

            stream.on('finish', () => resolve(filePath));
            stream.on('error', reject);

        } catch (error) {
            reject(error);
        }
    });
}

// Send payment email with Lesotho context
async function sendLesothoPaymentEmail(email, name, receiptPath, paymentDetails) {
    const mailOptions = {
        from: `"Limkokwing University Finance" <finance@limkokwing.co.ls>`,
        to: email,
        subject: `Payment Confirmation - ${paymentDetails.transactionId}`,
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
                <div style="background-color: #00247D; padding: 20px; text-align: center;">
                    <h2 style="color: white; margin: 0;">Limkokwing University Lesotho</h2>
                </div>
                
                <div style="padding: 20px;">
                    <h3 style="color: #00247D;">Payment Confirmation</h3>
                    <p>Dear ${name},</p>
                    
                    <p>Thank you for your payment to Limkokwing University Lesotho. Here are your payment details:</p>
                    
                    <div style="background-color: #f5f5f5; padding: 15px; border-left: 4px solid #00247D; margin: 15px 0;">
                        <p><strong>Transaction ID:</strong> ${paymentDetails.transactionId}</p>
                        <p><strong>Date:</strong> ${paymentDetails.date.toLocaleDateString('en-GB')}</p>
                        <p><strong>Payment Method:</strong> ${paymentDetails.paymentMethod}</p>
                        <p><strong>Amount:</strong> M${paymentDetails.amount.toFixed(2)}</p>
                    </div>
                    
                    <p>Your payment receipt is attached to this email. Please keep it for your records.</p>
                    
                    <p>For any questions regarding your payment, please contact our finance department:</p>
                    <ul>
                        <li>Email: finance@limkokwing.co.ls</li>
                        <li>Phone: +266 2231 2650</li>
                        <li>Location: Maseru Campus, Lesotho</li>
                    </ul>
                    
                    <div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee;">
                        <p>Best regards,</p>
                        <p><strong>Finance Department</strong><br>
                        Limkokwing University Lesotho</p>
                    </div>
                </div>
            </div>
        `,
        attachments: [
            {
                filename: `LKW_Payment_Receipt_${paymentDetails.transactionId}.pdf`,
                path: receiptPath
            }
        ]
    };

    await emailTransporter.sendMail(mailOptions);
}

// Student login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user exists
        const [users] = await db.query(
            'SELECT * FROM sign_up WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }

        const user = users[0];

        // Compare passwords
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }

        // Create session
        req.session.loggedIn = true;
        req.session.applicantId = user.applicant_id;
        req.session.fullName = user.full_name;
        req.session.email = user.email;

        res.json({ 
            success: true,
            message: 'Login successful',
            applicantId: user.applicant_id,
            username: user.username
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Login failed. Please try again.' 
        });
    }
});

// Admin login
app.post('/api/admin-login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if admin exists
        const [admins] = await db.query(
            'SELECT * FROM admin_users WHERE username = ?',
            [username]
        );

        if (admins.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }

        const admin = admins[0];

        // Compare passwords
        const passwordMatch = await bcrypt.compare(password, admin.password);
        if (!passwordMatch) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }

        // Create session
        req.session.loggedIn = true;
        req.session.isAdmin = true;
        req.session.adminId = admin.id;
        req.session.adminName = admin.full_name;

        res.json({ 
            success: true,
            message: 'Admin login successful'
        });

    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Admin login failed. Please try again.' 
        });
    }
});

// Protected routes
app.get('/dashboard', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin-dashboard', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

// WebSocket handling
wss.on('connection', async (ws, req) => {
    // Handle WebSocket connections here
    ws.on('message', (message) => {
        console.log('Received:', message);
        ws.send('Message received');
    });
});

// Handle WebSocket upgrade
server.on('upgrade', (request, socket, head) => {
    sessionMiddleware(request, {}, () => {
        if (!request.session.loggedIn) {
            socket.destroy();
            return;
        }

        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    });
});

// Ensure upload directory exists (with fallback)
const uploadDir = path.join(__dirname, process.env.UPLOAD_DIR || 'public/uploads', 'applications');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});


// Configure file storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|pdf/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        
        if (extname && mimetype) {
            return cb(null, true);
        } else {
            cb('Error: Only PDF, JPG, JPEG, and PNG files are allowed!');
        }
    }
}).array('documents', 5); // Max 5 files

// Application submission endpoint
app.post('/api/submit-application', async (req, res) => {
    upload(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ 
                success: false, 
                message: err 
            });
        }

        try {
            const { 
                applicantId,
                firstName,
                lastName,
                email,
                phone,
                idNumber,
                address,
                education,
                primaryCourse,
                secondaryCourse,
                faculty
            } = req.body;

            // Insert application into database
            const [result] = await db.query(
                `INSERT INTO applications (
                    applicant_id, first_name, last_name, email, phone, 
                    id_number, address, education_level, primary_course, 
                    secondary_course, faculty
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    applicantId, firstName, lastName, email, phone,
                    idNumber, address, education, primaryCourse,
                    secondaryCourse, faculty
                ]
            );

            const applicationId = result.insertId;

            // Handle file uploads
            if (req.files && req.files.length > 0) {
                for (const file of req.files) {
                    await db.query(
                        `INSERT INTO application_documents (
                            application_id, document_type, file_name, file_path
                        ) VALUES (?, ?, ?, ?)`,
                        [
                            applicationId,
                            file.fieldname, // or determine type from file name
                            file.originalname,
                            file.path.replace('public/', '') // store relative path
                        ]
                    );
                }
            }
            

            // Send confirmation email
            await emailTransporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Application Submission Confirmation',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #ffcc00;">Application Submitted Successfully</h2>
                        <p>Dear ${firstName} ${lastName},</p>
                        
                        <p>Thank you for applying to Limkokwing University Lesotho.</p>
                        
                        <h3 style="color: #ffcc00;">Application Details</h3>
                        <ul>
                            <li><strong>Application ID:</strong> APP-${applicationId.toString().padStart(6, '0')}</li>
                            <li><strong>Primary Course:</strong> ${primaryCourse}</li>
                            <li><strong>Secondary Option:</strong> ${secondaryCourse}</li>
                            <li><strong>Faculty:</strong> ${faculty}</li>
                        </ul>
                        
                        <p>We will review your application and contact you within 7-10 working days.</p>
                        
                        <p style="margin-top: 30px;">Best regards,<br>
                        <strong>Admissions Office</strong><br>
                        Limkokwing University Lesotho</p>
                    </div>
                `
            });

            res.json({ 
                success: true,
                message: 'Application submitted successfully',
                applicationId: applicationId
            });

        } catch (error) {
            console.error('Application submission error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Application submission failed' 
            });
        }
    });
});
// Add these endpoints after your existing routes

// Get application status
app.get('/api/application-status/:applicationId', requireLogin, async (req, res) => {
    try {
        const [application] = await db.query(`
            SELECT a.*, s.status, s.change_date as status_date, s.notes as status_notes
            FROM applications a
            LEFT JOIN (
                SELECT application_id, status, change_date, notes
                FROM application_status
                WHERE (application_id, change_date) IN (
                    SELECT application_id, MAX(change_date)
                    FROM application_status
                    GROUP BY application_id
                )
            ) s ON a.application_id = s.application_id
            WHERE a.application_id = ? AND a.applicant_id = ?
        `, [req.params.applicationId, req.session.applicantId]);

        if (application.length === 0) {
            return res.status(404).json({ success: false, message: 'Application not found' });
        }

        // Get all status history
        const [statusHistory] = await db.query(`
            SELECT * FROM application_status
            WHERE application_id = ?
            ORDER BY change_date DESC
        `, [req.params.applicationId]);

        // Get documents
        const [documents] = await db.query(`
            SELECT * FROM application_documents
            WHERE application_id = ?
        `, [req.params.applicationId]);

        // Get interview if exists
        const [interview] = await db.query(`
            SELECT * FROM interviews
            WHERE application_id = ?
        `, [req.params.applicationId]);

        res.json({
            success: true,
            application: application[0],
            statusHistory,
            documents,
            interview: interview[0] || null
        });

    } catch (error) {
        console.error('Status check error:', error);
        res.status(500).json({ success: false, message: 'Failed to get application status' });
    }
});

// Admin endpoints
app.get('/api/admin/applications', requireAdmin, async (req, res) => {
    try {
        const [applications] = await db.query(`
            SELECT a.*, s.status, s.change_date as status_date
            FROM applications a
            LEFT JOIN (
                SELECT application_id, status, change_date
                FROM application_status
                WHERE (application_id, change_date) IN (
                    SELECT application_id, MAX(change_date)
                    FROM application_status
                    GROUP BY application_id
                )
            ) s ON a.application_id = s.application_id
            ORDER BY a.submission_date DESC
        `);

        res.json({ success: true, applications });
    } catch (error) {
        console.error('Admin applications error:', error);
        res.status(500).json({ success: false, message: 'Failed to get applications' });
    }
});

app.post('/api/admin/update-status', requireAdmin, async (req, res) => {
    try {
        const { applicationId, status, notes } = req.body;

        await db.query(`
            INSERT INTO application_status
            (application_id, status, changed_by, notes)
            VALUES (?, ?, ?, ?)
        `, [applicationId, status, req.session.adminName, notes]);

        // If status is interview_scheduled, create an interview record
        if (status === 'interview_scheduled') {
            await db.query(`
                INSERT INTO interviews
                (application_id, scheduled_date, status)
                VALUES (?, NOW() + INTERVAL 3 DAY, 'scheduled')
            `, [applicationId]);
        }

        // Send email notification to applicant
        const [application] = await db.query(`
            SELECT email, first_name, last_name FROM applications
            WHERE application_id = ?
        `, [applicationId]);

        if (application.length > 0) {
            const { email, first_name, last_name } = application[0];
            
            await emailTransporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: `Application Status Update: ${status.replace('_', ' ')}`,
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #ffcc00;">Application Status Update</h2>
                        <p>Dear ${first_name} ${last_name},</p>
                        
                        <p>The status of your application has been updated:</p>
                        
                        <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #ffcc00; margin: 20px 0;">
                            <p><strong>New Status:</strong> ${status.replace('_', ' ')}</p>
                            ${notes ? `<p><strong>Notes:</strong> ${notes}</p>` : ''}
                        </div>
                        
                        <p>You can check your application status anytime by logging into your account.</p>
                        
                        <p style="margin-top: 30px;">Best regards,<br>
                        <strong>Admissions Office</strong><br>
                        Limkokwing University Lesotho</p>
                    </div>
                `
            });
        }

        res.json({ success: true, message: 'Status updated successfully' });
    } catch (error) {
        console.error('Status update error:', error);
        res.status(500).json({ success: false, message: 'Failed to update status' });
    }
});

// File download endpoint
app.get('/api/documents/:documentId', requireLogin, async (req, res) => {
    try {
        const [document] = await db.query(`
            SELECT ad.* FROM application_documents ad
            JOIN applications a ON ad.application_id = a.application_id
            WHERE ad.document_id = ? AND a.applicant_id = ?
        `, [req.params.documentId, req.session.applicantId]);

        if (document.length === 0) {
            return res.status(404).send('Document not found');
        }

        const filePath = path.join(__dirname, 'public', document[0].file_path);
        res.download(filePath, document[0].file_name);

    } catch (error) {
        console.error('Document download error:', error);
        res.status(500).send('Failed to download document');
    }
});

// Start server
server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});