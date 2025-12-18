// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// NEW: Razorpay Import
const Razorpay = require('razorpay');

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// ==========================================
// --- RAZORPAY INITIALIZATION ---
// ==========================================
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ==========================================
// --- FILE UPLOAD CONFIGURATION (Multer) ---
// ==========================================

// 1. IMPORTANT: Ensure 'uploads' directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir);
    console.log('Created "uploads" directory for storing images.');
}

// 2. Define storage strategy
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// 3. Initialize upload middleware
const upload = multer({ storage: storage });

// 4. Serve uploaded files statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// ==========================================


// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Connected successfully'))
    .catch(err => console.error('MongoDB connection error:', err));


// ==============================================
// --- DATABASE MODELS (Schemas) ---
// ==============================================

const addressSchema = new mongoose.Schema({
    _id: { type: mongoose.Schema.Types.ObjectId, default: () => new mongoose.Types.ObjectId() }, 
    type: { type: String, enum: ['Home', 'Work', 'Other'], default: 'Home' },
    name: { type: String, required: true, trim: true },
    houseNo: { type: String, required: true, trim: true },
    area: { type: String, required: true, trim: true },
    phone: { type: String, required: true, trim: true },
});

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
    phone: { type: String, unique: true, sparse: true, trim: true },
    password: { type: String },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    addresses: [addressSchema],
    createdAt: { type: Date, default: Date.now }
});
userSchema.pre('save', async function() { if (!this.email && !this.phone) { throw new Error('Either email or phone is required.'); } });
const User = mongoose.model('User', userSchema);

const otpSchema = new mongoose.Schema({
    identifier: { type: String, required: true, lowercase: true, trim: true },
    otp: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 300 } 
});
const Otp = mongoose.model('Otp', otpSchema);

const orderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [{ id: String, name: String, price: Number, quantity: Number, image: String }],
    totalAmount: { type: Number, required: true },
    deliveryAddress: { 
        name: { type: String, required: true },
        houseNo: { type: String, required: true }, 
        area: { type: String, required: true },
        phone: { type: String, required: true },
    },
    deliverySlot: { type: String },
    paymentMethod: { type: String, required: true },
    status: { type: String, default: 'Preparing', enum: ['Preparing', 'Out for Delivery', 'Delivered', 'Cancelled'] },
    createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

const menuItemSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    price: { type: Number, required: true, min: 0 },
    image: { type: String, required: true }, 
    category: { type: String, required: true, enum: ['Pizza', 'Burger', 'Pasta', 'Salad', 'Dessert', 'Drinks'] },
    discountPercent: { type: Number, default: 0, min: 0, max: 100 },
    isAvailable: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});
const MenuItem = mongoose.model('MenuItem', menuItemSchema);

const appStatusSchema = new mongoose.Schema({
    key: { type: String, required: true, default: 'main_status', unique: true },
    isOnline: { type: Boolean, required: true, default: true },
    lastUpdated: { type: Date, default: Date.now },
    isTimeSlotEnabled: { type: Boolean, default: false },
    timeSlots: { type: [String], default: ["12:00 PM - 2:00 PM", "2:00 PM - 4:00 PM", "4:00 PM - 6:00 PM"] }
});
const AppStatus = mongoose.model('AppStatus', appStatusSchema);


// --- HELPER & MIDDLEWARE ---
const transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } });
const generateOTP = () => crypto.randomInt(100000, 1000000).toString();
const getIdentifierType = (input) => { if (!input) return null; const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/i; if (gmailRegex.test(input)) return 'email'; return null; };

const verifyUser = (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) return res.status(401).json({ message: "Unauthorized: No token provided." });
        if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET missing");
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) { return res.status(401).json({ message: "Invalid or expired token." }); }
};

const verifyAdmin = (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) return res.status(401).json({ message: "Unauthorized." });
        if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET missing");
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ message: "Access denied. Admins only." });
        req.user = decoded; next();
    } catch (error) { return res.status(401).json({ message: "Invalid token." }); }
};

const initializeAppStatus = async () => {
    let status = await AppStatus.findOne({ key: 'main_status' });
    if (!status) {
        status = new AppStatus({ 
            isOnline: true, 
            isTimeSlotEnabled: false,
            timeSlots: ["12:00 PM - 2:00 PM", "2:00 PM - 4:00 PM", "4:00 PM - 6:00 PM"]
        });
        await status.save();
    }
    return status;
};


// ==============================================
// ================= API ROUTES =================
// ==============================================

// --- AUTH ROUTES (Unchanged) ---
app.post('/api/signup', async (req, res) => { try { let { name, email, phone, password } = req.body; if (!name || !password || (!email && !phone)) return res.status(400).json({ message: "Missing required fields." }); if (email) email = email.toLowerCase().trim(); if (email && !email.endsWith('@gmail.com')) return res.status(400).json({ message: "Only Gmail allowed." }); const query = {}; if (email) query.email = email; if (phone) query.phone = phone; const existingUser = await User.findOne({ $or: Object.entries(query).map(([k, v]) => ({ [k]: v })) }); if (existingUser) return res.status(400).json({ message: "User exists." }); const salt = await bcrypt.genSalt(10); const hashedPassword = await bcrypt.hash(password, salt); const newUser = new User({ name, email, phone, password: hashedPassword }); await newUser.save(); res.status(201).json({ message: "User created." }); } catch (error) { res.status(500).json({ message: error.message }); } });
app.post('/api/send-otp', async (req, res) => { try { let { identifier } = req.body; if (!identifier) return res.status(400).json({ message: "Email required." }); identifier = identifier.toLowerCase().trim(); if (!getIdentifierType(identifier)) return res.status(400).json({ message: "Invalid Gmail." }); const user = await User.findOne({ email: identifier }); if (!user) return res.status(404).json({ message: "User not found." }); const otpCode = generateOTP(); const salt = await bcrypt.genSalt(10); const hashedOTP = await bcrypt.hash(otpCode, salt); await Otp.deleteMany({ identifier }); await new Otp({ identifier, otp: hashedOTP }).save(); await transporter.sendMail({ from: '"CozyBites" <noreply@cozybites.com>', to: identifier, subject: 'Your Login OTP', text: `Your code is: ${otpCode}. Expires in 5 mins.` }); res.json({ message: `OTP sent to ${identifier}.` }); } catch (error) { res.status(500).json({ message: "Failed to send email." }); } });
app.post('/api/login-otp', async (req, res) => { try { let { identifier, otpInput } = req.body; if (!identifier || !otpInput) return res.status(400).json({ message: "Missing data." }); identifier = identifier.toLowerCase().trim(); if (!getIdentifierType(identifier)) return res.status(400).json({ message: "Invalid Gmail." }); const user = await User.findOne({ email: identifier }); if (!user) return res.status(404).json({ message: "User not found." }); const otpRecord = await Otp.findOne({ identifier }); if (!otpRecord) return res.status(400).json({ message: "Expired OTP." }); const isMatch = await bcrypt.compare(otpInput, otpRecord.otp); if (!isMatch) return res.status(400).json({ message: "Invalid OTP." }); const token = jwt.sign({ userId: user._id, name: user.name, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' }); await Otp.deleteOne({ _id: otpRecord._id }); res.json({ message: "Login successful!", token: token, username: user.name, role: user.role }); } catch (error) { res.status(500).json({ message: "Login failed." }); } });


// ==============================================
// --- PAYMENT INTEGRATION ROUTES ---
// ==============================================

// 1. Create Razorpay Order
app.post('/api/create-razorpay-order', verifyUser, async (req, res) => {
    try {
        const { amount } = req.body;
        // Razorpay expects the amount in paise (e.g., ₹100 is 10000 paise)
        const amountInPaise = Math.round(amount * 100); 

        if (!amount || amountInPaise < 100) {
            return res.status(400).json({ message: "Invalid amount or amount too small." });
        }

        const options = {
            amount: amountInPaise, 
            currency: "INR",
            receipt: "order_rcptid_" + Date.now(), 
        };

        const order = await razorpay.orders.create(options);
        
        res.status(200).json(order);
    } catch (error) {
        console.error("Razorpay Order Creation Error:", error);
        res.status(500).json({ message: "Failed to create Razorpay order.", error: error.message });
    }
});

// 2. Finalize Order (After Payment or Manual Payment)
app.post('/api/orders', verifyUser, async (req, res) => { 
    try { 
        const appStatus = await initializeAppStatus();
        if (!appStatus.isOnline) {
            return res.status(403).json({ message: "We are currently closed for orders to manage kitchen capacity. Please try again shortly!" });
        }
        
        const userId = req.userId; 
        const { items, totalAmount, deliveryAddress, paymentMethod, deliverySlot } = req.body; 
        
        // Logic for enforcing slot selection if enabled (Mandatory check)
        if (appStatus.isTimeSlotEnabled && (!deliverySlot || !appStatus.timeSlots.includes(deliverySlot))) {
            return res.status(400).json({ message: "Delivery slot is mandatory. Please select an available slot." });
        }
        // Logic for enforcing address (Mandatory check)
        if (!deliveryAddress || !deliveryAddress.name || !deliveryAddress.houseNo || !deliveryAddress.area || !deliveryAddress.phone) {
            return res.status(400).json({ message: "Missing required delivery address fields." });
        }

        if (!items || items.length === 0) return res.status(400).json({ message: "Empty order." }); 
        
        const newOrder = new Order({ userId, items, totalAmount, deliveryAddress, paymentMethod, deliverySlot }); 
        await newOrder.save(); 
        res.status(201).json({ message: "Order placed!", orderId: newOrder._id }); 
    } catch (error) { 
        console.error("Order Placement Error:", error);
        res.status(500).json({ message: "Failed to place order." }); 
    } 
});

// --- ADMIN ORDER ROUTES (Unchanged) ---
app.get('/api/orders', verifyUser, async (req, res) => { try { const userId = req.userId; const orders = await Order.find({ userId }).sort({ createdAt: -1 }); res.json(orders); } catch (error) { res.status(500).json({ message: "Failed to fetch orders." }); } });
app.get('/api/admin/orders', verifyAdmin, async (req, res) => { try { const orders = await Order.find({}).populate('userId', 'name email phone').sort({ createdAt: -1 }); res.json(orders); } catch (error) { res.status(500).json({ message: "Failed to fetch all orders." }); } });
app.put('/api/admin/orders/:id/status', verifyAdmin, async (req, res) => { try { const orderId = req.params.id; const newStatus = req.body.status; const validStatuses = ['Preparing', 'Out for Delivery', 'Delivered', 'Cancelled']; if (!validStatuses.includes(newStatus)) return res.status(400).json({ message: "Invalid status." }); const updatedOrder = await Order.findByIdAndUpdate(orderId, { status: newStatus }, { new: true }); if (!updatedOrder) return res.status(404).json({ message: "Order not found." }); res.json({ message: `Status updated to ${newStatus}`, order: updatedOrder }); } catch (error) { res.status(500).json({ message: "Failed to update status." }); } });


// ==========================================================
// --- USER ADDRESS BOOK ROUTES (Unchanged) ---
// ==========================================================

app.get('/api/user/addresses', verifyUser, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('addresses');
        if (!user) return res.status(404).json({ message: "User not found." });
        res.json(user.addresses);
    } catch (error) {
        console.error("Fetch Addresses Error:", error);
        res.status(500).json({ message: "Failed to fetch addresses." });
    }
});

app.post('/api/user/addresses', verifyUser, async (req, res) => {
    try {
        const { type, name, houseNo, area, phone } = req.body;
        if (!name || !houseNo || !area || !phone) {
            return res.status(400).json({ message: "Missing required address fields." });
        }
        
        const newAddress = { type: type || 'Home', name, houseNo, area, phone };

        const user = await User.findByIdAndUpdate(
            req.userId,
            { $push: { addresses: newAddress } },
            { new: true, runValidators: true }
        ).select('addresses');

        res.status(201).json({ message: "Address added successfully!", address: user.addresses[user.addresses.length - 1] });

    } catch (error) {
        console.error("Add Address Error:", error);
        res.status(500).json({ message: "Failed to add address." });
    }
});

app.put('/api/user/addresses/:addressId', verifyUser, async (req, res) => {
    try {
        const { addressId } = req.params;
        const { type, name, houseNo, area, phone } = req.body;

        const updateFields = {};
        if (type) updateFields['addresses.$.type'] = type;
        if (name) updateFields['addresses.$.name'] = name;
        if (houseNo) updateFields['addresses.$.houseNo'] = houseNo;
        if (area) updateFields['addresses.$.area'] = area;
        if (phone) updateFields['addresses.$.phone'] = phone;

        const user = await User.findOneAndUpdate(
            { _id: req.userId, 'addresses._id': addressId },
            { $set: updateFields },
            { new: true }
        );

        if (!user) return res.status(404).json({ message: "Address or User not found." });

        const updatedAddress = user.addresses.find(addr => addr._id.toString() === addressId);
        res.json({ message: "Address updated successfully!", address: updatedAddress });

    } catch (error) {
        console.error("Update Address Error:", error);
        res.status(500).json({ message: "Failed to update address." });
    }
});

app.delete('/api/user/addresses/:addressId', verifyUser, async (req, res) => {
    try {
        const { addressId } = req.params;

        const user = await User.findByIdAndUpdate(
            req.userId,
            { $pull: { addresses: { _id: addressId } } },
            { new: true }
        );

        if (!user) return res.status(404).json({ message: "User not found." });
        
        res.json({ message: "Address deleted successfully!" });

    } catch (error) {
        console.error("Delete Address Error:", error);
        res.status(500).json({ message: "Failed to delete address." });
    }
});


// ==============================================
// --- MENU & ADMIN ROUTES (Unchanged) ---
// ==============================================

app.get('/api/menu', async (req, res) => {
    try {
        const items = await MenuItem.find({ isAvailable: true }).sort({ createdAt: -1 });
        res.json(items);
    } catch (error) {
        console.error("Get Menu Error:", error);
        res.status(500).json({ message: "Failed to load menu items." });
    }
});

app.post('/api/admin/menu', verifyAdmin, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: "Please upload an image file." });
        const rawData = req.body;
        const price = rawData.price ? parseFloat(rawData.price) : null;
        const discountPercent = rawData.discountPercent ? parseFloat(rawData.discountPercent) : 0;
        if (!rawData.name || !price || !rawData.category) {
             fs.unlinkSync(req.file.path);
             return res.status(400).json({ message: "Missing required fields (name, price, category)." });
        }
        const imagePath = req.file.path.replace(/\\/g, "/"); 
        const newItem = new MenuItem({ name: rawData.name, description: rawData.description, price: price, image: imagePath, category: rawData.category, discountPercent: discountPercent });
        await newItem.save();
        res.status(201).json({ message: "Menu item added successfully!", item: newItem });
    } catch (error) {
        console.error("Add Menu Item Error:", error);
        if (req.file) fs.unlinkSync(req.file.path);
        res.status(500).json({ message: "Failed to add menu item. Check server logs." });
    }
});

app.put('/api/admin/menu/:id', verifyAdmin, upload.single('image'), async (req, res) => {
    try {
        const rawData = req.body;
        const updateData = {};
        if (rawData.name) updateData.name = rawData.name;
        if (rawData.description) updateData.description = rawData.description;
        if (rawData.category) updateData.category = rawData.category;
        if (rawData.price !== undefined && rawData.price !== '') updateData.price = parseFloat(rawData.price);
        if (rawData.discountPercent !== undefined && rawData.discountPercent !== '') updateData.discountPercent = parseFloat(rawData.discountPercent);
        if (req.file) { updateData.image = req.file.path.replace(/\\/g, "/"); }
        const updatedItem = await MenuItem.findByIdAndUpdate(req.params.id, updateData, { new: true, runValidators: true });
        if (!updatedItem) return res.status(404).json({ message: "Item not found." });
        res.json({ message: "Item updated successfully!", item: updatedItem });
    } catch (error) {
        console.error("Update Menu Item Error:", error);
        if (req.file) fs.unlinkSync(req.file.path);
        res.status(500).json({ message: "Failed to update item." });
    }
});

app.delete('/api/admin/menu/:id', verifyAdmin, async (req, res) => {
    try {
        const deletedItem = await MenuItem.findByIdAndDelete(req.params.id);
        if (!deletedItem) return res.status(404).json({ message: "Item not found." });
        res.json({ message: "Item deleted successfully!" });
    } catch (error) {
        console.error("Delete Menu Item Error:", error);
        res.status(500).json({ message: "Failed to delete item." });
    }
});


// ==============================================
// --- APP STATUS & TIME SLOT ADMIN ROUTES ---
// ==============================================

// 1. Get current status (for frontend check, now includes time slots)
app.get('/api/app-status', async (req, res) => {
    try {
        const status = await initializeAppStatus();
        res.json({ 
            isOnline: status.isOnline, 
            isTimeSlotEnabled: status.isTimeSlotEnabled,
            timeSlots: status.timeSlots
        });
    } catch (error) {
        res.status(500).json({ message: "Failed to fetch status." });
    }
});

// 2. Toggle main app status (Admin only)
app.put('/api/admin/app-status/toggle', verifyAdmin, async (req, res) => {
    try {
        const status = await initializeAppStatus();
        const newStatus = !status.isOnline;

        const updatedStatus = await AppStatus.findOneAndUpdate(
            { key: 'main_status' },
            { isOnline: newStatus, lastUpdated: new Date() },
            { new: true }
        );
        res.json({ message: `App is now ${newStatus ? 'ONLINE' : 'OFFLINE'}`, isOnline: updatedStatus.isOnline });
    } catch (error) {
        console.error("App Status Toggle Error:", error);
        res.status(500).json({ message: "Failed to toggle status." });
    }
});

// 3. Toggle Time Slot feature (Admin only)
app.put('/api/admin/time-slots/toggle', verifyAdmin, async (req, res) => {
    try {
        const { isTimeSlotEnabled } = req.body;
        if (isTimeSlotEnabled === undefined) {
            return res.status(400).json({ message: "Missing required field: isTimeSlotEnabled" });
        }

        const updatedStatus = await AppStatus.findOneAndUpdate(
            { key: 'main_status' },
            { isTimeSlotEnabled: isTimeSlotEnabled, lastUpdated: new Date() },
            { new: true, upsert: true }
        );
        
        res.json({ 
            message: `Time Slot feature is now ${updatedStatus.isTimeSlotEnabled ? 'ENABLED' : 'DISABLED'}`, 
            isTimeSlotEnabled: updatedStatus.isTimeSlotEnabled 
        });
    } catch (error) {
        console.error("Time Slot Toggle Error:", error);
        res.status(500).json({ message: "Failed to toggle time slot feature." });
    }
});

// 4. Update Time Slots list (Admin only)
app.put('/api/admin/time-slots', verifyAdmin, async (req, res) => {
    try {
        const { timeSlots } = req.body;
        if (!Array.isArray(timeSlots)) {
            return res.status(400).json({ message: "Invalid format. 'timeSlots' must be an array." });
        }

        const updatedStatus = await AppStatus.findOneAndUpdate(
            { key: 'main_status' },
            { timeSlots: timeSlots, lastUpdated: new Date() },
            { new: true, upsert: true }
        );
        
        res.json({ 
            message: "Time slots updated successfully.", 
            timeSlots: updatedStatus.timeSlots 
        });
    } catch (error) {
        console.error("Update Time Slots Error:", error);
        res.status(500).json({ message: "Failed to update time slots." });
    }
});


// ==============================================
// --- SALES ANALYTICS (Unchanged) ---
// ==============================================

// Helper to get date ranges
const getDateRange = (filter) => {
    const now = new Date();
    let start, end = new Date(now);
    end.setHours(23, 59, 59, 999);
    start = new Date(now);
    start.setHours(0, 0, 0, 0);

    switch (filter) {
        case 'today': break;
        case 'week': start.setDate(start.getDate() - start.getDay()); break;
        case 'month': start.setDate(1); break;
        case 'year': start.setMonth(0, 1); break;
        default: start.setDate(1);
    }
    return { start, end };
};


app.get('/api/admin/sales-stats', verifyAdmin, async (req, res) => {
    try {
        const { filter } = req.query; 
        const { start, end } = getDateRange(filter);

        let dateFormat;
        if (filter === 'today') dateFormat = "%H:00";
        else if (filter === 'year') dateFormat = "%Y-%m";
        else dateFormat = "%Y-%m-%d";

        const stats = await Order.aggregate([
            { $match: { createdAt: { $gte: start, $lte: end }, status: { $ne: 'Cancelled' } } },
            { $group: { _id: { $dateToString: { format: dateFormat, date: "$createdAt" } }, totalSales: { $sum: "$totalAmount" }, orderCount: { $sum: 1 } } },
            { $sort: { _id: 1 } }
        ]);

        const grandTotal = stats.reduce((acc, curr) => acc + curr.totalSales, 0);
        const totalOrders = stats.reduce((acc, curr) => acc + curr.orderCount, 0);

        const chartLabels = stats.map(s => s._id);
        const chartData = stats.map(s => s.totalSales);

        res.json({
            summary: { totalSales: grandTotal, totalOrders: totalOrders },
            chart: { labels: chartLabels, data: chartData }
        });

    } catch (error) {
        console.error("Sales Stats Error:", error);
        res.status(500).json({ message: "Failed to fetch sales statistics." });
    }
});

// ==============================================
// --- START SERVER ---
// ==============================================

const PORT = process.env.PORT || 5000;

// IMPORTANT FOR RENDER: Bind host 0.0.0.0
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
