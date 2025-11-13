// index.js
const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

// JWT creation
const createToken = (user) => {
  const payload = { email: user.email, id: user._id?.toString ? user._id.toString() : user.id || null };
  return jwt.sign(payload, process.env.JWT_SECRET || 'change_this_secret', { expiresIn: '7d' });
};

// JWT middleware
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send({ message: "Unauthorized access" });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET || 'change_this_secret', (err, decoded) => {
    if (err) return res.status(403).send({ message: "Forbidden access" });
    req.user = decoded;
    next();
  });
};

// Seed data if empty
const seedDataIfEmpty = async (db) => {
  const billsCollection = db.collection('bills');
  const usersCollection = db.collection('users');

  const billCount = await billsCollection.countDocuments();
  if (billCount === 0) {
    const sampleBills = [
      { title: "Frequent Power Outage in Mirpur", category: "Electricity", email: "admin@utility.com", location: "Mirpur-10, Dhaka", description: "Power cuts occur daily in the evening.", image: "https://via.placeholder.com/600x400?text=Electricity+1", date: new Date("2025-11-05"), amount: 260 },
      { title: "Gas Cylinder Delay in Mohammadpur", category: "Gas", email: "admin@utility.com", location: "Mohammadpur, Dhaka", description: "Gas delivery is delayed for households.", image: "https://via.placeholder.com/600x400?text=Gas+2", date: new Date("2025-11-06"), amount: 150 },
      { title: "Water Pipeline Maintenance in Motijheel", category: "Water", email: "admin@utility.com", location: "Motijheel, Dhaka", description: "Scheduled water pipeline maintenance.", image: "https://via.placeholder.com/600x400?text=Water+2", date: new Date("2025-11-04"), amount: 100 },
      { title: "Internet Router Issue in Mirpur", category: "Internet", email: "admin@utility.com", location: "Mirpur-12, Dhaka", description: "Router malfunction causing internet outage.", image: "https://via.placeholder.com/600x400?text=Internet+2", date: new Date("2025-11-03"), amount: 220 },
      { title: "Internet Down in Banani", category: "Internet", email: "admin@utility.com", location: "Banani, Dhaka", description: "Frequent internet disconnection in the area.", image: "https://via.placeholder.com/600x400?text=Internet+1", date: new Date("2025-11-08"), amount: 200 },
      { title: "Water Shortage in Gulshan", category: "Water", email: "admin@utility.com", location: "Gulshan, Dhaka", description: "Residents face water shortage during morning hours.", image: "https://via.placeholder.com/600x400?text=Water+1", date: new Date("2025-11-07"), amount: 120 },
      { title: "Electricity Spike in Uttara", category: "Electricity", email: "admin@utility.com", location: "Uttara, Dhaka", description: "Voltage fluctuation causing appliance damage.", image: "https://via.placeholder.com/600x400?text=Electricity+2", date: new Date("2025-11-09"), amount: 300 },
      { title: "Gas Leakage in Dhanmondi", category: "Gas", email: "admin@utility.com", location: "Dhanmondi, Dhaka", description: "Gas supply interruption reported frequently.", image: "https://via.placeholder.com/600x400?text=Gas+1", date: new Date("2025-11-10"), amount: 180 }
    ];
    await billsCollection.insertMany(sampleBills);
    console.log('Seeded bills collection with 8 sample bills.');
  }

  const userCount = await usersCollection.countDocuments();
  if (userCount === 0) {
    const demoPassword = 'DemoPass1';
    const hashed = await bcrypt.hash(demoPassword, 10);
    const demoUser = { name: 'Demo User', email: 'demo@utility.com', password: hashed, photo: '' };
    await usersCollection.insertOne(demoUser);
    console.log(`Seeded users collection with demo user (email: demo@utility.com, password: ${demoPassword})`);
  }
};

// Main run
async function run() {
  try {
    await client.connect();
    const db = client.db('utility_bill_db');
    const usersCollection = db.collection('users');
    const billsCollection = db.collection('bills');
    const myBillsCollection = db.collection('myBills');

    await seedDataIfEmpty(db);

    app.get('/', (req, res) => res.send('Utility Bill Management Server is running'));

    // ---------------- AUTH ----------------
    app.post('/auth/register', async (req, res) => {
      try {
        const { name, email, password, photo } = req.body;
        if (!name || !email || !password) return res.status(400).send({ message: 'Name, email and password required' });
        const uppercase = /[A-Z]/.test(password);
        const lowercase = /[a-z]/.test(password);
        if (!uppercase || !lowercase || password.length < 6)
          return res.status(400).send({ message: 'Password must contain uppercase, lowercase and at least 6 chars' });

        const existing = await usersCollection.findOne({ email });
        if (existing) return res.status(400).send({ message: 'User already exists' });

        const hashed = await bcrypt.hash(password, 10);
        const userDoc = { name, email, password: hashed, photo: photo || '' };
        const result = await usersCollection.insertOne(userDoc);

        const token = createToken({ email, id: result.insertedId });
        res.send({ message: 'Registered successfully', userId: result.insertedId, token });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Server error' });
      }
    });

    app.post('/auth/login', async (req, res) => {
      try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).send({ message: 'Email and password required' });
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(401).send({ message: 'Invalid credentials' });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).send({ message: 'Invalid credentials' });

        const token = createToken(user);
        const userInfo = { id: user._id.toString(), name: user.name, email: user.email, photo: user.photo || '' };
        res.send({ message: 'Login successful', token, user: userInfo });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Server error' });
      }
    });

    // ---------------- USERS ----------------
    app.get('/users/me', verifyJWT, async (req, res) => {
      try {
        const email = req.user.email;
        const user = await usersCollection.findOne({ email }, { projection: { password: 0 } });
        res.send(user || {});
      } catch (err) {
        res.status(500).send({ message: 'Server error' });
      }
    });

    // ---------------- BILLS ----------------
    app.get('/bills', async (req, res) => {
      try {
        const allBills = await billsCollection.find({}).toArray();
        const bills = allBills.map(b => ({ ...b, _id: b._id.toString() }));
        res.send(bills);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to fetch bills' });
      }
    });

    app.get('/bills/latest', async (req, res) => {
      try {
        const latestBills = await billsCollection.find({}).sort({ date: -1 }).limit(6).toArray();
        const bills = latestBills.map(b => ({ ...b, _id: b._id.toString() }));
        res.send(bills);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to fetch latest bills' });
      }
    });

    app.get('/bills/:id', async (req, res) => {
      try {
        const bill = await billsCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!bill) return res.status(404).send({ message: 'Bill not found' });
        res.send({ ...bill, _id: bill._id.toString() });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to fetch bill' });
      }
    });

    // ---------------- MY BILLS ----------------
    app.post('/myBills', verifyJWT, async (req, res) => {
      try {
        const { billId } = req.body;
        if (!billId) return res.status(400).send({ message: 'BillId required' });

        const bill = await billsCollection.findOne({ _id: new ObjectId(billId) });
        if (!bill) return res.status(404).send({ message: 'Bill not found' });

        const myBill = {
          billId: bill._id.toString(),
          userId: req.user.id,
          title: bill.title,
          category: bill.category,
          date: bill.date,
          amount: bill.amount
        };

        await myBillsCollection.insertOne(myBill);
        res.send({ message: 'Bill added to my bills', myBill });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to add to my bills' });
      }
    });

    app.get('/myBills', verifyJWT, async (req, res) => {
      try {
        const bills = await myBillsCollection.find({ userId: req.user.id }).toArray();
        res.send(bills);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to fetch my bills' });
      }
    });

    app.get('/myBills/total', verifyJWT, async (req, res) => {
      try {
        const bills = await myBillsCollection.find({ userId: req.user.id }).toArray();
        const total = bills.reduce((sum, b) => sum + (b.amount || 0), 0);
        res.send({ total });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to fetch total' });
      }
    });

    console.log('Connected to MongoDB successfully');
  } catch (err) {
    console.error('Failed to connect or run server:', err);
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`Utility Bill Management Server running on port ${port}`);
});
