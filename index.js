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

// mongodb connection
const uri = process.env.MONGO_URI || `mongodb+srv://utilityBillManagement:Z4IRithpsz3M4uyw@noobcreation.g1ic2tl.mongodb.net/?appName=noobCreation`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// create JWT

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
    req.user = decoded; // { email, id, iat, exp }
    next();
  });
};

// Seed data 8 bills demo user 

const seedDataIfEmpty = async (db) => {
  const billsCollection = db.collection('bills');
  const usersCollection = db.collection('users');

  const billCount = await billsCollection.countDocuments();
  if (billCount === 0) {
    const sampleBills = [
      {
        title: "Frequent Power Outage in Mirpur",
        category: "Electricity",
        email: "admin@utility.com",
        location: "Mirpur-10, Dhaka",
        description: "Power cuts occur daily in the evening.",
        image: "https://via.placeholder.com/600x400?text=Electricity+1",
        date: "2025-11-05",
        amount: 260
      },
      {
        title: "Gas Leakage in Dhanmondi",
        category: "Gas",
        email: "admin@utility.com",
        location: "Dhanmondi, Dhaka",
        description: "Gas supply interruption reported frequently.",
        image: "https://via.placeholder.com/600x400?text=Gas+1",
        date: "2025-11-10",
        amount: 180
      },
      {
        title: "Water Shortage in Gulshan",
        category: "Water",
        email: "admin@utility.com",
        location: "Gulshan, Dhaka",
        description: "Residents face water shortage during morning hours.",
        image: "https://via.placeholder.com/600x400?text=Water+1",
        date: "2025-11-07",
        amount: 120
      },
      {
        title: "Internet Down in Banani",
        category: "Internet",
        email: "admin@utility.com",
        location: "Banani, Dhaka",
        description: "Frequent internet disconnection in the area.",
        image: "https://via.placeholder.com/600x400?text=Internet+1",
        date: "2025-11-08",
        amount: 200
      },
      {
        title: "Electricity Spike in Uttara",
        category: "Electricity",
        email: "admin@utility.com",
        location: "Uttara, Dhaka",
        description: "Voltage fluctuation causing appliance damage.",
        image: "https://via.placeholder.com/600x400?text=Electricity+2",
        date: "2025-11-09",
        amount: 300
      },
      {
        title: "Gas Cylinder Delay in Mohammadpur",
        category: "Gas",
        email: "admin@utility.com",
        location: "Mohammadpur, Dhaka",
        description: "Gas delivery is delayed for households.",
        image: "https://via.placeholder.com/600x400?text=Gas+2",
        date: "2025-11-06",
        amount: 150
      },
      {
        title: "Water Pipeline Maintenance in Motijheel",
        category: "Water",
        email: "admin@utility.com",
        location: "Motijheel, Dhaka",
        description: "Scheduled water pipeline maintenance.",
        image: "https://via.placeholder.com/600x400?text=Water+2",
        date: "2025-11-04",
        amount: 100
      },
      {
        title: "Internet Router Issue in Mirpur",
        category: "Internet",
        email: "admin@utility.com",
        location: "Mirpur-12, Dhaka",
        description: "Router malfunction causing internet outage.",
        image: "https://via.placeholder.com/600x400?text=Internet+2",
        date: "2025-11-03",
        amount: 220
      }
    ];
    await billsCollection.insertMany(sampleBills);
    console.log('Seeded bills collection with 8 sample bills.');
  }

  const userCount = await usersCollection.countDocuments();
  if (userCount === 0) {
    const demoPassword = 'DemoPass1'; 
    const hashed = await bcrypt.hash(demoPassword, 10);
    const demoUser = {
      name: 'Demo User',
      email: 'demo@utility.com',
      password: hashed,
      photo: ''
    };
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

    // Seed if empty

    await seedDataIfEmpty(db);

    // Root

    app.get('/', (req, res) => res.send('Utility Bill Management Server is running'));

    // user section

    // Register part

    app.post('/users/register', async (req, res) => {
      try {
        const { name, email, password, photo } = req.body;
        if (!name || !email || !password) return res.status(400).send({ message: 'Name, email and password are required' });

        // Password validation check

        const uppercase = /[A-Z]/.test(password);
        const lowercase = /[a-z]/.test(password);
        if (!uppercase || !lowercase || password.length < 6) {
          return res.status(400).send({ message: 'Password must contain uppercase, lowercase and be at least 6 characters' });
        }

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

    // Login

    app.post('/users/login', async (req, res) => {
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

    //get current user token

    app.get('/users/me', verifyJWT, async (req, res) => {
      try {
        const email = req.user.email;
        const user = await usersCollection.findOne({ email }, { projection: { password: 0 } });
        res.send(user || {});
      } catch (err) {
        res.status(500).send({ message: 'Server error' });
      }
    });

    // bills section

    // get bill category serch and all the thing

    app.get('/bills', async (req, res) => {
      try {
        const { category, search, page = 1, limit = 12, sort } = req.query;
        const q = {};
        if (category) q.category = category;
        if (search) {
          const s = search.trim();
          q.$or = [
            { title: { $regex: s, $options: 'i' } },
            { description: { $regex: s, $options: 'i' } },
            { location: { $regex: s, $options: 'i' } },
          ];
        }

        let cursor = billsCollection.find(q);

        if (sort === 'date_asc') cursor = cursor.sort({ date: 1 });
        else cursor = cursor.sort({ date: -1 }); 

        const pageNum = parseInt(page, 10);
        const lim = parseInt(limit, 10);
        const total = await billsCollection.countDocuments(q);
        const bills = await cursor.skip((pageNum - 1) * lim).limit(lim).toArray();

        res.send({ total, page: pageNum, limit: lim, bills });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Server error' });
      }
    });

    // Latest 6 home bills 

    app.get('/bills/latest', async (req, res) => {
      try {
        const bills = await billsCollection.find().sort({ date: -1 }).limit(6).toArray();
        res.send(bills);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Server error' });
      }
    });

    // Get single bill

    app.get('/bills/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const bill = await billsCollection.findOne({ _id: new ObjectId(id) });
        if (!bill) return res.status(404).send({ message: 'Bill not found' });
        res.send(bill);
      } catch (err) {
        console.error(err);
        res.status(400).send({ message: 'Invalid bill id' });
      }
    });

    // Add bill 

    app.post('/bills', async (req, res) => {
      try {
        const doc = req.body;
        
        if (!doc.title || !doc.category || !doc.date || typeof doc.amount !== 'number') {
          return res.status(400).send({ message: 'title, category, date and numeric amount are required' });
        }
        const result = await billsCollection.insertOne(doc);
        res.send({ message: 'Bill added', insertedId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Server error' });
      }
    });

    // Update bill

    app.patch('/bills/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const update = req.body;
        const result = await billsCollection.updateOne({ _id: new ObjectId(id) }, { $set: update });
        res.send({ message: 'Bill updated', modifiedCount: result.modifiedCount });
      } catch (err) {
        console.error(err);
        res.status(400).send({ message: 'Invalid bill id or data' });
      }
    });

    // Delete bill

    app.delete('/bills/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const result = await billsCollection.deleteOne({ _id: new ObjectId(id) });
        res.send({ message: 'Bill deleted', deletedCount: result.deletedCount });
      } catch (err) {
        console.error(err);
        res.status(400).send({ message: 'Invalid bill id' });
      }
    });

    // my bill section for a user------

    // Pay a bill for current month 
    app.post('/myBills', verifyJWT, async (req, res) => {
      try {
        const userEmail = req.user.email;
        const { billId, username, phone, address, additionalInfo } = req.body;
        if (!billId || !username || !phone || !address) {
          return res.status(400).send({ message: 'billId, username, phone and address are required' });
        }

        // find user bill

        const bill = await billsCollection.findOne({ _id: new ObjectId(billId) });
        if (!bill) return res.status(404).send({ message: 'Bill not found' });

        // bill date creating 

        const billDate = new Date(bill.date);
        if (isNaN(billDate.getTime())) {
          return res.status(400).send({ message: 'Bill has invalid date format' });
        }

        const current = new Date();
        if (billDate.getMonth() !== current.getMonth() || billDate.getFullYear() !== current.getFullYear()) {
          return res.status(400).send({ message: 'Only current month bills can be paid' });
        }

        const payment = {
          billId: bill._id.toString(),
          username,
          email: userEmail,
          phone,
          address,
          amount: bill.amount,
          date: new Date().toISOString().slice(0, 10), 
          additionalInfo: additionalInfo || '',
          userId: req.user.id || null
        };

        const result = await myBillsCollection.insertOne(payment);
        res.send({ message: 'Bill paid successfully', insertedId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Server error' });
      }
    });

    // get log-in user's paid bill

    app.get('/myBills', verifyJWT, async (req, res) => {
      try {
        const userEmail = req.user.email;
        const bills = await myBillsCollection.find({ email: userEmail }).sort({ date: -1 }).toArray();
        res.send(bills);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Server error' });
      }
    });

    // update a myBill entry for owner log in 

    app.patch('/myBills/:id', verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const userEmail = req.user.email;
        // update user bio

        const update = req.body; 
        const allowedFields = {};
        ['username','phone','address','amount','date','additionalInfo'].forEach(f => {
          if (update[f] !== undefined) allowedFields[f] = update[f];
        });

        const result = await myBillsCollection.updateOne({ _id: new ObjectId(id), email: userEmail }, { $set: allowedFields });
        if (result.matchedCount === 0) return res.status(404).send({ message: 'Bill not found or not owned by you' });
        res.send({ message: 'MyBill updated', modifiedCount: result.modifiedCount });
      } catch (err) {
        console.error(err);
        res.status(400).send({ message: 'Invalid id or data' });
      }
    });

    // delete myBill entry 

    app.delete('/myBills/:id', verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const userEmail = req.user.email;
        const result = await myBillsCollection.deleteOne({ _id: new ObjectId(id), email: userEmail });
        if (result.deletedCount === 0) return res.status(404).send({ message: 'Bill not found or not owned by you' });
        res.send({ message: 'Deleted successfully' });
      } catch (err) {
        console.error(err);
        res.status(400).send({ message: 'Invalid id' });
      }
    });

    // totals bills for log-in user

    app.get('/myBills/total', verifyJWT, async (req, res) => {
      try {
        const userEmail = req.user.email;
        const bills = await myBillsCollection.find({ email: userEmail }).toArray();
        const totalAmount = bills.reduce((s, b) => s + (Number(b.amount) || 0), 0);
        res.send({ totalBills: bills.length, totalAmount });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Server error' });
      }
    });

    console.log('Connected to MongoDB successfully');
  } catch (err) {
    console.error('Failed to connect or run server:', err);
  } 
}

run().catch(console.dir);

//server start
app.listen(port, () => {
  console.log(`Utility Bill Management Server running on port ${port}`);
});
