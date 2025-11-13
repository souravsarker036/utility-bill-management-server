const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware

const allowedOrigins = ['http://localhost:5173'];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    }
}));
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


const seedDataIfEmpty = async (db) => {
  const billsCollection = db.collection('bills');
  const usersCollection = db.collection('users');

  const billCount = await billsCollection.countDocuments();
  if (billCount === 0) {
    const sampleBills = [
      { title: "Frequent Power Outage in Mirpur",
         category: "Electricity",
          email: "admin@utility.com", 
          location: "Mirpur-10, Dhaka", description: "Power cuts occur daily in the evening.", 
          image: "https://static.theprint.in/wp-content/uploads/2022/04/Electricity_jan28202201281016342022033120475520220401113045.jpg", 
          date: new Date("2025-11-05"), 
          amount: 260 },
      { title: "Gas Cylinder Delay in Mohammadpur", category: "Gas", email: "admin@utility.com", location: "Mohammadpur, Dhaka", description: "Gas delivery is delayed for households.", image: "https://www.tbsnews.net/sites/default/files/styles/big_2/public/images/2023/12/03/369911749_3171331229827167_6338295722403436914_n.jpg", date: new Date("2025-11-06"), amount: 150 },
      { title: "Water Pipeline Maintenance in Motijheel", category: "Water", email: "admin@utility.com", location: "Motijheel, Dhaka", description: "Scheduled water pipeline maintenance.", image: "https://www.citywaterpurifier.com/wp-content/uploads/2023/03/fl15011059300-image-ku5ccz6a.jpg", date: new Date("2025-11-04"), amount: 100 },
      { title: "Internet Router Issue in Mirpur", category: "Internet", email: "admin@utility.com", location: "Mirpur-12, Dhaka", description: "Router malfunction causing internet outage.", image: "https://noboit.com/assets/img/network-and-wifi.jpg", date: new Date("2025-11-03"), amount: 220 },
      { title: "Internet Down in Banani", category: "Internet", email: "admin@utility.com", location: "Banani, Dhaka", description: "Frequent internet disconnection in the area.", image: "https://ecdn.dhakatribune.net/contents/cache/images/800x450x1/uploads/media/2024/07/29/Mobile-internet-down-d60f7d01f02167cb7e9ef583fa170444.jpg?jadewits_media_id=25117", date: new Date("2025-11-08"), amount: 200 },
      { title: "Water Shortage in Gulshan", category: "Water", email: "admin@utility.com", location: "Gulshan, Dhaka", description: "Residents face water shortage during morning hours.", image: "https://ecdn.dhakatribune.net/contents/cache/images/640x359x1/uploads/media/2024/04/23/IMG-20240423-WA0013-9e83c5b7f4d4ec3b028b9761f0f25a16.jpg?jadewits_media_id=19139", date: new Date("2025-11-07"), amount: 120 },
      { title: "Electricity Spike in Uttara", category: "Electricity", email: "admin@utility.com", location: "Uttara, Dhaka", description: "Voltage fluctuation causing appliance damage.", image: "https://static.vecteezy.com/system/resources/thumbnails/018/825/545/small_2x/concrete-electricity-pylon-with-glass-insulators-and-bird-spikes-electric-power-concept-bird-protection-for-power-lines-photo.jpg", date: new Date("2025-11-09"), amount: 300 },
      { title: "Gas Leakage in Dhanmondi", category: "Gas", email: "admin@utility.com", location: "Dhanmondi, Dhaka", description: "Gas supply interruption reported frequently.", image: "https://www.tbsnews.net/sites/default/files/styles/big_2/public/images/2023/04/16/gas.jpeg", date: new Date("2025-11-10"), amount: 180 }
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

    // auth

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
    // auth section
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

    //user section creating
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
    app.get('/bills', async (req, res) => {
      try {
        const allBills = await billsCollection.find({}).toArray();
        console.log(allBills)
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

    // mybills

app.post('/myBills', verifyJWT, async (req, res) => {
  try {
    const { billId } = req.body;
    if (!billId) return res.status(400).send({ message: 'BillId required' });

    const bill = await billsCollection.findOne({ _id: new ObjectId(billId) });
    if (!bill) return res.status(404).send({ message: 'Bill not found' });

    const user = await usersCollection.findOne({ _id: new ObjectId(req.user.id) });
    if (!user) return res.status(404).send({ message: 'User not found' });

    const myBill = {
      billId: bill._id.toString(),
      userId: req.user.id,
      username: user.name,
      email: user.email,
      phone: user.phone || "",
      title: bill.title,
      category: bill.category,
      date: bill.date,
      amount: bill.amount,
      address: user.address || ""
    };

    await myBillsCollection.insertOne(myBill);
    res.send({ message: 'Bill added to my bills', myBill });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Failed to add to my bills' });
  }
});

//all bills 
app.get('/myBills', verifyJWT, async (req, res) => {
  try {
    const bills = await myBillsCollection.find({ userId: req.user.id }).toArray();
    res.send(bills);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Failed to fetch my bills' });
  }
});

// Total

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


// Delete myBill

app.delete('/myBills/:id', verifyJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await myBillsCollection.deleteOne({ _id: new ObjectId(id), userId: req.user.id });
    if (result.deletedCount === 0) return res.status(404).send({ message: 'Bill not found or not authorized' });
    res.send({ message: 'Deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Delete failed' });
  }
});

// Update myBill
app.put('/myBills/:id', verifyJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount, phone, date, address } = req.body;
    const result = await myBillsCollection.updateOne(
      { _id: new ObjectId(id), userId: req.user.id },
      { $set: { amount, phone, date, address } }
    );
    if (result.matchedCount === 0) return res.status(404).send({ message: 'Bill not found or not authorized' });
    res.send({ message: 'Updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Update failed' });
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