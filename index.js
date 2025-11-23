const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();


const app = express();

const allowedOrigins = [
  "http://localhost:5173",
  "https://utility-bills-a4d38.web.app",
  "https://utility-bills-a4d38.firebaseapp.com"
];



app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
}));

app.use(express.json());


// db connect
const uri = process.env.MONGO_URI;

const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

let cachedDb = null;

async function connectDB() {
  if (cachedDb) return cachedDb;

  if (!client.topology || !client.topology.isConnected()) {
    await client.connect();
  }

  cachedDb = client.db('utility_bill_db');
  return cachedDb;
}

// create token
const createToken = (user) => {
  const payload = {
    email: user.email,
    id: user._id?.toString ? user._id.toString() : user.id || null,
  };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
};

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send({ message: "Unauthorized access" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: "Forbidden access" });
    req.user = decoded;
    next();
  });
};


let seeded = false;

async function seedOnce() {
  if (seeded) return;
  const db = await connectDB();

  const billsCollection = db.collection('bills');
  const usersCollection = db.collection('users');

  const billCount = await billsCollection.countDocuments();
  if (billCount === 0) {
    const sampleBills = [
      { title: "Frequent Power Outage in Mirpur", category: "Electricity", email: "admin@utility.com", location: "Mirpur-10, Dhaka", description: "Power cuts occur daily in the evening.", image: "https://static.theprint.in/wp-content/uploads/2022/04/Electricity_jan28202201281016342022033120475520220401113045.jpg", date: new Date("2025-11-05"), amount: 260 },
      { title: "Gas Cylinder Delay in Mohammadpur", category: "Gas", email: "admin@utility.com", location: "Mohammadpur, Dhaka", description: "Gas delivery is delayed for households.", image: "https://www.tbsnews.net/sites/default/files/styles/big_2/public/images/2023/12/03/369911749_3171331229827167_6338295722403436914_n.jpg", date: new Date("2025-11-06"), amount: 150 },
      { title: "Water Pipeline Maintenance in Motijheel", category: "Water", email: "admin@utility.com", location: "Motijheel, Dhaka", description: "Scheduled water pipeline maintenance.", image: "https://www.citywaterpurifier.com/wp-content/uploads/2023/03/fl15011059300-image-ku5ccz6a.jpg", date: new Date("2025-11-04"), amount: 100 },
      { title: "Internet Router Issue in Mirpur", category: "Internet", email: "admin@utility.com", location: "Mirpur-12, Dhaka", description: "Router malfunction causing internet outage.", image: "https://noboit.com/assets/img/network-and-wifi.jpg", date: new Date("2025-11-03"), amount: 220 },
      { title: "Internet Down in Banani", category: "Internet", email: "admin@utility.com", location: "Banani, Dhaka", description: "Frequent internet disconnection in the area.", image: "https://ecdn.dhakatribune.net/contents/cache/images/800x450x1/uploads/media/2024/07/29/Mobile-internet-down-d60f7d01f02167cb7e9ef583fa170444.jpg", date: new Date("2025-11-08"), amount: 200 },
      { title: "Water Shortage in Gulshan", category: "Water", email: "admin@utility.com", location: "Gulshan, Dhaka", description: "Residents face water shortage during morning hours.", image: "https://ecdn.dhakatribune.net/contents/cache/images/640x359x1/uploads/media/2024/04/23/IMG-20240423-WA0013-9e83c5b7f4d4ec3b028b9761f0f25a16.jpg", date: new Date("2025-11-07"), amount: 120 },
      { title: "Electricity Spike in Uttara", category: "Electricity", email: "admin@utility.com", location: "Uttara, Dhaka", description: "Voltage fluctuation causing appliance damage.", image: "https://static.vecteezy.com/system/resources/thumbnails/018/825/545/small_2x/concrete-electricity-pylon-with-glass-insulators-and-bird-spikes-electric-power-concept-bird-protection-for-power-lines-photo.jpg", date: new Date("2025-11-09"), amount: 300 },
      { title: "Gas Leakage in Dhanmondi", category: "Gas", email: "admin@utility.com", location: "Dhanmondi, Dhaka", description: "Gas supply interruption reported frequently.", image: "https://www.tbsnews.net/sites/default/files/styles/big_2/public/images/2023/04/16/gas.jpeg", date: new Date("2025-11-10"), amount: 180 }
    ];
    await billsCollection.insertMany(sampleBills);
  }

  const userCount = await usersCollection.countDocuments();
  if (userCount === 0) {
    const hashed = await bcrypt.hash("DemoPass1", 10);
    await usersCollection.insertOne({
      name: "Demo User",
      email: "demo@utility.com",
      password: hashed,
      photo: "",
    });
  }

  seeded = true;
}


// ROUTES

app.get("/", async (req, res) => {
  await seedOnce();
  res.send("Utility Bill Management Server is running");
});

// Register
app.post("/auth/register", async (req, res) => {
  try {
    const db = await connectDB();
    const usersCollection = db.collection("users");

    const { name, email, password, photo } = req.body;

    if (!name || !email || !password)
      return res.status(400).send({ message: "Name, email and password required" });

    const uppercase = /[A-Z]/.test(password);
    const lowercase = /[a-z]/.test(password);
    if (!uppercase || !lowercase || password.length < 6)
      return res.status(400).send({ message: "Password must contain uppercase, lowercase and at least 6 chars" });

    const existing = await usersCollection.findOne({ email });
    if (existing) return res.status(400).send({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const userDoc = { name, email, password: hashed, photo: photo || "" };
    const result = await usersCollection.insertOne(userDoc);

    const token = createToken({ email, id: result.insertedId });
    res.send({ message: "Registered successfully", userId: result.insertedId, token });
  } catch (err) {
    res.status(500).send({ message: "Server error" });
  }
});

// auth Login sec 

app.post("/auth/login", async (req, res) => {
  try {
    const db = await connectDB();
    const usersCollection = db.collection("users");

    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send({ message: "Email and password required" });

    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(401).send({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).send({ message: "Invalid credentials" });

    const token = createToken(user);
    res.send({
      message: "Login successful",
      token,
      user: { id: user._id.toString(), name: user.name, email: user.email, photo: user.photo || "" }
    });
  } catch (err) {
    res.status(500).send({ message: "Server error" });
  }
});

// user me

app.get("/users/me", verifyJWT, async (req, res) => {
  try {
    const db = await connectDB();
    const usersCollection = db.collection("users");

    const email = req.user.email;
    const user = await usersCollection.findOne({ email }, { projection: { password: 0 } });

    res.send(user || {});
  } catch (err) {
    res.status(500).send({ message: "Server error" });
  }
});

// all bill sec
app.get("/bills", async (req, res) => {
  try {
    const db = await connectDB();
    const billsCollection = db.collection("bills");

    const all = await billsCollection.find({}).toArray();
    res.send(all.map(b => ({ ...b, _id: b._id.toString() })));
  } catch (err) {
    res.status(500).send({ message: "Failed to fetch bills" });
  }
});

// latest 6 bill homes page
app.get("/bills/latest", async (req, res) => {
  try {
    const db = await connectDB();
    const billsCollection = db.collection("bills");

    const latest = await billsCollection.find({}).sort({ date: -1 }).limit(6).toArray();
    res.send(latest.map(b => ({ ...b, _id: b._id.toString() })));
  } catch (err) {
    res.status(500).send({ message: "Failed to fetch latest bills" });
  }
});

// single one bill
app.get("/bills/:id", async (req, res) => {
  try {
    const db = await connectDB();
    const billsCollection = db.collection("bills");

    const bill = await billsCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!bill) return res.status(404).send({ message: "Bill not found" });

    res.send({ ...bill, _id: bill._id.toString() });
  } catch (err) {
    res.status(500).send({ message: "Failed to fetch bill" });
  }
});

//bill add
app.post("/myBills", verifyJWT, async (req, res) => {
  try {
    const { billId } = req.body;
    if (!billId) return res.status(400).send({ message: "BillId required" });

    const db = await connectDB();
    const billsCollection = db.collection("bills");
    const myBillsCollection = db.collection("myBills");

    const bill = await billsCollection.findOne({ _id: new ObjectId(billId) });
    if (!bill) return res.status(404).send({ message: "Bill not found" });

    await myBillsCollection.insertOne({
      ...bill,
      _id: undefined,
      billId,
      userEmail: req.user.email,
    });

    res.send({ message: "Successfully added" });
  } catch (err) {
    res.status(500).send({ message: "Failed to add bill" });
  }
});

// User list sec
app.get("/myBills", verifyJWT, async (req, res) => {
  try {
    const db = await connectDB();
    const myBillsCollection = db.collection("myBills");

    const list = await myBillsCollection.find({ userEmail: req.user.email }).toArray();
    res.send(list.map(item => ({ ...item, _id: item._id.toString() })));
  } catch (err) {
    res.status(500).send({ message: "Failed to fetch my bills" });
  }
});

// bill Delete
app.delete("/myBills/:id", verifyJWT, async (req, res) => {
  try {
    const db = await connectDB();
    const myBillsCollection = db.collection("myBills");

    const result = await myBillsCollection.deleteOne({ _id: new ObjectId(req.params.id) });

    res.send({ message: "Successfully deleted", deletedCount: result.deletedCount });
  } catch (err) {
    res.status(500).send({ message: "Failed to delete bill" });
  }
});

module.exports = app;
