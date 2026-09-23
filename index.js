const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB se connect ho gaya!'))
  .catch((err) => console.log('Connection mein error:', err));


const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});
const User = mongoose.model('User', userSchema);

const applicationSchema = new mongoose.Schema({
  company: String,
  role: String,
  appliedDate: String,
  status: String,
  userId: String,
});
const Application = mongoose.model('Application', applicationSchema);


function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).send('Token nahi mila, login karo!');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).send('Token invalid hai!');
  }
}


app.post('/signup', async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const newUser = new User({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
  });
  await newUser.save();
  res.send('User bana diya!');
});

app.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.send('User nahi mila!');
  }

  const isMatch = await bcrypt.compare(req.body.password, user.password);
  if (!isMatch) {
    return res.send('Password galat hai!');
  }

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
  res.json({ token, userId: user._id, name: user.name });
});


app.get('/applications', verifyToken, async (req, res) => {
  const apps = await Application.find({ userId: req.userId });
  res.json(apps);
});

app.post('/applications', verifyToken, async (req, res) => {
  const newApp = new Application({
    company: req.body.company,
    role: req.body.role,
    appliedDate: req.body.appliedDate,
    status: 'Applied',
    userId: req.userId,
  });
  await newApp.save();
  res.json(newApp);
});

app.put('/applications/:id', verifyToken, async (req, res) => {
  const updatedApp = await Application.findByIdAndUpdate(
    req.params.id,
    req.body,
    { new: true }
  );
  res.json(updatedApp);
});

app.delete('/applications/:id', verifyToken, async (req, res) => {
  await Application.findByIdAndDelete(req.params.id);
  res.send('Application delete ho gayi!');
});


app.listen(PORT, () => {
  console.log(`Server chal raha hai: http://localhost:${PORT}`);
});