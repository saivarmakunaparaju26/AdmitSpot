import db from '../../utils/db';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASSWORD,
  },
});

export const register = async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  await db.collection('users').insertOne({ email, password: hashedPassword, verified: false });

  const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1d' });
  await transporter.sendMail({
    to: email,
    subject: 'Email Verification',
    text: `Verify your email: ${process.env.BASE_URL}/api/auth/verify?token=${verificationToken}`,
  });

  res.status(201).send('User registered, please verify your email.');
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await db.collection('users').findOne({ email });
  
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).send('Invalid credentials');
  }
  
  if (!user.verified) {
    return res.status(403).send('Email not verified');
  }

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
};


import db from '../../utils/db';
import Joi from 'joi';

const contactSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().email().required(),
  phone: Joi.string().optional(),
  address: Joi.string().optional(),
  timezone: Joi.string().optional(),
});

export const addContact = async (req, res) => {
  const { error } = contactSchema.validate(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const contact = await db.collection('contacts').insertOne(req.body);
  res.status(201).json(contact);
};

import moment from 'moment-timezone';

export const getContacts = async (req, res) => {
  const { timezone } = req.query;
  const contacts = await db.collection('contacts').find().toArray();
  
  const adjustedContacts = contacts.map(contact => ({
    ...contact,
    createdAt: moment.utc(contact.createdAt).tz(timezone).format(),
    updatedAt: moment.utc(contact.updatedAt).tz(timezone).format(),
  }));
  
  res.json(adjustedContacts);
};

import multer from 'multer';
import Papa from 'papaparse';

const upload = multer({ dest: 'uploads/' });

export const uploadContacts = upload.single('file'), async (req, res) => {
  Papa.parse(req.file.path, {
    header: true,
    complete: async (results) => {
      const contacts = results.data;
      res.status(201).send('Contacts uploaded successfully.');
    },
  });
};




