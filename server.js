const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'votre_cle_secrete_super_seure_2026';

app.use(express.json());
app.use(cors());

// Connexion à la base de données SQLite
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) console.error("Erreur de connexion à la base de données", err.message);
  else console.log("Connecté à la base de données SQLite.");
});

// Initialisation de la structure de la base de données
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS user_data (
    user_id INTEGER PRIMARY KEY,
    store_json TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

/**
 * Validation stricte du format de l'e-mail (Regex conforme RFC 5322 standard)
 * Exige une syntaxe valide (ex: utilisateur@domaine.ext) avec un TLD de 2 caractères minimum.
 */
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email.trim());
}

// 1. Inscription d'un professeur avec validation stricte
app.post('/api/register', async (req, res) => {
  let { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "L'email et le mot de passe sont obligatoires." });
  }

  email = email.trim().toLowerCase();

  // Contrôle de la validité de l'e-mail
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "L'adresse e-mail saisie n'est pas valide (ex: nom@domaine.com)." });
  }

  // Contrôle de sécurité sur la longueur du mot de passe
  if (password.length < 6) {
    return res.status(400).json({ error: "Le mot de passe doit contenir au moins 6 caractères." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (email, password, name) VALUES (?, ?, ?)`,
      [email, hashedPassword, name || 'Professeur'],
      function (err) {
        if (err) {
          return res.status(400).json({ error: "Cet e-mail est déjà associé à un compte." });
        }
        res.json({ success: true, message: "Compte créé avec succès !" });
      }
    );
  } catch (e) {
    res.status(500).json({ error: "Erreur serveur lors de l'inscription." });
  }
});

// 2. Connexion d'un professeur
app.post('/api/login', (req, res) => {
  let { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Veuillez fournir un e-mail et un mot de passe." });
  }

  email = email.trim().toLowerCase();

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "Format d'e-mail invalide." });
  }

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) {
      return res.status(400).json({ error: "Email ou mot de passe incorrect." });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: "Email ou mot de passe incorrect." });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, name: user.name });
  });
});

// Middleware de vérification du Token JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Accès refusé. Token manquant." });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Session expirée ou invalide." });
    req.user = user;
    next();
  });
}

// 3. Récupérer les données cloud
app.get('/api/data', verifyToken, (req, res) => {
  db.get(`SELECT store_json FROM user_data WHERE user_id = ?`, [req.user.userId], (err, row) => {
    if (err) return res.status(500).json({ error: "Erreur de lecture des données." });
    if (!row || !row.store_json) return res.json({ success: true, data: null });
    res.json({ success: true, data: JSON.parse(row.store_json) });
  });
});

// 4. Enregistrer / Synchroniser les données cloud
app.post('/api/data', verifyToken, (req, res) => {
  const { storeData } = req.body;
  if (!storeData) return res.status(400).json({ error: "Données invalides." });

  const jsonString = JSON.stringify(storeData);

  db.run(
    `INSERT INTO user_data (user_id, store_json) VALUES (?, ?) 
     ON CONFLICT(user_id) DO UPDATE SET store_json = ?`,
    [req.user.userId, jsonString, jsonString],
    (err) => {
      if (err) return res.status(500).json({ error: "Erreur lors de la sauvegarde." });
      res.json({ success: true, message: "Données synchronisées dans le cloud." });
    }
  );
});

app.listen(PORT, () => {
  console.log(`Serveur SaaS démarré avec validation stricte sur le port ${PORT}`);
});