const mysql = require("mysql");
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
require("dotenv").config();
const app = express();

// Middleware
app.use(bodyParser.json());

// Configurer CORS
app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Connect to the database
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

connection.connect((err) => {
  if (err) throw err;
  console.log("Connected to the database");
});

// Middleware pour authentifier le token JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Récupérer uniquement le token

  if (!token) return res.sendStatus(401); // Si aucun token n'est trouvé

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Token invalide
    req.user = user; // Ajouter les infos du token à la requête
    next();
  });
};

// Login endpoint
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  const query = "SELECT * FROM Users WHERE email = ?";
  connection.query(query, [email], (error, results) => {
    if (error) {
      res.status(500).json({ error: "Internal server error" });
      return;
    }

    if (results.length > 0) {
      const user = results[0];

      // Comparer le mot de passe envoyé avec celui dans la DB (en utilisant bcrypt si crypté)
      if (password === user.password) {
        const token = jwt.sign(
          {
            id: user.id,
            firstname: user.firstname,
            lastname: user.lastname,
            email: user.email,
            address: user.address,
            dateOfCreation: user.dateOfCreation,
          },
          process.env.JWT_SECRET,
          {
            expiresIn: "1h",
          }
        );

        res.json({
          message: "Login successful",
          token,
          user: {
            id: user.id,
            firstname: user.firstname,
            lastname: user.lastname,
            email: user.email,
            address: user.address,
            dateOfCreation: user.dateOfCreation,
          },
        });
      } else {
        res.status(401).json({ error: "Invalid email or password" });
      }
    } else {
      res.status(401).json({ error: "Invalid email or password" });
    }
  });
});

// Endpoint pour récupérer les infos de l'utilisateur via le JWT
app.get("/api/user", authenticateToken, (req, res) => {
  const query =
    "SELECT id, firstname, lastname, email, address, mobile, dateOfCreation FROM Users WHERE id = ?";
  connection.query(query, [req.user.id], (error, results) => {
    if (error) {
      res.status(500).json({ error: "Internal server error" });
      return;
    }

    if (results.length > 0) {
      res.json(results[0]); // Renvoie les informations de l'utilisateur
    } else {
      res.status(404).json({ error: "User not found" });
    }
  });
});

// Start the server
app.listen(3000, () => {
  console.log("Server is running on port 3000");
});

//GET pour récupérer l'ensemble des ORDERS d'un USER
app.get("/api/orders", authenticateToken, (req, res) => {
  const query = "SELECT * FROM Orders WHERE userId = ?";
  connection.query(query, [req.user.id], (error, results) => {
    if (error) {
      res.status(500).json({ error: "Internal server error" });
      return;
    }
    if (results.length > 0) {
      res.json(results); // Renvoie les commandes obtenues
    } else {
      res.status(404).json({ error: "No orders found" });
    }
  });
});

//GET pour récupérer l'ensemble des ORDERPRODUCTS d'un USER
app.get("/api/orderProducts", authenticateToken, (req, res) => {
  const query = `
    SELECT OrderProducts.productId, OrderProducts.quantity
    FROM OrderProducts
    INNER JOIN Orders ON Orders.id = OrderProducts.orderId
    WHERE Orders.userId = ?
  `;
  connection.query(query, [req.user.id], (error, results) => {
    if (error) {
      res.status(500).json({ error: "Internal server error" });
      return;
    }
    if (results.length > 0) {
      res.json(results); // Renvoie les produits associés aux commandes de l'utilisateur
    } else {
      res.status(404).json({ error: "No product references found for the user" });
    }
  });
});



//GET pour récuperer l'ensemble des PRODUCTS
app.get("/api/products", (req, res) => {
  const query = "SELECT * FROM Products";
  connection.query(query, (error, results) => {
    if (error) {
      res.status(500).json({ error: "Internal server error" });
      return;
    }
    if (results.length > 0) {
      res.json(results); // Renvoie les produits obtenus
    } else {
      res.status(404).json({ error: "No products found" });
    }
  });
});
