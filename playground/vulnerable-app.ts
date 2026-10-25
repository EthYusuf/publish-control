import express from 'express';
import cors from 'cors';

const app = express();

// 1. Zafiyet: Wildcard CORS ve Credentials
app.use(cors({ origin: '*', credentials: true }));

// 2. Zafiyet: Hardcoded Secret & AWS Key
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const JWT_SECRET = "supersecret123456";

// 3. Zafiyet: SQL Injection
app.get('/users', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query);
});

// 4. Zafiyet: eval() kullanımı (Code Injection)
app.post('/calc', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

// 5. Zafiyet: Hassas veri loglama
app.post('/login', (req, res) => {
  console.log("Giriş yapıldı, şifre:", req.body.password);
  res.send("OK");
});

// 6. Zafiyet: 0.0.0.0 tüm arayüzlere bağlanma
app.listen(3000, '0.0.0.0');
