const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const Handlebars = require('handlebars');
const { MongoClient } = require('mongodb');
const client = require('prom-client');
const crypto = require('crypto');

// Inicjalizacja metryk
const register = new client.Registry();
client.collectDefaultMetrics({ register });

const loginAttempts = new client.Counter({
    name: 'honeypot_login_attempts',
    help: 'Total login attempts',
    labelNames: ['ip', 'username', 'password', 'password_length', 'password_type', 'request_id', 'timestamp'] // Bezpieczne etykiety
});

// Rejestracja niestandardowej metryki
register.registerMetric(loginAttempts);

const app = express();
const mongo = new MongoClient(process.env.HONEYPOT_MONGO_URL);

// Middleware do przechwytywania danych
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(`forms/${process.env.HONEYPOT_TYPE}`));

// Funkcja do klasyfikacji haseł
const classifyPassword = (password) => {
    if (!password) return 'empty';
    if (password.length < 4) return 'very_short';
    if (password.length < 8) return 'short';
    if (/^[a-z]+$/i.test(password)) return 'letters_only';
    if (/^[0-9]+$/.test(password)) return 'numbers_only';
    if (/^[a-z0-9]+$/i.test(password)) return 'alphanumeric';
    return 'complex';
};

// Endpoint metrics musi być pierwszy!
app.get('/metrics', async (req, res) => {
    try {
        res.set('Content-Type', register.contentType);
        res.end(await register.metrics());
    } catch (err) {
        console.error('Metrics endpoint error:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Metrics endpoint
/*app.get('/metrics', async (req, res) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
});*/

// Obsługa formularza
const template = Handlebars.compile(
    fs.readFileSync(`./forms/${process.env.HONEYPOT_TYPE}/index.html.hbs`, 'utf8')
);

app.get('/', (req, res) => {
    res.send(template({ dirty: false }));
});

app.post('/', async (req, res) => {
    try {
        const { username, password } = req.body;
        const requestId = crypto.randomUUID();
        const timestamp = new Date().toISOString();
        const passwordLength = password ? password.length : 0;
        const passwordType = classifyPassword(password);
        const passwordSample = password
            ? crypto.createHash('sha256').update(password).digest('hex').substring(0, 6)
            : 'empty';

        console.log(`Login attempt from ${req.ip}:`, {
            username,
            password,
            password_length: passwordLength,
            password_type: passwordType,
            request_id: requestId,
            timestamp: timestamp
        });

        // Aktualizacja metryki z bezpiecznymi danymi
        loginAttempts.labels({
            ip: req.ip.replace(/::ffff:/, ''),
            username: username || 'unknown',
            password: password,
            password_length: passwordLength.toString(),
            password_type: passwordType,
            request_id: requestId,
            timestamp: timestamp
        }).inc();

        // Zapis do MongoDB (z pełnymi danymi)
        await mongo.db()
            .collection(process.env.HONEYPOT_MONGO_COLLECTION)
            .insertOne({
                ip: req.ip,
                username: username,
                password: password, // Hasło w plaintext tylko w bazie
                password_hash: passwordSample, // Skrót dla bezpieczeństwa
                password_length: passwordLength,
                password_type: passwordType,
                timestamp: new Date()
            });

        res.send(template({ dirty: true }));
    } catch (err) {
        console.error('Error processing request:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Inicjalizacja
app.listen(process.env.HONEYPOT_PORT || 80, async () => {
    try {
        await mongo.connect();
        console.log(`✅ Honeypot active on port ${process.env.HONEYPOT_PORT || 80}`);
        console.log('🔗 MongoDB connected:', mongo.options.hosts);
    } catch (err) {
        console.error('⛔ Failed to start:', err);
        process.exit(1);
    }
});
