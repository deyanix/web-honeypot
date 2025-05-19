const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const Handlebars = require('handlebars');
const { MongoClient } = require('mongodb');
const geoip = require('geoip-lite');

const honeypotType = process.env.HONEYPOT_TYPE ?? 'standard';

const app = express();
const mongo = new MongoClient(process.env.HONEYPOT_MONGO_URL);

// Middleware do przechwytywania danych
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(`forms/${honeypotType}/public`));

// Funkcja do klasyfikacji haseł
const classifyPassword = (password) => {
    if (!password) return 'empty';
    if (/^[a-z]+$/i.test(password)) return 'letters_only';
    if (/^[0-9]+$/.test(password)) return 'numbers_only';
    if (/^[a-z0-9]+$/i.test(password)) return 'alphanumeric';
    return 'complex';
};

// Obsługa formularza
const route = honeypotType !== 'wordpress' ? '/' : '/wp-admin';

app.get(route, (req, res) => {
    const template = Handlebars.compile(
        fs.readFileSync(`./forms/${honeypotType}/index.html.hbs`, 'utf8')
    );

    res.send(template({ dirty: false }));
});

app.post(route, async (req, res) => {
    try {
        const { username, password } = req.body;
        const timestamp = new Date().toISOString();
        const passwordLength = password ? password.length : 0;
        const passwordType = classifyPassword(password);
        const publicIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

        const geo = geoip.lookup(publicIp.replace(/::ffff:/, ''));
        const country = geo && geo.country ? geo.country : "none";

        const logEntry = `timestamp="${new Date().toISOString()}" username="${username}" password="${password}" passwordLength="${passwordLength}" passwordType="${passwordType}" ip="${publicIp.replace(/::ffff:/, '')}" country="${country}"\n`;
        fs.appendFileSync('./logs/honeypot.log', logEntry);

        // Zapis do MongoDB (z pełnymi danymi)
        await mongo.db()
            .collection(process.env.HONEYPOT_MONGO_COLLECTION)
            .insertOne({
                ip: req.ip,
                username: username,
                password: password,
                password_length: passwordLength,
                password_type: passwordType,
                timestamp: new Date()
            });
        const template = Handlebars.compile(
            fs.readFileSync(`./forms/${honeypotType}/index.html.hbs`, 'utf8')
        );
        res.send(template({ dirty: true, username }));
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
