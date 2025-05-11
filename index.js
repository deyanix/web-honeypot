const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const Handlebars = require('handlebars');
const { MongoClient } = require('mongodb');

const mongo = new MongoClient(process.env.HONEYPOT_MONGO_URL);

const app = express()
app.use(bodyParser.urlencoded())
app.use(bodyParser.json())

const port = process.env.HONEYPOT_PORT || 80;

const templateContent = fs.readFileSync('./forms/standard/index.html.hbs', 'utf8');
const template = Handlebars.compile(templateContent);

app.get('/', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(template({ dirty: false }));
});

app.post('/', async (req, res) => {
    await mongo.db().collection(process.env.HONEYPOT_MONGO_COLLECTION).insertOne({
        ip: req.ip,
        data: req.body,
    });

    res.setHeader('Content-Type', 'text/html');
    res.send(template({ dirty: true }))
})

app.listen(port, async () => {
    console.log(`Example app listening on port ${port}`);
    await mongo.connect();
});
