const express = require('express');
const path = require('path');
const app = express();
const port = 3000;

// Serve static files from the public directory
app.use(express.static('public'));
app.use(express.json());

// Serve index.html at the root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve queryLangs.json
app.get('/queryLangs.json', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'queryLangs.json'));
});

app.listen(port, () => {
    console.log(`Threat Hunter app listening at http://localhost:${port}`);
});
