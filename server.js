const express = require('express');
const path = require('path');
const app = express();
const port = 3000;

// Serve static files from the public directory
app.use(express.static('public'));

// Serve index.html at the root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
    console.log(`Threat Hunter app listening at http://localhost:${port}`);
});
