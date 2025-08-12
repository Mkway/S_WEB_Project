const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Vulnerable endpoint for Prototype Pollution
app.post('/prototype_pollution', (req, res) => {
    // Simulate a vulnerable merge operation
    // In a real app, this would be a vulnerable library function
    // that doesn't properly sanitize keys like '__proto__'.
    
    function assignDeep(target, source) {
        for (const key in source) {
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                // This is the missing check in vulnerable implementations
                // For demonstration, we'll allow it to show the vulnerability
            }
            if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                if (!target[key] || typeof target[key] !== 'object') {
                    target[key] = {};
                }
                assignDeep(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }

    let userControlledObject = {};
    assignDeep(userControlledObject, req.body); // This is where the pollution would happen

    // Now, check if Object.prototype was polluted
    // This is the actual test for pollution
    if (({}).pollutedProperty === 'polluted') {
        res.json({ message: 'Prototype polluted!', status: 'vulnerable', test_result: 'Object.prototype.pollutedProperty is now "polluted"' });
    } else {
        res.json({ message: 'Prototype not polluted yet. Send a payload like {"__proto__": {"pollutedProperty": "polluted"}}', status: 'safe' });
    }
});

app.get('/', (req, res) => {
    res.send('Node.js app is running. Try POSTing to /prototype_pollution with JSON body.');
});

app.listen(port, () => {
    console.log(`Node.js app listening at http://localhost:${port}`);
});
