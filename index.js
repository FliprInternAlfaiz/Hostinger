const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');

const encrypt = require('./encrypt-function');
const ayushman_function = require('./ayushman-function');
const auth = require('./auth-function');

const app = express();
const port = 4000;
const strict_pass = "Rxp5MUcc0sunq67eDQe7MZfQzZ3n9mLWAMWTkB3B8Ik4SWh50Gw7T18alRU0t83u";

app.use(cors());                                                        // Use cors middleware to allow all origins
app.use(express.json({ limit: '10mb' }));                               // Increase JSON payload limit
app.use(express.urlencoded({ limit: '10mb', extended: true }));         // Increase URL-encoded payload limit
app.use(bodyParser.json());

// start encryption endpoints

app.post('/encrypt', (req, res) => {
    const { pass, value } = req.body;
    if (!pass || !value) { return res.status(400).json({ status: false, msg: "Password and value are required." }); }
    try {
        const result = encrypt.encrypt(pass, value);
        res.json({ status: true, msg: "success", result: result });
    } catch (error) {
        res.status(500).json({ status: false, msg: "Encryption failed.", error: error.message });
    }
});

app.post('/decrypt', (req, res) => {
    const { pass, value } = req.body;
    if (!pass || !value) { return res.status(400).json({ status: false, msg: "Password and value are required." }); }
    try {
        const result = encrypt.decrypt(pass, value);
        res.json({ status: true, msg: "success", result: result });
    } catch (error) {
        res.status(500).json({ status: false, msg: "Decryption failed.", error: error.message });
    }
});

app.post('/encrypt-json', (req, res) => {
    const { value } = req.body;
    if (!value) { return res.status(400).json({ status: false, msg: "JSON array are required." }); }
    try {
        const result = encrypt.encryptWithKey(value, strict_pass);
        res.json({ status: true, msg: "success", result: result });
    } catch (error) {
        res.status(500).json({ status: false, msg: "Encryption failed.", error: error.message });
    }
});

app.post('/decrypt-json', (req, res) => {
    const { value } = req.body;
    if (!value) { return res.status(400).json({ status: false, msg: "value are required." }); }
    try {
        const result = JSON.parse(encrypt.decryptWithKey(value, strict_pass));
        res.json({ status: true, msg: "success", result: result });
    } catch (error) {
        res.status(500).json({ status: false, msg: "Decryption failed.", error: error.message });
    }
});

// start ayushman api like - approve, reject, fatch-card

app.post('/ayushman-isa', async (req, res) => {
    const { search_by, search_value, action, state } = req.body;
    const role = 'ISA-BIS';
    const playlose_search = '1000000518';
    const result = await ayushman_function.ayushman_approve_reject(role, playlose_search, search_by, search_value, action, state);
    res.json(result);
});

app.post('/ayushman-sha', async (req, res) => {
    const { search_by, search_value, action, state } = req.body;
    const role = 'SHA-BIS';
    const playlose_search = '1000000522';
    const result = await ayushman_function.ayushman_approve_reject(role, playlose_search, search_by, search_value, action, state);
    res.json(result);
});

app.get('/ayushman-crad-fatch', async (req, res) => {
    const { search_by, search_value, state } = req.query;
    const result = await ayushman_function.ayushman_crad_fatch(search_by, search_value, state, "false");
    res.json(result);
});

app.get('/ayushman-crad-fatch-all', async (req, res) => {
    const { search_by, search_value, state } = req.query;
    const result = await ayushman_function.ayushman_crad_fatch(search_by, search_value, state, "true");
    res.json(result);
});

app.get('/ayushman-crad-download', async (req, res) => {
    const { state, cardId } = req.query;
    const result = await ayushman_function.ayushman_crad_download(state, cardId);
    res.json(result);
});

// start getting nomal value like state, city and scheme

app.get('/get-state', async (req, res) => {
    const result = await ayushman_function.getState();
    res.json(result);
});

app.get('/get-district', async (req, res) => {
    const { stateCd } = req.query;
    const result = await ayushman_function.getDistrict(stateCd);
    res.json(result);
});

app.get('/get-subdistrict', async (req, res) => {
    const { stateCd, districtCd, type } = req.query;
    const result = await ayushman_function.getSubDistrict(stateCd, districtCd, type);
    res.json(result);
});

app.get('/get-village', async (req, res) => {
    const { stateCd, districtCd, subdistrictCd, type } = req.query;
    const result = await ayushman_function.getVillage(stateCd, districtCd, subdistrictCd, type);
    res.json(result);
});

app.get('/get-scheme', async (req, res) => {
    const { stateCd } = req.query;
    const result = await ayushman_function.getSchemeCode(stateCd);
    res.json(result);
});

// start add member api endpoints

app.post('/add-member-send-otp-v2', async (req, res) => {
    const { state, fid, uid, usid} = req.body;
    const result = await ayushman_function.member_send_otp_v2(state, fid, uid, usid);
    res.json(result);
});

app.post('/add-member-verify-otp-v2', async (req, res) => {
    const { refresh_token, uidOTP, bisOTP } = req.body;
    const result = await ayushman_function.member_verify_otp_v2(refresh_token, uidOTP, bisOTP);
    res.json(result);
});

app.post('/add-family-member-v2', async (req, res) => {
    const { refresh_token, img, ctype, name, fname, gender, dob, relation, address, state, district, subdistrict, village, pin, type, usid } = req.body;
    const result = await ayushman_function.add_family_member_v2(refresh_token, img, ctype, name, fname, gender, dob, relation, address, state, district, subdistrict, village, pin, type, usid);
    res.json(result);
});

// start Connection, CronJob, login and Logout server api endpoints

app.post('/get-captcha', async (req, res) => {
    const result = await auth.getcaptcha();
    res.json(result);
});

app.post('/send-otp', async (req, res) => {
    const { phone, captcha, refresh_token } = req.body;
    const result = await auth.send_otp(phone, captcha, refresh_token);
    res.json(result);
});

app.post('/verify-otp', async (req, res) => {
    const { otp, captcha, refresh_token, usid } = req.body;
    const result = await auth.verify_otp(otp, captcha, refresh_token, usid);
    res.json(result);
});

app.post('/disconnect-operator', async (req, res) => {
    const { usid, userid } = req.body;
    const result = await auth.disconnect_operator(usid, userid);
    res.json(result);
});

app.get('/update-cron', async (req, res) => {
    try {
        const result = await auth.update_cron();
        const resultx = await auth.remove_temp_token();
        res.json({ result: result, resultx: resultx });
    } catch (error) {
        console.error('Error processing /remove-temp-token:', error);
        res.status(500).send('An error occurred while processing the request.');
    }
});

// start get mothode html file serve

app.get('/', (req, res) => {
    const result = { status: true, massage: "Hello World! version 5.0x" };
    res.json(result);
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});