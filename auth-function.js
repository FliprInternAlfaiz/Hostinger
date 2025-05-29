const fetch = require('node-fetch');
const moment = require('moment');
const crypto = require('crypto');
const encrypt = require('./encrypt-function');
const database = require('./database-function');

const strict_pass = "Rxp5MUcc0sunq67eDQe7MZfQzZ3n9mLWAMWTkB3B8Ik4SWh50Gw7T18alRU0t83u";

function isJson(input) {
    if (typeof input === "string") {
        try {
            JSON.parse(input);
            return true;
        } catch (e) {
            return false;
        }
    } else if (typeof input === "object") {
        return true;
    }
    return false;
}

function generateCustomHeaders(userJson, tempHeaders, token, authtoken, urole, transactionid) {
    return {
        "Host": "apisprod.nha.gov.in",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": "https://beneficiary.nha.gov.in/",
        "Origin": "https://beneficiary.nha.gov.in",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "TE": "trailers",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/131.0",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.5",
        "Content-Type": "application/json; charset=UTF-8",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "Access-Control-Allow-Origin": "https://beneficiary.nha.gov.in",
        "Authorization": `Bearer ${token}`,
        "appname": "BIS",
        "UAuthorization": `Bearer ${authtoken}`,
        "uid": userJson.userid,
        "urole": urole,
        "hid": tempHeaders.entityId,
        "pid": tempHeaders.parentEntityId,
        "cid": tempHeaders.clusterId[0],
        "uname": userJson.username,
        "ustate": tempHeaders.stateCode,
        "scode": tempHeaders.stateCode,
        "Request-Agent": "web",
        "tid": transactionid,
        "etype": tempHeaders.entityType,
        "Priority": "u=0"
    };
}

function locelHeaders(type = true) {
    let tempHeaders = {
        'Host': 'apisprod.nha.gov.in',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Referer': 'https://beneficiary.nha.gov.in/',
        'Origin': 'https://beneficiary.nha.gov.in',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
        'TE': 'trailers',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/131.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Content-Type': 'application/json; charset=UTF-8',
        'Request-Agent': 'web',
        'Priority': 'u=0'
    }

    if (!type) { tempHeaders["Content-Type"] = 'text/plain'; }

    return tempHeaders;
}

function GetHeaders(token, type = false) {
    let header = {
        'Host': 'apisprod.nha.gov.in',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Referer': 'https://beneficiary.nha.gov.in/',
        'Origin': 'https://beneficiary.nha.gov.in',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
        'TE': 'trailers',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/131.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Content-Type': 'application/json; charset=UTF-8',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Access-Control-Allow-Origin': 'https://beneficiary.nha.gov.in',
        'Authorization': `Bearer ${token}`,
        'appname': 'BIS',
        'Priority': 'u=0'
    }

    if (type) { delete header["Priority"]; }
    return header;
}

function generateUUID() {
    return crypto.randomBytes(16).toString('hex').toUpperCase();
}

function getAllBISRoles(data, state) {
    let bisRoles = [];
    data.entityapprolelist.forEach(item => {
        if (item.appRoleList && item.appRoleList.BIS && item.stateCode && item.stateCode == state) {
            bisRoles = bisRoles.concat(item.appRoleList.BIS);
        }
    });
    return bisRoles.toString();
}

function findIndexOfBISRole(data, roleToFind, stCode = '') {
    for (let index = 0; index < data.entityapprolelist.length; index++) {
        const item = data.entityapprolelist[index];
        if (stCode) {
            if (item.appRoleList && item.appRoleList.BIS && item.appRoleList.BIS.includes(roleToFind) && item.stateCode == stCode) { return index; }
        } else {
            if (item.appRoleList && item.appRoleList.BIS && item.appRoleList.BIS.includes(roleToFind)) { return index; }
        }
    }
    return -1;
}

function getAllBISState(data) {
    let stCode = [];
    data.entityapprolelist.forEach(item => {
        if (item.appRoleList && item.appRoleList.BIS && item.stateCode) {
            stCode = stCode.concat(item.stateCode);
        }
    });
    return (!stCode.toString()) ? "-1" : stCode;
}

async function getcaptcha(refresh_token = '', tokenType = false) {
    const create_date = moment().format('YYYY-MM-DD HH:mm:ss');
    let token, temp_headers, sqlQuery;

    try {
        if (!refresh_token) {
            const data = encrypt.token();
            const encryptData = encrypt.encrypt(strict_pass, data);

            const dataResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/configbis/bis/token/data', {
                method: 'POST',
                headers: locelHeaders(false),
                body: encryptData
            });

            token = await dataResponse.text(); // Assuming the response is a plain text
            if (!isNaN(token.replace('/', ''))) {
                throw new Error('Invalid token received');
            }
        } else {
            const { count, result } = await database.sqlGet(`SELECT * FROM temp_token WHERE refresh_token = '${refresh_token}';`);
            if (count === 0) {
                throw new Error('refresh_token is incorrect or has expired.');
            }
            token = result.token;
        }

        temp_headers = tokenType === false ? GetHeaders(token, true) : JSON.parse(result.headers);

        const captchaResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/bis/auth/generateCaptcha', {
            method: 'POST',
            headers: temp_headers,
            body: JSON.stringify({})
        });

        const captchaData = await captchaResponse.json();
        if (captchaData.transactionid && captchaData.message === "success") {
            const refresh_tokenx = generateUUID();
            if (!refresh_token) {
                sqlQuery = `INSERT INTO temp_token (refresh_token, transactionid, token, create_at) VALUES ('${refresh_tokenx}', '${captchaData.transactionid}', '${token}', '${create_date}')`;
            } else {
                sqlQuery = tokenType === false
                    ? `UPDATE temp_token SET transactionid = '${captchaData.transactionid}', create_at = '${create_date}' WHERE refresh_token = '${refresh_token}'`
                    : `UPDATE temp_token SET token = '${captchaData.transactionid}', create_at = '${create_date}' WHERE refresh_token = '${refresh_token}'`;
            }

            const insertResult = await database.sqlUpdate(sqlQuery);
            if (insertResult) {
                return { status: true, refresh_token: !refresh_token ? refresh_tokenx : refresh_token, captcha: captchaData.captcha };
            } else {
                throw new Error('Database record insertion failed.');
            }
        } else {
            throw new Error('Captcha not found or response invalid');
        }
    } catch (error) {
        return { status: false, error: error.message };
    }
}

async function send_otp(phone, captcha, refresh_token) {
    const create_date = moment().format('YYYY-MM-DD HH:mm:ss');
    try {
        if (!/^\d{10}$/.test(phone)) {
            throw new Error('* Phone number must consist of 10 digits.');
        }
        if (captcha.length < 6) {
            throw new Error('* Captcha must consist of at least 6 characters.');
        }

        const { count, result } = await database.sqlGet(`SELECT * FROM temp_token WHERE refresh_token = '${refresh_token}';`);
        if (count === 0) {
            throw new Error('* refresh_token is incorrect or has expired.');
        }

        const encryptedCaptcha = encrypt.encrypt(result.transactionid, captcha);
        const token = result.token;

        const checkResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/bis/auth/V3/check', {
            method: 'POST',
            headers: GetHeaders(token),
            body: JSON.stringify({
                role: "user",
                loginid: phone,
                captcha: encryptedCaptcha,
                captchaId: result.transactionid
            })
        });

        const checkData = await checkResponse.json();
        if (checkData.error) {
            throw new Error(checkData.error.message);
        }

        const userId = checkData.userid.replace('BEN', '');

        const initResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/bis/auth/V3/init', {
            method: 'POST',
            headers: GetHeaders(token, true),
            body: JSON.stringify({
                role: "user",
                userid: userId,
                authmode: 'Mobile_OTP'
            })
        });

        const initData = await initResponse.json();
        if (initData.message && initData.message.includes('sent to your registered mobile number')) {
            const refresh_tokenx = generateUUID();
            const insertResult = await database.sqlUpdate(`INSERT INTO temp_token (refresh_token, transactionid, token, create_at, user_id) VALUES ('${refresh_tokenx}', '${initData.transactionid}', '${token}', '${create_date}', '${userId}')`);
            if (insertResult) {
                const decryptedCaptcha = encrypt.decrypt(initData.transactionid, initData.captcha);
                return { status: true, message: initData.message, refresh_token: refresh_tokenx, captcha: decryptedCaptcha };
            } else {
                throw new Error('* Database record insertion failed.');
            }
        } else {
            throw new Error(initData.message || `Invalid mobile number or ${JSON.stringify(initData)}`);
        }
    } catch (error) {
        if (error.message.includes('*')) {
            return { status: false, error: error.message };
        }

        const new_captcha = await getcaptcha(refresh_token);
        if (new_captcha.status) {
            return { status: false, error: error.message, refresh_token: new_captcha.refresh_token, captcha: new_captcha.captcha };
        } else {
            return { status: false, error: error.message, captchaError: new_captcha.error };
        }
    }
}

async function verify_otp(otp, captcha, refresh_token, usid = '') {
    const create_date = moment().format('YYYY-MM-DD HH:mm:ss');

    try {
        if (!/^\d{6}$/.test(otp)) {
            throw new Error('* OTP must consist of 6 digits.');
        }
        if (captcha.length < 6) {
            throw new Error('* Captcha must consist of at least 6 characters.');
        }

        const { count, result } = await database.sqlGet(`SELECT * FROM temp_token WHERE refresh_token = '${refresh_token}';`);
        if (count === 0) {
            throw new Error('* refresh_token is incorrect or has expired.');
        }

        const encryptedCaptcha = encrypt.encrypt(result.transactionid, captcha);
        const encryptedOtp = encrypt.encrypt(result.transactionid, otp);
        const token = result.token;

        const validateResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/bis/auth/V3/validate', {
            method: 'POST',
            headers: GetHeaders(token),
            body: JSON.stringify({
                role: "user",
                transactionid: result.transactionid,
                captcha: encryptedCaptcha,
                token: encryptedOtp,
                language: 'English',
                authtransaction: null
            })
        });

        const validateData = await validateResponse.json();
        if (validateData.error) {
            throw new Error(validateData.error.message);
        }

        const transactionid = validateData.transactionid;
        const authtoken = validateData.authtoken;
        const decryptPayload = encrypt.encryptWithKey(JSON.stringify({ role: "user", transactionId: transactionid, authToken: authtoken }), strict_pass);

        const decryptRequest = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/bis/auth/V3/decrypt', {
            method: 'POST',
            headers: GetHeaders(token, true),
            body: decryptPayload
        });

        let decryptData = await decryptRequest.text();

        if (isJson(decryptData)) {
            const texterror = JSON.parse(decryptData);
            throw new Error(`* ${texterror.error.message}`);
        }

        const decryptJson = encrypt.decryptWithKey(decryptData, strict_pass);
        decryptData = JSON.parse(decryptJson);

        if (!decryptData.userid) {
            throw new Error('* Decrypt payload failed: Userid not found');
        }

        let sqlQuery = `DELETE FROM pmjay_operators WHERE userid = '${decryptData.userid}';`;
        const json = JSON.stringify(decryptData);
        const all_state_code = getAllBISState(decryptData);

        if (all_state_code == "-1") {
            throw new Error('Correct role is not mapped in UMP application.');
        }

        for (const valuexu of all_state_code) {
            sqlQuery += (usid)
                ? `INSERT INTO pmjay_operators (remark, userid, state, services, authorization, authtoken, transactionid, json, authorization_time, authtoken_time, conected_by) VALUES ('connected', '${decryptData.userid}','${valuexu}','${getAllBISRoles(decryptData, valuexu)}','${token}','${authtoken}','${transactionid}','${json}','${create_date}','${create_date}', '${usid}');`
                : `INSERT INTO pmjay_operators (remark, userid, state, services, authorization, authtoken, transactionid, json, authorization_time, authtoken_time) VALUES ('connected', '${decryptData.userid}','${valuexu}','${getAllBISRoles(decryptData, valuexu)}','${token}','${authtoken}','${transactionid}','${json}','${create_date}','${create_date}');`;
        }

        const insertResult = await database.sqlUpdateAll(sqlQuery);
        if (!insertResult) {
            throw new Error('* Database record insertion failed.');
        }

        const urole = getAllBISRoles(decryptData, all_state_code[0]).split(',')[0];
        const indexof = findIndexOfBISRole(decryptData, urole, all_state_code[0]);
        if (!indexof) {
            throw new Error('This service is not currently available, please try later');
        }

        const tempHeaders = decryptData.entityapprolelist[indexof];

        const headers = generateCustomHeaders(decryptData, tempHeaders, token, authtoken, urole, transactionid);

        const storeLoginResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/bis/auth/audit/storeLoginLogoutDetails', {
            method: 'POST',
            headers,
            body: JSON.stringify({
                transactionid: transactionid,
                userid: decryptData.userid.replace('USER', ''),
                location: null,
                action: "Login",
                browserName: "Firefox,131.0",
                applicationName: "BIS",
                operatingSystem: "",
                ipAddres: ""
            })
        });

        const storeLoginData = await storeLoginResponse.json();
        if (storeLoginData.error) {
            return { status: true, message: `Your Account Successfully connected PMJAY - Beneficiary Portal But 'StoreLogin Error: ${storeLoginData.error.message}'` };
        } else if (storeLoginData.message === "success") {
            return { status: true, message: "Your Account Successfully connected PMJAY - Beneficiary Portal" };
        } else {
            return { status: true, message: `Your Account Successfully connected PMJAY - Beneficiary Portal But 'StoreLogin Message: ${storeLoginData.message}'` };
        }
    } catch (error) {
        if (error.message.includes('*')) {
            return { status: false, error: error.message };
        }
        const new_captcha = await getcaptcha(refresh_token);
        if (new_captcha.status) {
            return { status: false, error: error.message, refresh_token: new_captcha.refresh_token, captcha: new_captcha.captcha };
        }
        return { status: false, error: error.message, captchaError: new_captcha.error };
    }
}

async function disconnect_operator(usid, userid) {
    const create_date = moment().format('YYYY-MM-DD HH:mm:ss');
    try {
        if (!usid) {
            throw new Error('Please enter usid value');
        }

        if (!userid) {
            throw new Error('Please enter userid value');
        }

        const { count, result } = await database.sqlGet(`SELECT * FROM pmjay_operators WHERE active = 1 AND conected_by = '${usid}' AND userid = '${userid}';`);
        if (count === 0) {
            throw new Error('The operator you want to disconnect is already disconnected.');
        }

        const urole = result.services.includes(',') ? result.services.split(',')[0] : result.services;
        const transactionid = result.transactionid;
        const token = result.authorization;
        const authtoken = result.authtoken;
        const userJson = JSON.parse(result.json);

        const indexof = findIndexOfBISRole(userJson, urole);
        if (indexof === -1) {
            throw new Error('This service is not currently available, please try later');
        }

        const tempHeaders = userJson.entityapprolelist[indexof];
        const headers = generateCustomHeaders(userJson, tempHeaders, token, authtoken, urole, transactionid);

        const storeLoginResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/bis/auth/audit/storeLoginLogoutDetails', {
            method: 'POST',
            headers,
            body: JSON.stringify({
                transactionid: transactionid,
                userid: userJson.userid.replace('USER', ''),
                location: null,
                action: "Logout",
                browserName: "Firefox,131.0",
                applicationName: "BIS",
                operatingSystem: "",
                ipAddres: ""
            })
        });

        const storeLoginData = await storeLoginResponse.json();
        if (storeLoginData.error) {
            throw new Error(storeLoginData.error.message);
        } else if (storeLoginData.message === "success") {
            const sqlQuery = await database.sqlUpdate(`UPDATE pmjay_operators SET active = 0, authtoken_time ='${create_date}', remark='Disconnected By User' WHERE userid = '${userid}'`);
            if (sqlQuery) {
                return { status: true, message: "Your Account Successfully Disconnect PMJAY - Beneficiary Portal" };
            } else {
                return { status: true, message: "Your Account Successfully Disconnect PMJAY - Beneficiary Portal, But Database Update Error" };
            }
        } else {
            throw new Error(storeLoginData.message);
        }
    } catch (error) {
        return { status: false, error: error.message };
    }
}


async function remove_temp_token(limit = 0) {
    try {
        const { count, result } = await database.sqlGetAllwithKey(`SELECT id, create_at FROM temp_token ORDER BY id LIMIT ${limit}, 10`);
        if (count === 0) { return 'No more records to process.'; }
        const idsToDelete = [];
        const currentTime = moment().unix();
        for (const value of result) {
            const createdAt = moment(value.create_at, 'YYYY-MM-DD HH:mm:ss').unix();
            if ((currentTime - createdAt) > (5 * 60)) {
                idsToDelete.push(value.id);
            }
        }
        if (idsToDelete.length > 0) {
            const idsString = idsToDelete.join(', ');
            const deleteResult = await database.sqlUpdate(`DELETE FROM temp_token WHERE id IN (${idsString})`);
            (deleteResult) ? console.log(`Deleted records with IDs: ${idsToDelete.join(', ')}`) : console.log('Error deleting records');
        }
        return await remove_temp_token(limit + result.length);
    } catch (error) {
        console.error('Error in remove_temp_token:', error);
    }
}

async function update_cron(limit = 0) {
    try {
        const { count, result } = await database.sqlGetAllwithKey(`SELECT * FROM pmjay_operators WHERE active = 1 GROUP BY userid LIMIT ${limit}, 10;`);
        if (count === 0) { return 'No more records to process.'; }

        let create_date, currentTime, authtokentime;
        let urole, sqlQuery, transactionid, token, authtoken, userJson, indexof, tempHeaders, headers, userId;
        let storeLoginResponse, refreshTokenResponse;

        for (const value of result) {
            create_date = moment().format('YYYY-MM-DD HH:mm:ss');
            currentTime = moment().unix();
            authtokentime = moment(value.authtoken_time, 'YYYY-MM-DD HH:mm:ss').unix();

            if ((currentTime - authtokentime) > (9 * 60)) {
                urole = value.services.includes(',') ? value.services.split(',')[0] : value.services;
                transactionid = value.transactionid;
                token = value.authorization;
                authtoken = value.authtoken;
                userJson = JSON.parse(value.json);
                indexof = findIndexOfBISRole(userJson, urole, value.state);

                if (!indexof) {
                    sqlQuery = `UPDATE pmjay_operators SET active = 0, authtoken_time ='${create_date}', remark='disconnected - Index not found' WHERE userid = '${value.userid}'`;
                    await database.sqlUpdate(sqlQuery);
                } else {
                    tempHeaders = userJson.entityapprolelist[indexof];
                    headers = generateCustomHeaders(userJson, tempHeaders, token, authtoken, urole, transactionid);
                    userId = userJson.userid.replace('USER', '');

                    refreshTokenResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/bis/auth/token/refreshToken', {
                        method: 'POST',
                        headers,
                        body: JSON.stringify({
                            userid: userId,
                            authtoken: authtoken,
                            role: "user"
                        })
                    });

                    const refreshTokenData = await refreshTokenResponse.json();

                    if (refreshTokenData.error) {
                        sqlQuery = `UPDATE pmjay_operators SET active = 0, authtoken_time ='${create_date}', remark='disconnected - ${refreshTokenData.error.message}' WHERE userid = '${value.userid}'`;
                    } else {
                        sqlQuery = `UPDATE pmjay_operators SET authtoken ='${refreshTokenData.token}', authtoken_time ='${create_date}', active = 1, remark='connected' WHERE userid = '${value.userid}'`;
                    }

                    if (await database.sqlUpdate(sqlQuery)) {
                        console.log(`Updated credentials records with IDs: ${value.id}`);
                    } else {
                        console.log(`Error updating credentials records with IDs: '${value.id}'`);
                    }

                    /*
                    // Store Login Request
                    storeLoginResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/bis/auth/audit/storeLoginLogoutDetails', {
                        method: 'POST',
                        headers,
                        body: JSON.stringify({
                            transactionid: transactionid,
                            userid: userId,
                            location: null,
                            action: "Login",
                            browserName: "Firefox,131.0",
                            applicationName: "BIS",
                            operatingSystem: "",
                            ipAddres: ""
                        })
                    });

                    const storeLoginData = await storeLoginResponse.json();

                    if (storeLoginData.error) {
                        await database.sqlUpdate(`UPDATE pmjay_operators SET active = 0, authtoken_time ='${create_date}', remark='disconnected - ${storeLoginData.error.message}' WHERE userid = '${value.userid}'`);
                    } else if (storeLoginData.message === "success") {
                        refreshTokenResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/bis/auth/token/refreshToken', {
                            method: 'POST',
                            headers,
                            body: JSON.stringify({
                                userid: userId,
                                authtoken: authtoken,
                                role: "user"
                            })
                        });

                        const refreshTokenData = await refreshTokenResponse.json();

                        if (refreshTokenData.error) {
                            sqlQuery = `UPDATE pmjay_operators SET active = 0, authtoken_time ='${create_date}', remark='disconnected - ${refreshTokenData.error.message}' WHERE userid = '${value.userid}'`;
                        } else {
                            sqlQuery = `UPDATE pmjay_operators SET authtoken ='${refreshTokenData.token}', authtoken_time ='${create_date}', active = 1, remark='connected' WHERE userid = '${value.userid}'`;
                        }

                        if (await database.sqlUpdate(sqlQuery)) {
                            console.log(`Updated credentials records with IDs: ${value.id}`);
                        } else {
                            console.log(`Error updating credentials records with IDs: '${value.id}'`);
                        }
                    } else {
                        await database.sqlUpdate(`UPDATE pmjay_operators SET active = 0, authtoken_time ='${create_date}', remark='disconnected - ${storeLoginData.message}' WHERE userid = '${value.userid}'`);
                    }
                    
                    */
                }
            }
        }
        return await update_cron(limit + result.length);
    } catch (error) {
        console.error('Error in update_cron:', error);
    }
}

module.exports = {
    getcaptcha,
    send_otp,
    verify_otp,
    disconnect_operator,

    update_cron,
    remove_temp_token,
};