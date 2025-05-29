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

function findIndexOfMemberID(data, member) {
    for (let index = 0; index < data.length; index++) {
        const item = data[index];
        if (item.relation && item.relation == member) { return index; }
    }
    return -1;
}

function formatText(input) {
    return input.toLowerCase().replace(/\b\w/g, char => char.toUpperCase());
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateUUID() {
    return crypto.randomBytes(16).toString('hex').toUpperCase();
}

function findIndexOfBISRole(data, roleToFind, stCode = '') {
    for (let index = 0; index < data.entityapprolelist.length; index++) {
        const item = data.entityapprolelist[index];
        if (stCode) {
            if (item.appRoleList?.BIS?.includes(roleToFind) && item.stateCode === stCode) {
                return index;
            }
        } else {
            if (item.appRoleList?.BIS?.includes(roleToFind)) {
                return index;
            }
        }
    }
    return -1;
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

async function transformFamilyData(data, tid) {
    const transformedMembers = data[0].familyMember.map(member => ({
        uId: member.uId,
        cardNo: member.cardNo,
        aadharId: encrypt.decrypt(tid, member.aadharId),
        photo: member.photo,
        name: member.name,
        fatherOrGuardianName: member.fatherOrGuardianName,
        dob: member.dob,
        age: member.age,
        gender: member.gender,
        relation: member.relation,
        mobileNumber: member.mobileNumber,
        address: member.addr1,
        stateName: member.stateName,
        distName: member.distName,

        stateCode: member.stateCode,
        districtCode: member.districtCode,
        ruralUrbanFlag: member.ruralUrbanFlag,
        blockOrTown: member.blockOrTown,
        wardOrVillage: member.wardOrVillage,
        subdivision: member.subdivision,

        sourceType: member.sourceType,
        familyId: member.familyId,
        memberId: member.memberId,
        bisFamilyId: member.bisFamilyId,
        bisMemberId: member.bisMemberId,
        enrlStatus: member.enrlStatus,
        cardStatus: member.cardStatus,
        aadharStatus: member.aadharStatus,
        enrollDate: moment(member.enrollDate).format('DD MMM YYYY [at] hh:mm:ss a'),
        approveDate: moment(member.approveDate).format('DD MMM YYYY [at] hh:mm:ss a'),
        abhaId: member.abhaId,
        bisSource: member.bisSource,
        statusDesc: member.statusDesc,
        pendingRole: member.pendingRole,
        pendingUser: member.pendingUser,
    }));
    return {
        familyMember: transformedMembers
    };
}

function getStateName(stateCode, list) {
    const stateList = list.result.StateList;
    for (const [name, code] of Object.entries(stateList)) {
        if (code === stateCode) {
            return formatText(name);
        }
    }
    return null;
}

function getvalueName(value, list) {
    const districtList = list.result;
    for (const district of districtList) {
        if (district.lgdcode === value) {
            return formatText(district.lgdname);
        }
    }
    return null;
}

async function getState() {
    try {
        const response = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/configbis/bis/get/activeStates/details');
        const data = await response.json();
        return { status: true, result: data };
    } catch (error) {
        return { status: false, error: error.message };
    }
}

async function getDistrict(stateCd) {
    try {
        const response = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/configbis/bis/v1/getlistOfLGD', {
            method: 'POST',
            headers: locelHeaders(),
            body: JSON.stringify({
                "lgdtype": "ST",
                "state": stateCd,
                "parentcd": stateCd
            })
        });
        const data = await response.json();
        return { status: true, result: data };
    } catch (error) {
        return { status: false, error: error.message };
    }
}

async function getSubDistrict(stateCd, districtCd, type = 'R') {
    try {
        const typeValue = (type == "R") ? "DT-R" : "DT-U";
        const response = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/configbis/bis/v1/getlistOfLGD', {
            method: 'POST',
            headers: locelHeaders(),
            body: JSON.stringify({
                "lgdtype": typeValue,
                "parentcd": districtCd,
                "state": stateCd,
                "grandparentcd": stateCd
            })
        });
        const data = await response.json();
        return { status: true, result: data };
    } catch (error) {
        return { status: false, error: error.message };
    }
}

async function getVillage(stateCd, districtCd, subdistrictCd, type = 'R') {
    try {
        const typeValue = (type == "R") ? "SD-R" : "SD-U";
        const response = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/configbis/bis/v1/getlistOfLGD', {
            method: 'POST',
            headers: locelHeaders(),
            body: JSON.stringify({
                "lgdtype": typeValue,
                "parentcd": subdistrictCd,
                "state": stateCd,
                "grandparentcd": districtCd
            })
        });
        const data = await response.json();
        return { status: true, result: data };
    } catch (error) {
        return { status: false, error: error.message };
    }
}

async function getSchemeCode(stateCd) {
    let urole = "";
    try {
        if (!stateCd) {
            throw new Error('Please enter stateCd');
        }

        const { count, result } = await database.sqlGet(`SELECT * FROM pmjay_operators WHERE active = 1 AND (services LIKE '%PMAM%' OR services LIKE '%Operator-BIS%') ORDER BY rand();`);
        if (count === 0) {
            throw new Error('This service is not currently available because the service ID is not currently connected.');
        }

        urole = result.services.includes('PMAM') ? 'PMAM' : 'Operator-BIS';

        const transactionid = result.transactionid;
        const token = result.authorization;
        const authtoken = result.authtoken;
        const userJson = JSON.parse(result.json);

        const indexof = findIndexOfBISRole(userJson, urole);
        if (!indexof) {
            throw new Error('This service is not currently available, please try later');
        }

        const tempHeaders = userJson.entityapprolelist[indexof];
        const headers = generateCustomHeaders(userJson, tempHeaders, token, authtoken, urole, transactionid);

        const response = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/configbis/bis/get/schemes/list2', {
            method: 'POST',
            headers,
            body: JSON.stringify({ statecode: stateCd })
        });

        const data = await response.json();
        return { status: true, result: data };

    } catch (error) {
        return { status: false, error: error.message };
    }
}

async function ayushman_approve_reject(role, playlose_search, search_by, search_value, action, state, usid = '') {
    const urole = role;
    const status_value = playlose_search;
    let actionid = "";

    if (urole === "ISA-BIS") {
        actionid = (action === "approve") ? "1000000521" : "1000000522";
    } else if (urole === "SHA-BIS") {
        actionid = (action === "approve") ? "1000000523" : "1000000524";
    }

    try {
        if (!search_by) throw new Error('Please select search by');
        if (!search_value) throw new Error('Please enter search value');

        if (search_by === "uid") {
            if (search_value.length !== 12) {
                throw new Error('Your Aadhaar number must consist of exactly 12 digits');
            }
            if (!/^[2-9]{1}[0-9]{3}[0-9]{4}[0-9]{4}$/.test(search_value)) {
                throw new Error('Your Aadhaar number is not valid. Please enter a valid Aadhaar number');
            }
        }

        if (!/^(?:[0-9]|1[0-9]|2[0-7])$/.test(state)) {
            throw new Error('The state you have selected is not correct. Please select your correct state.');
        }

        const query = usid
            ? `SELECT * FROM pmjay_operators WHERE conected_by = '${usid}' AND state = '${state}' AND active = 1 AND services LIKE '%${urole}%' ORDER BY rand();`
            : `SELECT * FROM pmjay_operators WHERE state = '${state}' AND active = 1 AND services LIKE '%${urole}%' ORDER BY rand();`;

        const { count, result } = await database.sqlGet(query);
        if (count === 0) {
            throw new Error('This service is not currently available because the service ID is not currently connected.');
        }

        const transactionid = result.transactionid;
        const token = result.authorization;
        const authtoken = result.authtoken;
        const userJson = JSON.parse(result.json);

        const indexof = findIndexOfBISRole(userJson, urole, state);
        if (!indexof) {
            throw new Error('This service is not currently available, please try later');
        }

        const tempHeaders = userJson.entityapprolelist[indexof];
        const headers = generateCustomHeaders(userJson, tempHeaders, token, authtoken, urole, transactionid);

        const workflowListResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/serviceworkflow/workflow/list', {
            method: 'POST',
            headers,
            body: JSON.stringify({
                worklistRequest: {
                    pagenumber: "0",
                    pagesize: "10",
                    searchcriteria: [
                        { key: "status", value: status_value, operation: "Equal" },
                        { key: search_by, value: search_value, operation: "Equal" }
                    ],
                }
            })
        });

        const workflowListData = await workflowListResponse.json();
        if (workflowListData.timestamp) {
            throw new Error(workflowListData.error.message);
        } else if (workflowListData.totalcount) {
            const captchaResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/bis/auth/generateCaptcha', {
                method: 'POST',
                headers,
                body: JSON.stringify({})
            });

            const captchaData = await captchaResponse.json();
            if (captchaData.transactionid && captchaData.message === "success") {
                const captchaTextResponse = await fetch('https://api.apitruecaptcha.org/one/gettext', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        "userid": "govindaxyz65@gmail.com",
                        "apikey": "1yVtaXBE4uKa3F3Y5c4B",
                        "data": captchaData.captcha
                    })
                });

                const captchaTextResult = await captchaTextResponse.json();
                const encryptCaptcha = encrypt.encrypt(transactionid, captchaTextResult.result);

                const updateRequestResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/serviceworkflow/workflow/v3/update', {
                    method: 'POST',
                    headers,
                    body: encrypt.encryptWithKey(JSON.stringify({
                        "benId": workflowListData.Beneficiarys[0].benId,
                        "actionId": actionid,
                        "assignedTo": "",
                        "remarks": "ok",
                        "otherDetails": {
                            "checkListJson": [
                                { "fieldName": "Did the photo of e-KYC match with the beneficiary source photo?", "fieldValue": "Yes" },
                                { "fieldName": "Did the e-KYC details match with the beneficiary source data?", "fieldValue": "Yes" }
                            ],
                            "additionalDetails": [{ "fieldName": "processingtime", "fieldValue": null }]
                        },
                        "captcha": encryptCaptcha,
                        "transactionId": captchaData.transactionid
                    }), strict_pass),
                });

                const updateRequestData = await updateRequestResponse.text();
                if (isJson(updateRequestData)) {
                    throw new Error(updateRequestData);
                }

                return { status: true, message: JSON.parse(encrypt.decryptWithKey(updateRequestData, strict_pass)).status };
            } else {
                throw new Error('Captcha not found or response invalid');
            }
        } else {
            throw new Error(workflowListData.message);
        }
    } catch (error) {
        return { status: false, error: error.message };
    }
}

async function ayushman_crad_fatch(search_by, search_value, state, type, schemeCd = 'PMJAY') {
    let urole = "";
    const approveFlag = (type == "true") ? null : "Y";

    try {
        if (!search_by) {
            throw new Error('Please select search by');
        }
        if (!search_value) {
            throw new Error('Please enter search value');
        }
        if (search_by === "uid" && search_value.length !== 12) {
            throw new Error('Your Aadhaar number must consist of exactly 12 digits');
        }
        if (search_by === "uid" && !/^[2-9]{1}[0-9]{3}[0-9]{4}[0-9]{4}$/.test(search_value)) {
            throw new Error('Your Aadhaar number is not valid. Please enter a valid Aadhaar number');
        }
        if (!/^(?:[0-9]|1[0-9]|2[0-7])$/.test(state)) {
            throw new Error('The state you have selected is not correct. Please select your correct state.');
        }

        const { count, result } = await database.sqlGet(`SELECT * FROM pmjay_operators WHERE active = 1 AND (services LIKE '%PMAM%' OR services LIKE '%Operator-BIS%') ORDER BY rand();`);
        if (count === 0) {
            throw new Error('This service is not currently available because the service ID is not currently connected.');
        }

        urole = result.services.includes('PMAM') ? 'PMAM' : 'Operator-BIS';

        const transactionid = result.transactionid;
        const token = result.authorization;
        const authtoken = result.authtoken;
        const userJson = JSON.parse(result.json);

        const indexof = findIndexOfBISRole(userJson, urole);
        if (!indexof) {
            throw new Error('This service is not currently available, please try later');
        }

        const tempHeaders = userJson.entityapprolelist[indexof];
        const headers = generateCustomHeaders(userJson, tempHeaders, token, authtoken, urole, transactionid);

        const body = encrypt.encryptWithKey(JSON.stringify({
            idType: search_by,
            idValue: search_value,
            stateCd: state,
            advanceSearch: { userId: null, approveFlag },
            pageNumber: "0",
            pageSize: "10",
            searchType: "F",
            schemeCd: schemeCd
        }), strict_pass);

        const response = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/searchbis/ben/v3/card/search', {
            method: 'POST',
            headers,
            body
        });

        const responseData = await response.text();
        if (isJson(responseData)) {
            throw new Error(responseData);
        }

        const SearchData = JSON.parse(encrypt.decryptWithKey(responseData, strict_pass));
        const valuexdf = await transformFamilyData(SearchData, transactionid);

        return { status: true, result: valuexdf };

    } catch (error) {
        return { status: false, error: error.message };
    }
}

async function ayushman_crad_download(state, cardId) {
    let urole = "";
    try {

        if (!cardId) {
            throw new Error('Please enter CardID value');
        }
        if (!state) {
            throw new Error('Please enter state');
        }

        const { count, result } = await database.sqlGet(`SELECT * FROM pmjay_operators WHERE active = 1 AND (services LIKE '%PMAM%' OR services LIKE '%Operator-BIS%') ORDER BY rand();`);
        if (count === 0) {
            throw new Error('This service is not currently available because the service ID is not currently connected.');
        }

        urole = result.services.includes('PMAM') ? 'PMAM' : 'Operator-BIS';

        const transactionid = result.transactionid;
        const token = result.authorization;
        const authtoken = result.authtoken;
        const userJson = JSON.parse(result.json);

        const indexof = findIndexOfBISRole(userJson, urole);
        if (!indexof) {
            throw new Error('This service is not currently available, please try later');
        }

        const tempHeaders = userJson.entityapprolelist[indexof];
        const headers = generateCustomHeaders(userJson, tempHeaders, token, authtoken, urole, transactionid);

        const body = encrypt.encryptWithKey(JSON.stringify({
            beneficiaryIds: [cardId],
            stateCode: state,
            appName: "BIS20",
            schemeCd: "PMJAY"
        }), strict_pass);

        const response = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/downloadcard/v2/cards/download', {
            method: 'POST',
            headers: headers,
            body: body
        });

        const data = await response.text()

        if (isJson(data)) {
            throw new Error(JSON.stringify(data));
        }

        const decryptedData = encrypt.decryptWithKey(data, strict_pass);
        return { status: true, result: JSON.parse(decryptedData) };

    } catch (error) {
        return { status: false, error: error.message };
    }
}

async function member_send_otp_v2(state, fid, uid, usid) {

    let urole, familyJson, newuid;
    const create_date = moment().format('YYYY-MM-DD HH:mm:ss');

    try {

        if (!state) { throw new Error('Please select state'); }
        if (!fid) { throw new Error('Please enter family ID'); }
        if (!uid || uid.length !== 12) { throw new Error('Your Aadhaar number must consist of digits only and exactly 12 characters'); }
        if (!/^[2-9]{1}[0-9]{3}[0-9]{4}[0-9]{4}$/.test(uid)) { throw new Error('Your Aadhaar number is not valid. Please enter a valid Aadhaar number'); }

        const { count, result } = await database.sqlGet(`SELECT * FROM pmjay_operators WHERE conected_by = ${usid} AND active = 1 AND (services LIKE '%PMAM%' OR services LIKE '%Operator-BIS%') ORDER BY RAND();`);
        if (count === 0) { throw new Error('This service is not currently available because the service ID is not currently connected.'); }

        const operatorAadharResponse = await database.sqlGet(`SELECT aadhar FROM accounts WHERE id = ${usid};`);
        const operatorAadhar = operatorAadharResponse.result.aadhar;

        newuid = operatorAadhar || uid;
        urole = result.services.includes('PMAM') ? 'PMAM' : 'Operator-BIS';

        const transactionid = result.transactionid;
        const token = result.authorization;
        const authtoken = result.authtoken;
        const userJson = JSON.parse(result.json);

        const indexof = findIndexOfBISRole(userJson, urole);
        if (indexof === -1) { throw new Error('This service is not currently available, please try later'); }

        const tempHeaders = userJson.entityapprolelist[indexof];
        const headers = generateCustomHeaders(userJson, tempHeaders, token, authtoken, urole, transactionid);
      
      	const CheckRequest = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/sourcebissearch/ben/source/check/aadhaar', {
            method: 'POST',
            headers: headers,
            body: encrypt.encrypt(transactionid, uid)
        });
        const CheckResponse = await CheckRequest.json();
        if (CheckResponse.status && CheckResponse.status === "YES") { throw new Error(`This aadhaar number is linked to another family ID`); }
      
      	const familyId_info = await ayushman_crad_fatch("fid", fid, state, "false");

        let familyJson;

        if (familyId_info.status) {
            const familyIndex = findIndexOfMemberID(familyId_info.result.familyMember, "SELF");
            familyJson = (familyIndex === -1) 
                ? createNewFamilyJson(fid)
                : familyId_info.result.familyMember[familyIndex];
        } else {
            familyJson = createNewFamilyJson(fid);
        }

        function createNewFamilyJson(fid) {
          	const masterCard = `${fid}${getRandomInt(11, 99)}`;
            return {
                uId: masterCard,
                memberId: masterCard,
                bisMemberId: masterCard,
                bisFamilyId: null
            };
        }

        const AadharOTPResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/v2/auth/aadhaar/init', {
            method: 'POST',
            headers,
            body: JSON.stringify({
                aadhaarNumber: encrypt.encrypt(transactionid, `${state}~PMJAY~${fid}~${familyJson.memberId}~${newuid}~F`),
                authType: "EKYC",
                authMode: "AADHAAR_OTP"
            })
        });

        const responseData = await AadharOTPResponse.json();

        if (responseData.error?.message) {
            throw new Error(responseData.error.message);
        }

        const refresh_tokenx = generateUUID();
        const insertResult = await database.sqlUpdate(`INSERT INTO temp_token (temp_aadhar, refresh_token, transactionid, token, authtoken, user_id, headers, txn_date, temp_text, create_at) VALUES ('${newuid}', '${refresh_tokenx}', '${transactionid}', '${responseData.transactionid}', '${fid}', '${uid}', '${JSON.stringify(headers)}', '${state}', '${JSON.stringify(familyJson)}', '${create_date}')`);

        return (insertResult)
            ? { status: true, message: `OTP has been sent to your number ${responseData.mobileNo}`, refresh_token: refresh_tokenx }
            : { status: false, error: 'OTP has been sent, but database record insertion failed.' };

    } catch (error) {
        return { status: false, error: error.message };
    }
}

async function member_verify_otp_v2(refresh_token, uidOTP, bisOTP) {

    const create_date = moment().format('YYYY-MM-DD HH:mm:ss');

    try {

        if (!/^\d{6}$/.test(uidOTP)) { throw new Error('* uidOTP must consist of 6 digits.'); }
        if (!/^\d{6}$/.test(bisOTP)) { throw new Error('* bisOTP must consist of 6 digits.'); }

        const { count, result } = await database.sqlGet(`SELECT * FROM temp_token WHERE refresh_token = '${refresh_token}';`);
        if (count === 0) { throw new Error('refresh_token is incorrect or has expired.'); }

        const headers = JSON.parse(result.headers);
        const transactionid = result.transactionid;
        const new_transactionid = result.token;
        const fid = result.authtoken;
        const uid = result.user_id;
        const state = result.txn_date;
        const temp_aadhar = result.temp_aadhar;

        const familyJson = JSON.parse(result.temp_text);

        const validateResponse = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/authService/v2/auth/aadhaar/validate', {
            method: 'POST',
            headers,
            body: JSON.stringify({
                txn: new_transactionid,
                aadhaarNumber: encrypt.encrypt(transactionid, `${state}~PMJAY~${fid}~${familyJson.memberId}~${temp_aadhar}~R`),
                token: uidOTP,
                authType: "EKYC",
                authMode: "AADHAAR_OTP",
                captcha: encrypt.encrypt(transactionid, bisOTP)
            })
        });

        const responseData = await validateResponse.json();

        if (responseData.error && !responseData.txn) {
            throw new Error(responseData.error.message);
        }

        const refresh_tokenx = generateUUID();
        const insertResult = await database.sqlUpdate(`INSERT INTO temp_token (refresh_token, transactionid, token, authtoken, user_id, headers, txn_date, temp_state, temp_text, create_at) VALUES ('${refresh_tokenx}', '${transactionid}', '${responseData.txn}', '${fid}', '${uid}', '${JSON.stringify(headers)}', '${responseData.txn_date}', '${state}', '${JSON.stringify(familyJson)}', '${create_date}')`);

        return (insertResult)
            ? { status: true, message: 'Your OTP has been successfully verified', refresh_token: refresh_tokenx }
            : { status: false, error: 'OTP has been successfully verified, but database record insertion failed.', reload: true };

    } catch (error) {
        return (error.message.includes('*'))
            ? { status: false, error: error.message }
            : { status: false, error: `OTP Verify Error: ${error.message}`, reload: true };
    }
}

async function add_family_member_v2(refresh_token, img, ctype, name, fname, gender, dob, relation, address, state, district, subdistrict, village, pin, type, usid = '',) {

    const create_date = moment().format('YYYY-MM-DD HH:mm:ss');

    try {

        if (!name) throw new Error('*Please enter a name');
        if (name.length < 3) throw new Error('*Your name must consist of at least 3 characters');
        if (name.length > 40) throw new Error('*Your name cannot be more than 40 characters');
        if (!/^[A-Za-z ]+$/.test(name)) throw new Error('*Please enter a valid name');
        if (!fname) throw new Error('*Please enter a father name');
        if (fname.length < 3) throw new Error('*Your father name must consist of at least 3 characters');
        if (fname.length > 40) throw new Error('*Your father name cannot be more than 40 characters');
        if (!/^[A-Za-z ]+$/.test(fname)) throw new Error('*Please enter a valid father name');
        if (!gender) throw new Error('*Please select a gender');
        if (!dob) throw new Error('*Please select your date of birth');
        if (!img) throw new Error('*Please select your image');
        if (!relation) throw new Error('*Please select your relation');
        if (!address) throw new Error('*Please enter a user address');
        if (!state) throw new Error('*Please select a state');
        if (!district) throw new Error('*Please select a district');
        if (!subdistrict) throw new Error('*Please select a subdistrict');
        if (!village) throw new Error('*Please select a village');
        if (!pin) throw new Error('*Please enter a pin code');
        if (!type) throw new Error('*Please enter a village type');
        if (!/^\d{6}$/.test(pin)) throw new Error('*Your pin code must consist of digits only and be exactly 6 characters long');

        const { count, result } = await database.sqlGet(`SELECT * FROM temp_token WHERE refresh_token = '${refresh_token}';`);
        if (count === 0) { throw new Error('refresh_token is incorrect or has expired.'); }

        const headers = JSON.parse(result.headers);
        const transctionid = result.transactionid;
        const txn = result.token;
        const txn_date = result.txn_date;
        const fid = result.authtoken;
        const uid = result.user_id;

        const familyJson = JSON.parse(result.temp_text);

        const state_name = (await getState()).status ? getStateName(state, await getState()) : null;
        const district_name = (await getDistrict(state)).status ? getvalueName(district, await getDistrict(state)) : null;
        const block_name = (await getSubDistrict(state, district, type)).status ? getvalueName(subdistrict, await getSubDistrict(state, district, type)) : null;
        const village_name = (await getVillage(state, district, subdistrict, type)).status ? getvalueName(village, await getVillage(state, district, subdistrict, type)) : null;
        const full_address = formatText(address);

        const agex = moment().format('YYYY') - moment(dob, 'YYYY-MM-DD').format('YYYY');
        const yearOfBirth = moment(dob, 'YYYY-MM-DD').format('YYYY');
        const dateOfBirth = moment(dob, 'YYYY-MM-DD').format('DD-MM-YYYY');
        const ExaadharNumber = encrypt.encrypt(transctionid, uid);
        const subShort_Aadhaar = uid.substr(-4);

        const temp_jsonx = JSON.stringify({
            "benId": familyJson.uId,
            "familyId": fid,
            "name": name,
            "fatherName": fname,
            "age": `${agex}`,
            "stateCode": state,
            "distCode": district,
            "blockId": subdistrict,
            "villageId": village,
            "ruralUrbanFlag": type.toUpperCase(),
            "benMobileNo": "NA",
            "benEmailId": null,
            "gender": gender.toUpperCase(),
            "yearOfBirth": yearOfBirth,
            "dateOfBirth": yearOfBirth,
            "houseNo": null,
            "street": full_address,
            "city": subdistrict,
            "pinCode": pin,
            "address": full_address,
            "benSourceDtls": {
                "name": name,
                "yearOfBirth": yearOfBirth,
                "gender": gender.toUpperCase(),
                "fatherName": fname,
                "spouse": null,
                "addressline1": full_address,
                "addressline2": pin,
                "city": "0",
                "district": district,
                "state": state,
                "pincode": pin
            },
            "benEkycDtls": {},
            "benOtherDtls": {
                "attr1": null,
                "attr2": null,
                "attr3": null,
                "aadharNumber": [
                    {
                        "docid": null,
                        "docName": null,
                      	"doccontent": null
                    }
                ],
                "additionalDetails": [
                    {
                        "fieldName": "aadhaar_consent",
                        "fieldValue": "Y"
                    },
                    {
                        "fieldName": "app_version",
                        "fieldValue": "1.0"
                    },
                    {
                        "fieldName": "sourceType",
                        "fieldValue": ctype
                    },
                    {
                        "fieldName": "mobileVerifyExemp",
                        "fieldValue": "Y"
                    },
                    {
                        "fieldName": "State",
                        "fieldValue": state_name
                    },
                    {
                        "fieldName": "District",
                        "fieldValue": district_name
                    },
                    {
                        "fieldName": "Sub-District",
                        "fieldValue": block_name
                    },
                    {
                        "fieldName": "Village",
                        "fieldValue": village_name
                    },
                    {
                        "fieldName": "BenMobileNumber",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "BenPrimaryAadhaar",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "BenPrimaryTnx",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "processingtime",
                        "fieldValue": `${getRandomInt(165, 380)}`
                    },
                    {
                        "fieldName": "docID",
                        "fieldValue": `${getRandomInt(1111111111, 9999999999)}`
                    },
                    {
                        "fieldName": "dynamicForms",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "income",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "issuedDate",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "incomeName",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "incomeFatherName",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "incomeCertNo",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "expiryDate",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "dtpName",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "pppId",
                        "fieldValue": null
                    },
                    {
                        "fieldName": "retirementDate",
                        "fieldValue": null
                    }
                ]
            },
            "aadharVault": {
                "aadharNumber": ExaadharNumber
            },
            "authObj": {
                "authMode": "AADHAAR_OTP",
                "txn": txn,
                "ekycDate": txn_date
            },
            "primaryAuthObj": {
                "authMode": null,
                "id": null,
                "txn": null
            },
            "enrlStatus": null,
            "abhaId": null,
            "payerId": state,
            "tpaIsaId": null,
            "sourceType": null,
            "enrollFor": relation,
            "photo": img.replace('data:image/jpeg;base64,', ''),
            "memberFlag": "N",
            "autoApprovalFlag": "Y",
            "matchScore": "0.95",
            "memberId": familyJson.memberId,
            "bisMemberId": familyJson.bisMemberId,
            "bisFamilyId": familyJson.bisFamilyId,
            "schemeCode": "PMJAY",
            "requestType": "N",
            "sourceMemberId": familyJson.uId,
            "aadharDispCode": subShort_Aadhaar,
            "apiFlag": "Y"
        });

        const enrolmentPaylode = encrypt.encryptWithKey(temp_jsonx, strict_pass);
      
      	const enrolmentRequest = await fetch('https://apisprod.nha.gov.in/pmjay/prodbis/enrolmentbis/bis/save/v4/enrolmentDetails', {
            method: 'POST',
            headers: headers,
            body: enrolmentPaylode
        });

        const enrolmentResponse = await enrolmentRequest.json();

        if (enrolmentResponse.error) {
            throw new Error(enrolmentResponse.error.message);
        } else if (fid == enrolmentResponse.referenceId) {
            throw new Error(enrolmentResponse.message);
        }

        const insertResult = await database.sqlUpdateWithID(`INSERT INTO temp_hhid(usid, uid, state, service_name, name, state_code, fid, refid, create_at, responce) VALUES('${usid}', '${uid}', '${state_name}', 'Add Member', '${name}', '${state}', '${fid}', '${enrolmentResponse.referenceId}', '${create_date}', '${JSON.stringify(enrolmentResponse)}');`);

        return (insertResult) ? { status: true, message: enrolmentResponse.message, processId: insertResult, refid: enrolmentResponse.referenceId } : { status: false, error: `${enrolmentResponse.message}, But Database record insertion failed.`, relode: true };

    } catch (error) {
        return (error.message.includes('*')) ? { status: false, error: error.message } : { status: false, error: error.message, relode: true };
    }
}


module.exports = {
    ayushman_approve_reject,
    ayushman_crad_fatch,
    ayushman_crad_download,

    getState,
    getDistrict,
    getSubDistrict,
    getVillage,
    getSchemeCode,

  	member_send_otp_v2,
  	member_verify_otp_v2,
    add_family_member_v2,
}