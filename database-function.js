const mysql = require('mysql2');

const pool = mysql.createPool({
    host: '193.203.184.98',
    user: 'u767527953_portal',
    password: 'Govinda@841410',
    database: 'u767527953_portal'
});

const db = pool.promise();

async function sqlGet(query) {
    const [rows] = await db.query(query);
    return ({
        count: rows.length,
        result: rows[0] || null,
    });
}

async function sqlUpdate(query) {
    const [result] = await db.query(query);
    return result;
}

async function sqlGetAll(query) {
    const [rows] = await db.query(query);
    return ({
        count: rows.length,
        result: rows,
    });
}

async function sqlGetAllwithKey(query) {
    const [rows] = await db.query(query);
    return ({
        count: rows.length,
        result: rows,
    });
}

async function sqlUpdateWithID(query) {
    const [result] = await db.query(query);
    return result.insertId || 0;
}

async function sqlUpdateAll(queryString) {
    const queries = queryString.split(';').map(q => q.trim()).filter(q => q); // Trim and filter empty queries
    const results = await Promise.all(queries.map(query => db.query(query)));
    const affectedRows = results.reduce((total, result) => { return total + (result[0]?.affectedRows || 0); }, 0);

    return affectedRows > 0 ? 1 : 0;
}

module.exports = {
    sqlGet,
    sqlUpdate,
    sqlGetAll,
    sqlGetAllwithKey,
    sqlUpdateWithID,
    sqlUpdateAll,
};

