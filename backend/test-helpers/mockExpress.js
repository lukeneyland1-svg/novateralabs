// Minimal fake Express req/res for unit-testing controllers without a real server.
function mockReq({ body = {}, query = {}, session = null } = {}) {
    return { body, query, session };
}

function mockRes() {
    const res = {
        statusCode: 200,
        body: undefined,
        headers: {},
        ended: false,
    };
    res.status = (code) => {
        res.statusCode = code;
        return res;
    };
    res.json = (payload) => {
        res.body = payload;
        return res;
    };
    res.redirect = (location) => {
        res.statusCode = 302;
        res.redirectedTo = location;
        return res;
    };
    res.writeHead = (code, headers) => {
        res.statusCode = code;
        res.headers = headers;
        return res;
    };
    res.write = (chunk) => {
        res.written = (res.written || "") + chunk;
        return true;
    };
    res.on = () => {};
    return res;
}

module.exports = { mockReq, mockRes };
