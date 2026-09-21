// Minimal fake Express req/res for unit-testing controllers without a real server.
function mockReq({ body = {}, query = {}, session = null, headers = {} } = {}) {
    if (session && typeof session.destroy !== "function") {
        session.destroy = (cb) => cb && cb();
    }
    return { body, query, session, headers };
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
    res.clearCookie = (name) => {
        res.clearedCookie = name;
        return res;
    };
    res.setHeader = (name, value) => {
        res.headers[name] = value;
        return res;
    };
    res.send = (body) => {
        res.body = body;
        return res;
    };
    return res;
}

module.exports = { mockReq, mockRes };
