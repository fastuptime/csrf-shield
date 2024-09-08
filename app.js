const CryptoJS = require('crypto-js');

module.exports = function(options = {}) {
    const {
        secret = CryptoJS.lib.WordArray.random(32).toString(),
        timeout = 1000 * 60 * 10,
    } = options;

    function generateToken(ip, userAgent) {
        const timestamp = Date.now();
        const data = JSON.stringify({ ip, userAgent, timestamp });
        return CryptoJS.AES.encrypt(data, secret).toString();
    }

    function parseToken(token) {
        try {
            const bytes = CryptoJS.AES.decrypt(token, secret);
            const decryptedData = bytes.toString(CryptoJS.enc.Utf8);
            return JSON.parse(decryptedData);
        } catch (error) {
            throw new Error('Invalid token');
        }
    }

    function verifyToken(token, ip, userAgent) {
        try {
            const { ip: tokenIp, userAgent: tokenUserAgent, timestamp } = parseToken(token);
            
            if (tokenIp !== ip || tokenUserAgent !== userAgent) {
                return { valid: false, reason: 'Token mismatch' };
            }
            
            if (Date.now() - timestamp > timeout) {
                return { valid: false, reason: 'Token expired' };
            }
            
            return { valid: true };
        } catch (error) {
            return { valid: false, reason: error.message };
        }
    }

    return {
        middleware: function(req, res, next) {
            req.csrfToken = function() {
                const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip;
                const userAgent = req.headers['user-agent'];
                return generateToken(ip, userAgent);
            };
            next();
        },
        
        verifyToken: function() {
            return function(req, res, next) {
                const token = req.body._csrf || req.query._csrf || req.headers['x-csrf-token'];
                
                if (!token) {
                    return res.status(403).json({ status: false, message: 'CSRF token is missing' });
                }

                const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip;
                const userAgent = req.headers['user-agent'];

                const { valid, reason } = verifyToken(token, ip, userAgent);

                if (!valid) {
                    return res.status(403).json({ status: false, message: `CSRF_TOKEN_INVALID`, details: reason });
                }

                next();
            };
        }
    };
};