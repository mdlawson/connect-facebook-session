var crypto = require('crypto');
module.exports = function(options) {
  var appId = options.appId;
  var secret = options.secret;
  var parse = function(cookie){
    var encoded = cookie.split(".",2);
    var sig = encoded[0];
    var data = JSON.parse(new Buffer(encoded[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    if (!data.algorithm || (data.algorithm.toUpperCase() != 'HMAC-SHA256')) {
      return new Error("unknown algorithm. expected HMAC-SHA256");
    }
    var expectedSig = crypto.createHmac('sha256', secret).update(encoded[1]).digest('base64').replace(/\+/g,'-').replace(/\//g,'_').replace('=','');
    if (sig !== expectedSig) {
      return new Error("bad signature");
    }
    return data;
  };
  return function(req, res, next){
    var cookie = req.cookies["fbsr_"+appId];
    var signed = req.body.signed_request;
    if (signed) { cookie = signed; }
    if (cookie) {
      req.facebook = parse(cookie);
    }
    next();
  };
};