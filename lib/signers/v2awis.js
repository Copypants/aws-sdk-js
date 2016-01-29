var AWS = require('../core');
var inherit = AWS.util.inherit;

/**
 * @api private
 */
AWS.Signers.V2AWIS = inherit(AWS.Signers.RequestSigner, {
  addAuthorization: function addAuthorization(credentials, date) {

    console.log('!!!!! AWS.Signers.V2AWIS.addAuthorization !!!!!');

    if (!date) date = AWS.util.date.getDate();

    var r = this.request;

    r.params.Timestamp = AWS.util.date.iso8601(date);
    r.params.SignatureVersion = '2';
    r.params.SignatureMethod = 'HmacSHA1';
    r.params.AWSAccessKeyId = credentials.accessKeyId;

    if (credentials.sessionToken) {
      r.params.SecurityToken = credentials.sessionToken;
    }

    delete r.params.Signature; // delete old Signature for re-signing
    r.params.Signature = this.signature(credentials);

    r.body = AWS.util.queryParamsToString(r.params);
    r.headers['Content-Length'] = r.body.length;

    console.log('!!!!! r.params !!!!!', r.params);
  },

  signature: function signature(credentials) {
    var stringToSign = this.stringToSign();
    console.log('## string to sign ##', stringToSign);
    return AWS.util.crypto.hmac(credentials.secretAccessKey, stringToSign, 'base64');
  },

  stringToSign: function stringToSign() {

    console.log(this.request.params);

    this.request.method = 'GET';

    var parts = [];
    parts.push(this.request.method);
    parts.push(this.request.endpoint.host.toLowerCase());
    parts.push(this.request.pathname());
    parts.push(AWS.util.queryParamsToString(this.request.params));
    return parts.join('\n');
  }

});

module.exports = AWS.Signers.V2AWIS;
