'use strict';
var crypto = require('crypto');

function generateNonceStr(len){
  var length = len || 16;
  var nonceStr = crypto.randomBytes(length).toString('hex');
  return nonceStr;
}

function prepareSignData(params){
  var keys = Object.keys(params).sort();
  var pairs = keys.map((key)=>{
    return key + '='+ encodeURIComponent(params[key])
  });
  return pairs.join('&');
}

function sha1Sign(params){
  var data = prepareSignData(params);
  var signature = crypto.createHash('sha1').update(data,'utf8').digest('hex');
  return signature;
}

function md5Sign(params){
  var data = prepareSignData(params);
  var signature = crypto.createHash('md5').update(data,'utf8').digest('hex');
  return signature;
}

function xmlSign(params, mch_key, method){
  method = method || 'md5';
  var keys = Object.keys(params).sort();
  var pairs = [];
  keys.forEach((key)=>{
    var value = params[key];
    if ( value == null ) return ;
    pairs.push(key + '='+ encodeURIComponent(value));
  });
  if ( mch_key ) {
    pairs.push('key='+mch_key);
  }
  var signData = pairs.join('&');
  var signature = crypto.createHash(method).update(data,'utf8').digest('hex');
  pairs = ['<xml>'];
  keys.forEach(function(key){
    var value = params[key];
    if ( value == null ) return ;
    pairs.push('<'+key+'><![CDATA['+value+']]></'+key+'>');
  });
  pairs.push('</xml>');
  return pairs.join('');
}

function xmlResult(errCode, errMsg, data){
  var pairs = ['<xml>'];
  errCode = errCode==null?'SUCCESS':errCode;
  errMsg = errMsg==null?'OK': errMsg;
  pairs.push(`<errcode>${errCode}</errcode>`);
  pairs.push(`<errmsg>${errMsg}</errmsg>`);
  if ( data ) {
    Object.keys(data).forEach(function(key){
      var value = data[key];
      if ( value == null ) return;
      pairs.push(`<${key}><![CDATA[${value}]]></${key}>`)
    });
  }
  return pairs.join('');
}

module.exports = {
  generateNonceStr: generateNonceStr,
  sha1Sign: sha1Sign,
  md5Sign: md5Sign,
  xmlSign: xmlSign,
  xmlResult: xmlResult
}
