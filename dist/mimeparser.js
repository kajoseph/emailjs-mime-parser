'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.MimeNode = exports.NodeCounter = undefined;

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

exports.default = parse;

var _ramda = require('ramda');

var _timezones = require('./timezones');

var _timezones2 = _interopRequireDefault(_timezones);

var _emailjsMimeCodecBigarray = require('emailjs-mime-codec-bigarray');

var _textEncoding = require('text-encoding');

var _emailjsAddressparser = require('emailjs-addressparser');

var _emailjsAddressparser2 = _interopRequireDefault(_emailjsAddressparser);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
 * Counts MIME nodes to prevent memory exhaustion attacks (CWE-400)
 * see: https://snyk.io/vuln/npm:emailjs-mime-parser:20180625
 */
var MAXIMUM_NUMBER_OF_MIME_NODES = 999;

var NodeCounter = exports.NodeCounter = function () {
  function NodeCounter() {
    _classCallCheck(this, NodeCounter);

    this.count = 0;
  }

  _createClass(NodeCounter, [{
    key: 'bump',
    value: function bump() {
      if (++this.count > MAXIMUM_NUMBER_OF_MIME_NODES) {
        throw new Error('Maximum number of MIME nodes exceeded!');
      }
    }
  }]);

  return NodeCounter;
}();

function parse(chunk) {
  var root = new MimeNode(new NodeCounter());
  var lines = ((typeof chunk === 'undefined' ? 'undefined' : _typeof(chunk)) === 'object' ? String.fromCharCode.apply(null, chunk) : chunk).split(/\r?\n/g);
  lines.forEach(function (line) {
    return root.writeLine(line);
  });
  root.finalize();
  return root;
}

var MimeNode = exports.MimeNode = function () {
  function MimeNode() {
    var nodeCounter = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : new NodeCounter();

    _classCallCheck(this, MimeNode);

    this.nodeCounter = nodeCounter;
    this.nodeCounter.bump();

    this.header = []; // An array of unfolded header lines
    this.headers = {}; // An object that holds header key=value pairs
    this.bodystructure = '';
    this.childNodes = []; // If this is a multipart or message/rfc822 mime part, the value will be converted to array and hold all child nodes for this node
    this.raw = ''; // Stores the raw content of this node

    this._state = 'HEADER'; // Current state, always starts out with HEADER
    this._bodyBuffer = ''; // Body buffer
    this._lineCount = 0; // Line counter bor the body part
    this._currentChild = false; // Active child node (if available)
    this._lineRemainder = ''; // Remainder string when dealing with base64 and qp values
    this._isMultipart = false; // Indicates if this is a multipart node
    this._multipartBoundary = false; // Stores boundary value for current multipart node
    this._isRfc822 = false; // Indicates if this is a message/rfc822 node
  }

  _createClass(MimeNode, [{
    key: 'writeLine',
    value: function writeLine(line) {
      this.raw += (this.raw ? '\n' : '') + line;

      if (this._state === 'HEADER') {
        this._processHeaderLine(line);
      } else if (this._state === 'BODY') {
        this._processBodyLine(line);
      }
    }
  }, {
    key: 'finalize',
    value: function finalize() {
      var _this = this;

      if (this._isRfc822) {
        this._currentChild.finalize();
      } else {
        this._emitBody();
      }

      this.bodystructure = this.childNodes.reduce(function (agg, child) {
        return agg + '--' + _this._multipartBoundary + '\n' + child.bodystructure;
      }, this.header.join('\n') + '\n\n') + (this._multipartBoundary ? '--' + this._multipartBoundary + '--\n' : '');
    }
  }, {
    key: '_decodeBodyBuffer',
    value: function _decodeBodyBuffer() {
      switch (this.contentTransferEncoding.value) {
        case 'base64':
          this._bodyBuffer = (0, _emailjsMimeCodecBigarray.base64Decode)(this._bodyBuffer, this.charset);
          break;
        case 'quoted-printable':
          {
            this._bodyBuffer = this._bodyBuffer.replace(/=(\r?\n|$)/g, '').replace(/=([a-f0-9]{2})/ig, function (m, code) {
              return String.fromCharCode(parseInt(code, 16));
            });
            break;
          }
      }
    }

    /**
     * Processes a line in the HEADER state. It the line is empty, change state to BODY
     *
     * @param {String} line Entire input line as 'binary' string
     */

  }, {
    key: '_processHeaderLine',
    value: function _processHeaderLine(line) {
      if (!line) {
        this._parseHeaders();
        this.bodystructure += this.header.join('\n') + '\n\n';
        this._state = 'BODY';
        return;
      }

      if (line.match(/^\s/) && this.header.length) {
        this.header[this.header.length - 1] += '\n' + line;
      } else {
        this.header.push(line);
      }
    }

    /**
     * Joins folded header lines and calls Content-Type and Transfer-Encoding processors
     */

  }, {
    key: '_parseHeaders',
    value: function _parseHeaders() {
      for (var hasBinary = false, i = 0, len = this.header.length; i < len; i++) {
        var value = this.header[i].split(':');
        var key = (value.shift() || '').trim().toLowerCase();
        value = (value.join(':') || '').replace(/\n/g, '').trim();

        if (value.match(/[\u0080-\uFFFF]/)) {
          if (!this.charset) {
            hasBinary = true;
          }
          // use default charset at first and if the actual charset is resolved, the conversion is re-run
          value = (0, _emailjsMimeCodecBigarray.decode)((0, _emailjsMimeCodecBigarray.convert)(str2arr(value), this.charset || 'iso-8859-1'));
        }

        this.headers[key] = (this.headers[key] || []).concat([this._parseHeaderValue(key, value)]);

        if (!this.charset && key === 'content-type') {
          this.charset = this.headers[key][this.headers[key].length - 1].params.charset;
        }

        if (hasBinary && this.charset) {
          // reset values and start over once charset has been resolved and 8bit content has been found
          hasBinary = false;
          this.headers = {};
          i = -1; // next iteration has i == 0
        }
      }

      this.fetchContentType();
      this._processContentTransferEncoding();
    }

    /**
     * Parses single header value
     * @param {String} key Header key
     * @param {String} value Value for the key
     * @return {Object} parsed header
     */

  }, {
    key: '_parseHeaderValue',
    value: function _parseHeaderValue(key, value) {
      var parsedValue = void 0;
      var isAddress = false;

      switch (key) {
        case 'content-type':
        case 'content-transfer-encoding':
        case 'content-disposition':
        case 'dkim-signature':
          parsedValue = (0, _emailjsMimeCodecBigarray.parseHeaderValue)(value);
          break;
        case 'from':
        case 'sender':
        case 'to':
        case 'reply-to':
        case 'cc':
        case 'bcc':
        case 'abuse-reports-to':
        case 'errors-to':
        case 'return-path':
        case 'delivered-to':
          isAddress = true;
          parsedValue = {
            value: [].concat((0, _emailjsAddressparser2.default)(value) || [])
          };
          break;
        case 'date':
          parsedValue = {
            value: this._parseDate(value)
          };
          break;
        default:
          parsedValue = {
            value: value
          };
      }
      parsedValue.initial = value;

      this._decodeHeaderCharset(parsedValue, { isAddress: isAddress });

      return parsedValue;
    }

    /**
     * Checks if a date string can be parsed. Falls back replacing timezone
     * abbrevations with timezone values. Bogus timezones default to UTC.
     *
     * @param {String} str Date header
     * @returns {String} UTC date string if parsing succeeded, otherwise returns input value
     */

  }, {
    key: '_parseDate',
    value: function _parseDate() {
      var str = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';

      var date = new Date(str.trim().replace(/\b[a-z]+$/i, function (tz) {
        return _timezones2.default[tz.toUpperCase()] || '+0000';
      }));
      return date.toString() !== 'Invalid Date' ? date.toUTCString().replace(/GMT/, '+0000') : str;
    }
  }, {
    key: '_decodeHeaderCharset',
    value: function _decodeHeaderCharset(parsed) {
      var _this2 = this;

      var _ref = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {},
          isAddress = _ref.isAddress;

      // decode default value
      if (typeof parsed.value === 'string') {
        parsed.value = (0, _emailjsMimeCodecBigarray.mimeWordsDecode)(parsed.value);
      }

      // decode possible params
      Object.keys(parsed.params || {}).forEach(function (key) {
        if (typeof parsed.params[key] === 'string') {
          parsed.params[key] = (0, _emailjsMimeCodecBigarray.mimeWordsDecode)(parsed.params[key]);
        }
      });

      // decode addresses
      if (isAddress && Array.isArray(parsed.value)) {
        parsed.value.forEach(function (addr) {
          if (addr.name) {
            addr.name = (0, _emailjsMimeCodecBigarray.mimeWordsDecode)(addr.name);
            if (Array.isArray(addr.group)) {
              _this2._decodeHeaderCharset({ value: addr.group }, { isAddress: true });
            }
          }
        });
      }

      return parsed;
    }

    /**
     * Parses Content-Type value and selects following actions.
     */

  }, {
    key: 'fetchContentType',
    value: function fetchContentType() {
      var defaultValue = (0, _emailjsMimeCodecBigarray.parseHeaderValue)('text/plain');
      this.contentType = (0, _ramda.pathOr)(defaultValue, ['headers', 'content-type', '0'])(this);
      this.contentType.value = (this.contentType.value || '').toLowerCase().trim();
      this.contentType.type = this.contentType.value.split('/').shift() || 'text';

      if (this.contentType.params && this.contentType.params.charset && !this.charset) {
        this.charset = this.contentType.params.charset;
      }

      if (this.contentType.type === 'multipart' && this.contentType.params.boundary) {
        this.childNodes = [];
        this._isMultipart = this.contentType.value.split('/').pop() || 'mixed';
        this._multipartBoundary = this.contentType.params.boundary;
      }

      /**
       * For attachment (inline/regular) if charset is not defined and attachment is non-text/*,
       * then default charset to binary.
       * Refer to issue: https://github.com/emailjs/emailjs-mime-parser/issues/18
       */
      var defaultContentDispositionValue = (0, _emailjsMimeCodecBigarray.parseHeaderValue)('');
      var contentDisposition = (0, _ramda.pathOr)(defaultContentDispositionValue, ['headers', 'content-disposition', '0'])(this);
      var isAttachment = (contentDisposition.value || '').toLowerCase().trim() === 'attachment';
      var isInlineAttachment = (contentDisposition.value || '').toLowerCase().trim() === 'inline';
      if ((isAttachment || isInlineAttachment) && this.contentType.type !== 'text' && !this.charset) {
        this.charset = 'binary';
      }

      if (this.contentType.value === 'message/rfc822' && !isAttachment) {
        /**
         * Parse message/rfc822 only if the mime part is not marked with content-disposition: attachment,
         * otherwise treat it like a regular attachment
         */
        this._currentChild = new MimeNode(this.nodeCounter);
        this.childNodes = [this._currentChild];
        this._isRfc822 = true;
      }
    }

    /**
     * Parses Content-Transfer-Encoding value to see if the body needs to be converted
     * before it can be emitted
     */

  }, {
    key: '_processContentTransferEncoding',
    value: function _processContentTransferEncoding() {
      var defaultValue = (0, _emailjsMimeCodecBigarray.parseHeaderValue)('7bit');
      this.contentTransferEncoding = (0, _ramda.pathOr)(defaultValue, ['headers', 'content-transfer-encoding', '0'])(this);
      this.contentTransferEncoding.value = (0, _ramda.pathOr)('', ['contentTransferEncoding', 'value'])(this).toLowerCase().trim();
    }

    /**
     * Processes a line in the BODY state. If this is a multipart or rfc822 node,
     * passes line value to child nodes.
     *
     * @param {String} line Entire input line as 'binary' string
     */

  }, {
    key: '_processBodyLine',
    value: function _processBodyLine(line) {
      if (this._isMultipart) {
        if (line === '--' + this._multipartBoundary) {
          this.bodystructure += line + '\n';
          if (this._currentChild) {
            this._currentChild.finalize();
          }
          this._currentChild = new MimeNode(this.nodeCounter);
          this.childNodes.push(this._currentChild);
        } else if (line === '--' + this._multipartBoundary + '--') {
          this.bodystructure += line + '\n';
          if (this._currentChild) {
            this._currentChild.finalize();
          }
          this._currentChild = false;
        } else if (this._currentChild) {
          this._currentChild.writeLine(line);
        } else {
          // Ignore multipart preamble
        }
      } else if (this._isRfc822) {
        this._currentChild.writeLine(line);
      } else {
        this._lineCount++;

        switch (this.contentTransferEncoding.value) {
          case 'base64':
            this._bodyBuffer += line;
            break;
          case 'quoted-printable':
            {
              var curLine = this._lineRemainder + (this._lineCount > 1 ? '\n' : '') + line;
              var match = curLine.match(/=[a-f0-9]{0,1}$/i);
              if (match) {
                this._lineRemainder = match[0];
                curLine = curLine.substr(0, curLine.length - this._lineRemainder.length);
              } else {
                this._lineRemainder = '';
              }
              this._bodyBuffer += curLine;
              break;
            }
          case '7bit':
          case '8bit':
          default:
            this._bodyBuffer += (this._lineCount > 1 ? '\n' : '') + line;
            break;
        }
      }
    }

    /**
     * Emits a chunk of the body
    */

  }, {
    key: '_emitBody',
    value: function _emitBody() {
      this._decodeBodyBuffer();
      if (this._isMultipart || !this._bodyBuffer) {
        return;
      }

      this._processFlowedText();
      this.content = str2arr(this._bodyBuffer);
      this._processHtmlText();
      this._bodyBuffer = '';
    }
  }, {
    key: '_processFlowedText',
    value: function _processFlowedText() {
      var isText = /^text\/(plain|html)$/i.test(this.contentType.value);
      var isFlowed = /^flowed$/i.test((0, _ramda.pathOr)('', ['contentType', 'params', 'format'])(this));
      if (!isText || !isFlowed) return;

      var delSp = /^yes$/i.test(this.contentType.params.delsp);
      this._bodyBuffer = this._bodyBuffer.split('\n').reduce(function (previousValue, currentValue) {
        // remove soft linebreaks after space symbols.
        // delsp adds spaces to text to be able to fold it.
        // these spaces can be removed once the text is unfolded
        var endsWithSpace = / $/.test(previousValue);
        var isBoundary = /(^|\n)-- $/.test(previousValue);
        return (delSp ? previousValue.replace(/[ ]+$/, '') : previousValue) + (endsWithSpace && !isBoundary ? '' : '\n') + currentValue;
      }).replace(/^ /gm, ''); // remove whitespace stuffing http://tools.ietf.org/html/rfc3676#section-4.4
    }
  }, {
    key: '_processHtmlText',
    value: function _processHtmlText() {
      var contentDisposition = this.headers['content-disposition'] && this.headers['content-disposition'][0] || (0, _emailjsMimeCodecBigarray.parseHeaderValue)('');
      var isHtml = /^text\/(plain|html)$/i.test(this.contentType.value);
      var isAttachment = /^attachment$/i.test(contentDisposition.value);
      if (isHtml && !isAttachment) {
        if (!this.charset && /^text\/html$/i.test(this.contentType.value)) {
          this.charset = this.detectHTMLCharset(this._bodyBuffer);
        }

        // decode "binary" string to an unicode string
        if (!/^utf[-_]?8$/i.test(this.charset)) {
          this.content = (0, _emailjsMimeCodecBigarray.convert)(str2arr(this._bodyBuffer), this.charset || 'iso-8859-1');
        } else if (this.contentTransferEncoding.value === 'base64') {
          this.content = utf8Str2arr(this._bodyBuffer);
        }

        // override charset for text nodes
        this.charset = this.contentType.params.charset = 'utf-8';
      }
    }

    /**
     * Detect charset from a html file
     *
     * @param {String} html Input HTML
     * @returns {String} Charset if found or undefined
     */

  }, {
    key: 'detectHTMLCharset',
    value: function detectHTMLCharset(html) {
      var charset = void 0,
          input = void 0;

      html = html.replace(/\r?\n|\r/g, ' ');
      var meta = html.match(/<meta\s+http-equiv=["'\s]*content-type[^>]*?>/i);
      if (meta) {
        input = meta[0];
      }

      if (input) {
        charset = input.match(/charset\s?=\s?([a-zA-Z\-_:0-9]*);?/);
        if (charset) {
          charset = (charset[1] || '').trim().toLowerCase();
        }
      }

      meta = html.match(/<meta\s+charset=["'\s]*([^"'<>/\s]+)/i);
      if (!charset && meta) {
        charset = (meta[1] || '').trim().toLowerCase();
      }

      return charset;
    }
  }]);

  return MimeNode;
}();

var str2arr = function str2arr(str) {
  return new Uint8Array(str.split('').map(function (char) {
    return char.charCodeAt(0);
  }));
};
var utf8Str2arr = function utf8Str2arr(str) {
  return new _textEncoding.TextEncoder('utf-8').encode(str);
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9taW1lcGFyc2VyLmpzIl0sIm5hbWVzIjpbInBhcnNlIiwiTUFYSU1VTV9OVU1CRVJfT0ZfTUlNRV9OT0RFUyIsIk5vZGVDb3VudGVyIiwiY291bnQiLCJFcnJvciIsImNodW5rIiwicm9vdCIsIk1pbWVOb2RlIiwibGluZXMiLCJTdHJpbmciLCJmcm9tQ2hhckNvZGUiLCJhcHBseSIsInNwbGl0IiwiZm9yRWFjaCIsIndyaXRlTGluZSIsImxpbmUiLCJmaW5hbGl6ZSIsIm5vZGVDb3VudGVyIiwiYnVtcCIsImhlYWRlciIsImhlYWRlcnMiLCJib2R5c3RydWN0dXJlIiwiY2hpbGROb2RlcyIsInJhdyIsIl9zdGF0ZSIsIl9ib2R5QnVmZmVyIiwiX2xpbmVDb3VudCIsIl9jdXJyZW50Q2hpbGQiLCJfbGluZVJlbWFpbmRlciIsIl9pc011bHRpcGFydCIsIl9tdWx0aXBhcnRCb3VuZGFyeSIsIl9pc1JmYzgyMiIsIl9wcm9jZXNzSGVhZGVyTGluZSIsIl9wcm9jZXNzQm9keUxpbmUiLCJfZW1pdEJvZHkiLCJyZWR1Y2UiLCJhZ2ciLCJjaGlsZCIsImpvaW4iLCJjb250ZW50VHJhbnNmZXJFbmNvZGluZyIsInZhbHVlIiwiY2hhcnNldCIsInJlcGxhY2UiLCJtIiwiY29kZSIsInBhcnNlSW50IiwiX3BhcnNlSGVhZGVycyIsIm1hdGNoIiwibGVuZ3RoIiwicHVzaCIsImhhc0JpbmFyeSIsImkiLCJsZW4iLCJrZXkiLCJzaGlmdCIsInRyaW0iLCJ0b0xvd2VyQ2FzZSIsInN0cjJhcnIiLCJjb25jYXQiLCJfcGFyc2VIZWFkZXJWYWx1ZSIsInBhcmFtcyIsImZldGNoQ29udGVudFR5cGUiLCJfcHJvY2Vzc0NvbnRlbnRUcmFuc2ZlckVuY29kaW5nIiwicGFyc2VkVmFsdWUiLCJpc0FkZHJlc3MiLCJfcGFyc2VEYXRlIiwiaW5pdGlhbCIsIl9kZWNvZGVIZWFkZXJDaGFyc2V0Iiwic3RyIiwiZGF0ZSIsIkRhdGUiLCJ0aW1lem9uZSIsInR6IiwidG9VcHBlckNhc2UiLCJ0b1N0cmluZyIsInRvVVRDU3RyaW5nIiwicGFyc2VkIiwiT2JqZWN0Iiwia2V5cyIsIkFycmF5IiwiaXNBcnJheSIsImFkZHIiLCJuYW1lIiwiZ3JvdXAiLCJkZWZhdWx0VmFsdWUiLCJjb250ZW50VHlwZSIsInR5cGUiLCJib3VuZGFyeSIsInBvcCIsImRlZmF1bHRDb250ZW50RGlzcG9zaXRpb25WYWx1ZSIsImNvbnRlbnREaXNwb3NpdGlvbiIsImlzQXR0YWNobWVudCIsImlzSW5saW5lQXR0YWNobWVudCIsImN1ckxpbmUiLCJzdWJzdHIiLCJfZGVjb2RlQm9keUJ1ZmZlciIsIl9wcm9jZXNzRmxvd2VkVGV4dCIsImNvbnRlbnQiLCJfcHJvY2Vzc0h0bWxUZXh0IiwiaXNUZXh0IiwidGVzdCIsImlzRmxvd2VkIiwiZGVsU3AiLCJkZWxzcCIsInByZXZpb3VzVmFsdWUiLCJjdXJyZW50VmFsdWUiLCJlbmRzV2l0aFNwYWNlIiwiaXNCb3VuZGFyeSIsImlzSHRtbCIsImRldGVjdEhUTUxDaGFyc2V0IiwidXRmOFN0cjJhcnIiLCJodG1sIiwiaW5wdXQiLCJtZXRhIiwiVWludDhBcnJheSIsIm1hcCIsImNoYXIiLCJjaGFyQ29kZUF0IiwiVGV4dEVuY29kZXIiLCJlbmNvZGUiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7O2tCQXNCd0JBLEs7O0FBdEJ4Qjs7QUFDQTs7OztBQUNBOztBQUNBOztBQUNBOzs7Ozs7OztBQUVBOzs7O0FBSUEsSUFBTUMsK0JBQStCLEdBQXJDOztJQUNhQyxXLFdBQUFBLFc7QUFDWCx5QkFBZTtBQUFBOztBQUNiLFNBQUtDLEtBQUwsR0FBYSxDQUFiO0FBQ0Q7Ozs7MkJBQ087QUFDTixVQUFJLEVBQUUsS0FBS0EsS0FBUCxHQUFlRiw0QkFBbkIsRUFBaUQ7QUFDL0MsY0FBTSxJQUFJRyxLQUFKLENBQVUsd0NBQVYsQ0FBTjtBQUNEO0FBQ0Y7Ozs7OztBQUdZLFNBQVNKLEtBQVQsQ0FBZ0JLLEtBQWhCLEVBQXVCO0FBQ3BDLE1BQU1DLE9BQU8sSUFBSUMs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eUQsVUFBSixDQUFlOUMsSUFBSXhELEtBQUosQ0FBVSxFQUFWLEVBQWN1RyxHQUFkLENBQWtCO0FBQUEsV0FBUUMsS0FBS0MsVUFBTCxDQUFnQixDQUFoQixDQUFSO0FBQUEsR0FBbEIsQ0FBZixDQUFQO0FBQUEsQ0FBaEI7QUFDQSxJQUFNUCxjQUFjLFNBQWRBLFdBQWM7QUFBQSxTQUFPLElBQUlRLHlCQUFKLENBQWdCLE9BQWhCLEVBQXlCQyxNQUF6QixDQUFnQ25ELEdBQWhDLENBQVA7QUFBQSxDQUFwQiIsImZpbGUiOiJtaW1lcGFyc2VyLmpzIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgcGF0aE9yIH0gZnJvbSAncmFtZGEnXHJcbmltcG9ydCB0aW1lem9uZSBmcm9tICcuL3RpbWV6b25lcydcclxuaW1wb3J0IHsgZGVjb2RlLCBiYXNlNjREZWNvZGUsIGNvbnZlcnQsIHBhcnNlSGVhZGVyVmFsdWUsIG1pbWVXb3Jkc0RlY29kZSB9IGZyb20gJ2VtYWlsanMtbWltZS1jb2RlYy1iaWdhcnJheSdcclxuaW1wb3J0IHsgVGV4dEVuY29kZXIgfSBmcm9tICd0ZXh0LWVuY29kaW5nJ1xyXG5pbXBvcnQgcGFyc2VBZGRyZXNzIGZyb20gJ2VtYWlsanMtYWRkcmVzc3BhcnNlcidcclxuXHJcbi8qXHJcbiAqIENvdW50cyBNSU1FIG5vZGVzIHRvIHByZXZlbnQgbWVtb3J5IGV4aGF1c3Rpb24gYXR0YWNrcyAoQ1dFLTQwMClcclxuICogc2VlOiBodHRwczovL3NueWsuaW8vdnVsbi9ucG06ZW1haWxqcy1taW1lLXBhcnNlcjoyMDE4MDYyNVxyXG4gKi9cclxuY29uc3QgTUFYSU1VTV9OVU1CRVJfT0ZfTUlNRV9OT0RFUyA9IDk5OVxyXG5leHBvcnQgY2xhc3MgTm9kZUNvdW50ZXIge1xyXG4gIGNvbnN0cnVjdG9yICgpIHtcclxuICAgIHRoaXMuY291bnQgPSAwXHJcbiAgfVxyXG4gIGJ1bXAgKCkge1xyXG4gICAgaWYgKCsrdGhpcy5jb3VudCA+IE1BWElNVU1fTlVNQkVSX09GX01JTUVfTk9ERVMpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdNYXhpbXVtIG51bWJlciBvZiBNSU1FIG5vZGVzIGV4Y2VlZGVkIScpXHJcbiAgICB9XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBwYXJzZSAoY2h1bmspIHtcclxuICBjb25zdCByb290ID0gbmV3IE1pbWVOb2RlKG5ldyBOb2RlQ291bnRlcigpKVxyXG4gIGNvbnN0IGxpbmVzID0gKHR5cGVvZiBjaHVuayA9PT0gJ29iamVjdCcgPyBTdHJpbmcuZnJvbUNoYXJDb2RlLmFwcGx5KG51bGwsIGNodW5rKSA6IGNodW5rKS5zcGxpdCgvXFxyP1xcbi9nKVxyXG4gIGxpbmVzLmZvckVhY2gobGluZSA9PiByb290LndyaXRlTGluZShsaW5lKSlcclxuICByb290LmZpbmFsaXplKClcclxuICByZXR1cm4gcm9vdFxyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgTWltZU5vZGUge1xyXG4gIGNvbnN0cnVjdG9yIChub2RlQ291bnRlciA9IG5ldyBOb2RlQ291bnRlcigpKSB7XHJcbiAgICB0aGlzLm5vZGVDb3VudGVyID0gbm9kZUNvdW50ZXJcclxuICAgIHRoaXMubm9kZUNvdW50ZXIuYnVtcCgpXHJcblxyXG4gICAgdGhpcy5oZWFkZXIgPSBbXSAvLyBBbiBhcnJheSBvZiB1bmZvbGRlZCBoZWFkZXIgbGluZXNcclxuICAgIHRoaXMuaGVhZGVycyA9IHt9IC8vIEFuIG9iamVjdCB0aGF0IGhvbGRzIGhlYWRlciBrZXk9dmFsdWUgcGFpcnNcclxuICAgIHRoaXMuYm9keXN0cnVjdHVyZSA9ICcnXHJcbiAgICB0aGlzLmNoaWxkTm9kZXMgPSBbXSAvLyBJZiB0aGlzIGlzIGEgbXVsdGlwYXJ0IG9yIG1lc3NhZ2UvcmZjODIyIG1pbWUgcGFydCwgdGhlIHZhbHVlIHdpbGwgYmUgY29udmVydGVkIHRvIGFycmF5IGFuZCBob2xkIGFsbCBjaGlsZCBub2RlcyBmb3IgdGhpcyBub2RlXHJcbiAgICB0aGlzLnJhdyA9ICcnIC8vIFN0b3JlcyB0aGUgcmF3IGNvbnRlbnQgb2YgdGhpcyBub2RlXHJcblxyXG4gICAgdGhpcy5fc3RhdGUgPSAnSEVBREVSJyAvLyBDdXJyZW50IHN0YXRlLCBhbHdheXMgc3RhcnRzIG91dCB3aXRoIEhFQURFUlxyXG4gICAgdGhpcy5fYm9keUJ1ZmZlciA9ICcnIC8vIEJvZHkgYnVmZmVyXHJcbiAgICB0aGlzLl9saW5lQ291bnQgPSAwIC8vIExpbmUgY291bnRlciBib3IgdGhlIGJvZHkgcGFydFxyXG4gICAgdGhpcy5fY3VycmVudENoaWxkID0gZmFsc2UgLy8gQWN0aXZlIGNoaWxkIG5vZGUgKGlmIGF2YWlsYWJsZSlcclxuICAgIHRoaXMuX2xpbmVSZW1haW5kZXIgPSAnJyAvLyBSZW1haW5kZXIgc3RyaW5nIHdoZW4gZGVhbGluZyB3aXRoIGJhc2U2NCBhbmQgcXAgdmFsdWVzXHJcbiAgICB0aGlzLl9pc011bHRpcGFydCA9IGZhbHNlIC8vIEluZGljYXRlcyBpZiB0aGlzIGlzIGEgbXVsdGlwYXJ0IG5vZGVcclxuICAgIHRoaXMuX211bHRpcGFydEJvdW5kYXJ5ID0gZmFsc2UgLy8gU3RvcmVzIGJvdW5kYXJ5IHZhbHVlIGZvciBjdXJyZW50IG11bHRpcGFydCBub2RlXHJcbiAgICB0aGlzLl9pc1JmYzgyMiA9IGZhbHNlIC8vIEluZGljYXRlcyBpZiB0aGlzIGlzIGEgbWVzc2FnZS9yZmM4MjIgbm9kZVxyXG4gIH1cclxuXHJcbiAgd3JpdGVMaW5lIChsaW5lKSB7XHJcbiAgICB0aGlzLnJhdyArPSAodGhpcy5yYXcgPyAnXFxuJyA6ICcnKSArIGxpbmVcclxuXHJcbiAgICBpZiAodGhpcy5fc3RhdGUgPT09ICdIRUFERVInKSB7XHJcbiAgICAgIHRoaXMuX3Byb2Nlc3NIZWFkZXJMaW5lKGxpbmUpXHJcbiAgICB9IGVsc2UgaWYgKHRoaXMuX3N0YXRlID09PSAnQk9EWScpIHtcclxuICAgICAgdGhpcy5fcHJvY2Vzc0JvZHlMaW5lKGxpbmUpXHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBmaW5hbGl6ZSAoKSB7XHJcbiAgICBpZiAodGhpcy5faXNSZmM4MjIpIHtcclxuICAgICAgdGhpcy5fY3VycmVudENoaWxkLmZpbmFsaXplKClcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHRoaXMuX2VtaXRCb2R5KClcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLmJvZHlzdHJ1Y3R1cmUgPSB0aGlzLmNoaWxkTm9kZXNcclxuICAgICAgLnJlZHVjZSgoYWdnLCBjaGlsZCkgPT4gYWdnICsgJy0tJyArIHRoaXMuX211bHRpcGFydEJvdW5kYXJ5ICsgJ1xcbicgKyBjaGlsZC5ib2R5c3RydWN0dXJlLCB0aGlzLmhlYWRlci5qb2luKCdcXG4nKSArICdcXG5cXG4nKSArXHJcbiAgICAgICh0aGlzLl9tdWx0aXBhcnRCb3VuZGFyeSA/ICctLScgKyB0aGlzLl9tdWx0aXBhcnRCb3VuZGFyeSArICctLVxcbicgOiAnJylcclxuICB9XHJcblxyXG4gIF9kZWNvZGVCb2R5QnVmZmVyICgpIHtcclxuICAgIHN3aXRjaCAodGhpcy5jb250ZW50VHJhbnNmZXJFbmNvZGluZy52YWx1ZSkge1xyXG4gICAgICBjYXNlICdiYXNlNjQnOlxyXG4gICAgICAgIHRoaXMuX2JvZHlCdWZmZXIgPSBiYXNlNjREZWNvZGUodGhpcy5fYm9keUJ1ZmZlciwgdGhpcy5jaGFyc2V0KVxyXG4gICAgICAgIGJyZWFrXHJcbiAgICAgIGNhc2UgJ3F1b3RlZC1wcmludGFibGUnOiB7XHJcbiAgICAgICAgdGhpcy5fYm9keUJ1ZmZlciA9IHRoaXMuX2JvZHlCdWZmZXJcclxuICAgICAgICAgIC5yZXBsYWNlKC89KFxccj9cXG58JCkvZywgJycpXHJcbiAgICAgICAgICAucmVwbGFjZSgvPShbYS1mMC05XXsyfSkvaWcsIChtLCBjb2RlKSA9PiBTdHJpbmcuZnJvbUNoYXJDb2RlKHBhcnNlSW50KGNvZGUsIDE2KSkpXHJcbiAgICAgICAgYnJlYWtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUHJvY2Vzc2VzIGEgbGluZSBpbiB0aGUgSEVBREVSIHN0YXRlLiBJdCB0aGUgbGluZSBpcyBlbXB0eSwgY2hhbmdlIHN0YXRlIHRvIEJPRFlcclxuICAgKlxyXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBsaW5lIEVudGlyZSBpbnB1dCBsaW5lIGFzICdiaW5hcnknIHN0cmluZ1xyXG4gICAqL1xyXG4gIF9wcm9jZXNzSGVhZGVyTGluZSAobGluZSkge1xyXG4gICAgaWYgKCFsaW5lKSB7XHJcbiAgICAgIHRoaXMuX3BhcnNlSGVhZGVycygpXHJcbiAgICAgIHRoaXMuYm9keXN0cnVjdHVyZSArPSB0aGlzLmhlYWRlci5qb2luKCdcXG4nKSArICdcXG5cXG4nXHJcbiAgICAgIHRoaXMuX3N0YXRlID0gJ0JPRFknXHJcbiAgICAgIHJldHVyblxyXG4gICAgfVxyXG5cclxuICAgIGlmIChsaW5lLm1hdGNoKC9eXFxzLykgJiYgdGhpcy5oZWFkZXIubGVuZ3RoKSB7XHJcbiAgICAgIHRoaXMuaGVhZGVyW3RoaXMuaGVhZGVyLmxlbmd0aCAtIDFdICs9ICdcXG4nICsgbGluZVxyXG4gICAgfSBlbHNlIHtcclxuICAgICAgdGhpcy5oZWFkZXIucHVzaChsaW5lKVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogSm9pbnMgZm9sZGVkIGhlYWRlciBsaW5lcyBhbmQgY2FsbHMgQ29udGVudC1UeXBlIGFuZCBUcmFuc2Zlci1FbmNvZGluZyBwcm9jZXNzb3JzXHJcbiAgICovXHJcbiAgX3BhcnNlSGVhZGVycyAoKSB7XHJcbiAgICBmb3IgKGxldCBoYXNCaW5hcnkgPSBmYWxzZSwgaSA9IDAsIGxlbiA9IHRoaXMuaGVhZGVyLmxlbmd0aDsgaSA8IGxlbjsgaSsrKSB7XHJcbiAgICAgIGxldCB2YWx1ZSA9IHRoaXMuaGVhZGVyW2ldLnNwbGl0KCc6JylcclxuICAgICAgY29uc3Qga2V5ID0gKHZhbHVlLnNoaWZ0KCkgfHwgJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpXHJcbiAgICAgIHZhbHVlID0gKHZhbHVlLmpvaW4oJzonKSB8fCAnJykucmVwbGFjZSgvXFxuL2csICcnKS50cmltKClcclxuXHJcbiAgICAgIGlmICh2YWx1ZS5tYXRjaCgvW1xcdTAwODAtXFx1RkZGRl0vKSkge1xyXG4gICAgICAgIGlmICghdGhpcy5jaGFyc2V0KSB7XHJcbiAgICAgICAgICBoYXNCaW5hcnkgPSB0cnVlXHJcbiAgICAgICAgfVxyXG4gICAgICAgIC8vIHVzZSBkZWZhdWx0IGNoYXJzZXQgYXQgZmlyc3QgYW5kIGlmIHRoZSBhY3R1YWwgY2hhcnNldCBpcyByZXNvbHZlZCwgdGhlIGNvbnZlcnNpb24gaXMgcmUtcnVuXHJcbiAgICAgICAgdmFsdWUgPSBkZWNvZGUoY29udmVydChzdHIyYXJyKHZhbHVlKSwgdGhpcy5jaGFyc2V0IHx8ICdpc28tODg1OS0xJykpXHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHRoaXMuaGVhZGVyc1trZXldID0gKHRoaXMuaGVhZGVyc1trZXldIHx8IFtdKS5jb25jYXQoW3RoaXMuX3BhcnNlSGVhZGVyVmFsdWUoa2V5LCB2YWx1ZSldKVxyXG5cclxuICAgICAgaWYgKCF0aGlzLmNoYXJzZXQgJiYga2V5ID09PSAnY29udGVudC10eXBlJykge1xyXG4gICAgICAgIHRoaXMuY2hhcnNldCA9IHRoaXMuaGVhZGVyc1trZXldW3RoaXMuaGVhZGVyc1trZXldLmxlbmd0aCAtIDFdLnBhcmFtcy5jaGFyc2V0XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmIChoYXNCaW5hcnkgJiYgdGhpcy5jaGFyc2V0KSB7XHJcbiAgICAgICAgLy8gcmVzZXQgdmFsdWVzIGFuZCBzdGFydCBvdmVyIG9uY2UgY2hhcnNldCBoYXMgYmVlbiByZXNvbHZlZCBhbmQgOGJpdCBjb250ZW50IGhhcyBiZWVuIGZvdW5kXHJcbiAgICAgICAgaGFzQmluYXJ5ID0gZmFsc2VcclxuICAgICAgICB0aGlzLmhlYWRlcnMgPSB7fVxyXG4gICAgICAgIGkgPSAtMSAvLyBuZXh0IGl0ZXJhdGlvbiBoYXMgaSA9PSAwXHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICB0aGlzLmZldGNoQ29udGVudFR5cGUoKVxyXG4gICAgdGhpcy5fcHJvY2Vzc0NvbnRlbnRUcmFuc2ZlckVuY29kaW5nKClcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFBhcnNlcyBzaW5nbGUgaGVhZGVyIHZhbHVlXHJcbiAgICogQHBhcmFtIHtTdHJpbmd9IGtleSBIZWFkZXIga2V5XHJcbiAgICogQHBhcmFtIHtTdHJpbmd9IHZhbHVlIFZhbHVlIGZvciB0aGUga2V5XHJcbiAgICogQHJldHVybiB7T2JqZWN0fSBwYXJzZWQgaGVhZGVyXHJcbiAgICovXHJcbiAgX3BhcnNlSGVhZGVyVmFsdWUgKGtleSwgdmFsdWUpIHtcclxuICAgIGxldCBwYXJzZWRWYWx1ZVxyXG4gICAgbGV0IGlzQWRkcmVzcyA9IGZhbHNlXHJcblxyXG4gICAgc3dpdGNoIChrZXkpIHtcclxuICAgICAgY2FzZSAnY29udGVudC10eXBlJzpcclxuICAgICAgY2FzZSAnY29udGVudC10cmFuc2Zlci1lbmNvZGluZyc6XHJcbiAgICAgIGNhc2UgJ2NvbnRlbnQtZGlzcG9zaXRpb24nOlxyXG4gICAgICBjYXNlICdka2ltLXNpZ25hdHVyZSc6XHJcbiAgICAgICAgcGFyc2VkVmFsdWUgPSBwYXJzZUhlYWRlclZhbHVlKHZhbHVlKVxyXG4gICAgICAgIGJyZWFrXHJcbiAgICAgIGNhc2UgJ2Zyb20nOlxyXG4gICAgICBjYXNlICdzZW5kZXInOlxyXG4gICAgICBjYXNlICd0byc6XHJcbiAgICAgIGNhc2UgJ3JlcGx5LXRvJzpcclxuICAgICAgY2FzZSAnY2MnOlxyXG4gICAgICBjYXNlICdiY2MnOlxyXG4gICAgICBjYXNlICdhYnVzZS1yZXBvcnRzLXRvJzpcclxuICAgICAgY2FzZSAnZXJyb3JzLXRvJzpcclxuICAgICAgY2FzZSAncmV0dXJuLXBhdGgnOlxyXG4gICAgICBjYXNlICdkZWxpdmVyZWQtdG8nOlxyXG4gICAgICAgIGlzQWRkcmVzcyA9IHRydWVcclxuICAgICAgICBwYXJzZWRWYWx1ZSA9IHtcclxuICAgICAgICAgIHZhbHVlOiBbXS5jb25jYXQocGFyc2VBZGRyZXNzKHZhbHVlKSB8fCBbXSlcclxuICAgICAgICB9XHJcbiAgICAgICAgYnJlYWtcclxuICAgICAgY2FzZSAnZGF0ZSc6XHJcbiAgICAgICAgcGFyc2VkVmFsdWUgPSB7XHJcbiAgICAgICAgICB2YWx1ZTogdGhpcy5fcGFyc2VEYXRlKHZhbHVlKVxyXG4gICAgICAgIH1cclxuICAgICAgICBicmVha1xyXG4gICAgICBkZWZhdWx0OlxyXG4gICAgICAgIHBhcnNlZFZhbHVlID0ge1xyXG4gICAgICAgICAgdmFsdWU6IHZhbHVlXHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG4gICAgcGFyc2VkVmFsdWUuaW5pdGlhbCA9IHZhbHVlXHJcblxyXG4gICAgdGhpcy5fZGVjb2RlSGVhZGVyQ2hhcnNldChwYXJzZWRWYWx1ZSwgeyBpc0FkZHJlc3MgfSlcclxuXHJcbiAgICByZXR1cm4gcGFyc2VkVmFsdWVcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIENoZWNrcyBpZiBhIGRhdGUgc3RyaW5nIGNhbiBiZSBwYXJzZWQuIEZhbGxzIGJhY2sgcmVwbGFjaW5nIHRpbWV6b25lXHJcbiAgICogYWJicmV2YXRpb25zIHdpdGggdGltZXpvbmUgdmFsdWVzLiBCb2d1cyB0aW1lem9uZXMgZGVmYXVsdCB0byBVVEMuXHJcbiAgICpcclxuICAgKiBAcGFyYW0ge1N0cmluZ30gc3RyIERhdGUgaGVhZGVyXHJcbiAgICogQHJldHVybnMge1N0cmluZ30gVVRDIGRhdGUgc3RyaW5nIGlmIHBhcnNpbmcgc3VjY2VlZGVkLCBvdGhlcndpc2UgcmV0dXJucyBpbnB1dCB2YWx1ZVxyXG4gICAqL1xyXG4gIF9wYXJzZURhdGUgKHN0ciA9ICcnKSB7XHJcbiAgICBjb25zdCBkYXRlID0gbmV3IERhdGUoc3RyLnRyaW0oKS5yZXBsYWNlKC9cXGJbYS16XSskL2ksIHR6ID0+IHRpbWV6b25lW3R6LnRvVXBwZXJDYXNlKCldIHx8ICcrMDAwMCcpKVxyXG4gICAgcmV0dXJuIChkYXRlLnRvU3RyaW5nKCkgIT09ICdJbnZhbGlkIERhdGUnKSA/IGRhdGUudG9VVENTdHJpbmcoKS5yZXBsYWNlKC9HTVQvLCAnKzAwMDAnKSA6IHN0clxyXG4gIH1cclxuXHJcbiAgX2RlY29kZUhlYWRlckNoYXJzZXQgKHBhcnNlZCwgeyBpc0FkZHJlc3MgfSA9IHt9KSB7XHJcbiAgICAvLyBkZWNvZGUgZGVmYXVsdCB2YWx1ZVxyXG4gICAgaWYgKHR5cGVvZiBwYXJzZWQudmFsdWUgPT09ICdzdHJpbmcnKSB7XHJcbiAgICAgIHBhcnNlZC52YWx1ZSA9IG1pbWVXb3Jkc0RlY29kZShwYXJzZWQudmFsdWUpXHJcbiAgICB9XHJcblxyXG4gICAgLy8gZGVjb2RlIHBvc3NpYmxlIHBhcmFtc1xyXG4gICAgT2JqZWN0LmtleXMocGFyc2VkLnBhcmFtcyB8fCB7fSkuZm9yRWFjaChmdW5jdGlvbiAoa2V5KSB7XHJcbiAgICAgIGlmICh0eXBlb2YgcGFyc2VkLnBhcmFtc1trZXldID09PSAnc3RyaW5nJykge1xyXG4gICAgICAgIHBhcnNlZC5wYXJhbXNba2V5XSA9IG1pbWVXb3Jkc0RlY29kZShwYXJzZWQucGFyYW1zW2tleV0pXHJcbiAgICAgIH1cclxuICAgIH0pXHJcblxyXG4gICAgLy8gZGVjb2RlIGFkZHJlc3Nlc1xyXG4gICAgaWYgKGlzQWRkcmVzcyAmJiBBcnJheS5pc0FycmF5KHBhcnNlZC52YWx1ZSkpIHtcclxuICAgICAgcGFyc2VkLnZhbHVlLmZvckVhY2goYWRkciA9PiB7XHJcbiAgICAgICAgaWYgKGFkZHIubmFtZSkge1xyXG4gICAgICAgICAgYWRkci5uYW1lID0gbWltZVdvcmRzRGVjb2RlKGFkZHIubmFtZSlcclxuICAgICAgICAgIGlmIChBcnJheS5pc0FycmF5KGFkZHIuZ3JvdXApKSB7XHJcbiAgICAgICAgICAgIHRoaXMuX2RlY29kZUhlYWRlckNoYXJzZXQoeyB2YWx1ZTogYWRkci5ncm91cCB9LCB7IGlzQWRkcmVzczogdHJ1ZSB9KVxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgICAgfSlcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gcGFyc2VkXHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBQYXJzZXMgQ29udGVudC1UeXBlIHZhbHVlIGFuZCBzZWxlY3RzIGZvbGxvd2luZyBhY3Rpb25zLlxyXG4gICAqL1xyXG4gIGZldGNoQ29udGVudFR5cGUgKCkge1xyXG4gICAgY29uc3QgZGVmYXVsdFZhbHVlID0gcGFyc2VIZWFkZXJWYWx1ZSgndGV4dC9wbGFpbicpXHJcbiAgICB0aGlzLmNvbnRlbnRUeXBlID0gcGF0aE9yKGRlZmF1bHRWYWx1ZSwgWydoZWFkZXJzJywgJ2NvbnRlbnQtdHlwZScsICcwJ10pKHRoaXMpXHJcbiAgICB0aGlzLmNvbnRlbnRUeXBlLnZhbHVlID0gKHRoaXMuY29udGVudFR5cGUudmFsdWUgfHwgJycpLnRvTG93ZXJDYXNlKCkudHJpbSgpXHJcbiAgICB0aGlzLmNvbnRlbnRUeXBlLnR5cGUgPSAodGhpcy5jb250ZW50VHlwZS52YWx1ZS5zcGxpdCgnLycpLnNoaWZ0KCkgfHwgJ3RleHQnKVxyXG5cclxuICAgIGlmICh0aGlzLmNvbnRlbnRUeXBlLnBhcmFtcyAmJiB0aGlzLmNvbnRlbnRUeXBlLnBhcmFtcy5jaGFyc2V0ICYmICF0aGlzLmNoYXJzZXQpIHtcclxuICAgICAgdGhpcy5jaGFyc2V0ID0gdGhpcy5jb250ZW50VHlwZS5wYXJhbXMuY2hhcnNldFxyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLmNvbnRlbnRUeXBlLnR5cGUgPT09ICdtdWx0aXBhcnQnICYmIHRoaXMuY29udGVudFR5cGUucGFyYW1zLmJvdW5kYXJ5KSB7XHJcbiAgICAgIHRoaXMuY2hpbGROb2RlcyA9IFtdXHJcbiAgICAgIHRoaXMuX2lzTXVsdGlwYXJ0ID0gKHRoaXMuY29udGVudFR5cGUudmFsdWUuc3BsaXQoJy8nKS5wb3AoKSB8fCAnbWl4ZWQnKVxyXG4gICAgICB0aGlzLl9tdWx0aXBhcnRCb3VuZGFyeSA9IHRoaXMuY29udGVudFR5cGUucGFyYW1zLmJvdW5kYXJ5XHJcbiAgICB9XHJcblxyXG4gICAgLyoqXHJcbiAgICAgKiBGb3IgYXR0YWNobWVudCAoaW5saW5lL3JlZ3VsYXIpIGlmIGNoYXJzZXQgaXMgbm90IGRlZmluZWQgYW5kIGF0dGFjaG1lbnQgaXMgbm9uLXRleHQvKixcclxuICAgICAqIHRoZW4gZGVmYXVsdCBjaGFyc2V0IHRvIGJpbmFyeS5cclxuICAgICAqIFJlZmVyIHRvIGlzc3VlOiBodHRwczovL2dpdGh1Yi5jb20vZW1haWxqcy9lbWFpbGpzLW1pbWUtcGFyc2VyL2lzc3Vlcy8xOFxyXG4gICAgICovXHJcbiAgICBjb25zdCBkZWZhdWx0Q29udGVudERpc3Bvc2l0aW9uVmFsdWUgPSBwYXJzZUhlYWRlclZhbHVlKCcnKVxyXG4gICAgY29uc3QgY29udGVudERpc3Bvc2l0aW9uID0gcGF0aE9yKGRlZmF1bHRDb250ZW50RGlzcG9zaXRpb25WYWx1ZSwgWydoZWFkZXJzJywgJ2NvbnRlbnQtZGlzcG9zaXRpb24nLCAnMCddKSh0aGlzKVxyXG4gICAgY29uc3QgaXNBdHRhY2htZW50ID0gKGNvbnRlbnREaXNwb3NpdGlvbi52YWx1ZSB8fCAnJykudG9Mb3dlckNhc2UoKS50cmltKCkgPT09ICdhdHRhY2htZW50J1xyXG4gICAgY29uc3QgaXNJbmxpbmVBdHRhY2htZW50ID0gKGNvbnRlbnREaXNwb3NpdGlvbi52YWx1ZSB8fCAnJykudG9Mb3dlckNhc2UoKS50cmltKCkgPT09ICdpbmxpbmUnXHJcbiAgICBpZiAoKGlzQXR0YWNobWVudCB8fCBpc0lubGluZUF0dGFjaG1lbnQpICYmIHRoaXMuY29udGVudFR5cGUudHlwZSAhPT0gJ3RleHQnICYmICF0aGlzLmNoYXJzZXQpIHtcclxuICAgICAgdGhpcy5jaGFyc2V0ID0gJ2JpbmFyeSdcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5jb250ZW50VHlwZS52YWx1ZSA9PT0gJ21lc3NhZ2UvcmZjODIyJyAmJiAhaXNBdHRhY2htZW50KSB7XHJcbiAgICAgIC8qKlxyXG4gICAgICAgKiBQYXJzZSBtZXNzYWdlL3JmYzgyMiBvbmx5IGlmIHRoZSBtaW1lIHBhcnQgaXMgbm90IG1hcmtlZCB3aXRoIGNvbnRlbnQtZGlzcG9zaXRpb246IGF0dGFjaG1lbnQsXHJcbiAgICAgICAqIG90aGVyd2lzZSB0cmVhdCBpdCBsaWtlIGEgcmVndWxhciBhdHRhY2htZW50XHJcbiAgICAgICAqL1xyXG4gICAgICB0aGlzLl9jdXJyZW50Q2hpbGQgPSBuZXcgTWltZU5vZGUodGhpcy5ub2RlQ291bnRlcilcclxuICAgICAgdGhpcy5jaGlsZE5vZGVzID0gW3RoaXMuX2N1cnJlbnRDaGlsZF1cclxuICAgICAgdGhpcy5faXNSZmM4MjIgPSB0cnVlXHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBQYXJzZXMgQ29udGVudC1UcmFuc2Zlci1FbmNvZGluZyB2YWx1ZSB0byBzZWUgaWYgdGhlIGJvZHkgbmVlZHMgdG8gYmUgY29udmVydGVkXHJcbiAgICogYmVmb3JlIGl0IGNhbiBiZSBlbWl0dGVkXHJcbiAgICovXHJcbiAgX3Byb2Nlc3NDb250ZW50VHJhbnNmZXJFbmNvZGluZyAoKSB7XHJcbiAgICBjb25zdCBkZWZhdWx0VmFsdWUgPSBwYXJzZUhlYWRlclZhbHVlKCc3Yml0JylcclxuICAgIHRoaXMuY29udGVudFRyYW5zZmVyRW5jb2RpbmcgPSBwYXRoT3IoZGVmYXVsdFZhbHVlLCBbJ2hlYWRlcnMnLCAnY29udGVudC10cmFuc2Zlci1lbmNvZGluZycsICcwJ10pKHRoaXMpXHJcbiAgICB0aGlzLmNvbnRlbnRUcmFuc2ZlckVuY29kaW5nLnZhbHVlID0gcGF0aE9yKCcnLCBbJ2NvbnRlbnRUcmFuc2ZlckVuY29kaW5nJywgJ3ZhbHVlJ10pKHRoaXMpLnRvTG93ZXJDYXNlKCkudHJpbSgpXHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBQcm9jZXNzZXMgYSBsaW5lIGluIHRoZSBCT0RZIHN0YXRlLiBJZiB0aGlzIGlzIGEgbXVsdGlwYXJ0IG9yIHJmYzgyMiBub2RlLFxyXG4gICAqIHBhc3NlcyBsaW5lIHZhbHVlIHRvIGNoaWxkIG5vZGVzLlxyXG4gICAqXHJcbiAgICogQHBhcmFtIHtTdHJpbmd9IGxpbmUgRW50aXJlIGlucHV0IGxpbmUgYXMgJ2JpbmFyeScgc3RyaW5nXHJcbiAgICovXHJcbiAgX3Byb2Nlc3NCb2R5TGluZSAobGluZSkge1xyXG4gICAgaWYgKHRoaXMuX2lzTXVsdGlwYXJ0KSB7XHJcbiAgICAgIGlmIChsaW5lID09PSAnLS0nICsgdGhpcy5fbXVsdGlwYXJ0Qm91bmRhcnkpIHtcclxuICAgICAgICB0aGlzLmJvZHlzdHJ1Y3R1cmUgKz0gbGluZSArICdcXG4nXHJcbiAgICAgICAgaWYgKHRoaXMuX2N1cnJlbnRDaGlsZCkge1xyXG4gICAgICAgICAgdGhpcy5fY3VycmVudENoaWxkLmZpbmFsaXplKClcclxuICAgICAgICB9XHJcbiAgICAgICAgdGhpcy5fY3VycmVudENoaWxkID0gbmV3IE1pbWVOb2RlKHRoaXMubm9kZUNvdW50ZXIpXHJcbiAgICAgICAgdGhpcy5jaGlsZE5vZGVzLnB1c2godGhpcy5fY3VycmVudENoaWxkKVxyXG4gICAgICB9IGVsc2UgaWYgKGxpbmUgPT09ICctLScgKyB0aGlzLl9tdWx0aXBhcnRCb3VuZGFyeSArICctLScpIHtcclxuICAgICAgICB0aGlzLmJvZHlzdHJ1Y3R1cmUgKz0gbGluZSArICdcXG4nXHJcbiAgICAgICAgaWYgKHRoaXMuX2N1cnJlbnRDaGlsZCkge1xyXG4gICAgICAgICAgdGhpcy5fY3VycmVudENoaWxkLmZpbmFsaXplKClcclxuICAgICAgICB9XHJcbiAgICAgICAgdGhpcy5fY3VycmVudENoaWxkID0gZmFsc2VcclxuICAgICAgfSBlbHNlIGlmICh0aGlzLl9jdXJyZW50Q2hpbGQpIHtcclxuICAgICAgICB0aGlzLl9jdXJyZW50Q2hpbGQud3JpdGVMaW5lKGxpbmUpXHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgLy8gSWdub3JlIG11bHRpcGFydCBwcmVhbWJsZVxyXG4gICAgICB9XHJcbiAgICB9IGVsc2UgaWYgKHRoaXMuX2lzUmZjODIyKSB7XHJcbiAgICAgIHRoaXMuX2N1cnJlbnRDaGlsZC53cml0ZUxpbmUobGluZSlcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHRoaXMuX2xpbmVDb3VudCsrXHJcblxyXG4gICAgICBzd2l0Y2ggKHRoaXMuY29udGVudFRyYW5zZmVyRW5jb2RpbmcudmFsdWUpIHtcclxuICAgICAgICBjYXNlICdiYXNlNjQnOlxyXG4gICAgICAgICAgdGhpcy5fYm9keUJ1ZmZlciArPSBsaW5lXHJcbiAgICAgICAgICBicmVha1xyXG4gICAgICAgIGNhc2UgJ3F1b3RlZC1wcmludGFibGUnOiB7XHJcbiAgICAgICAgICBsZXQgY3VyTGluZSA9IHRoaXMuX2xpbmVSZW1haW5kZXIgKyAodGhpcy5fbGluZUNvdW50ID4gMSA/ICdcXG4nIDogJycpICsgbGluZVxyXG4gICAgICAgICAgY29uc3QgbWF0Y2ggPSBjdXJMaW5lLm1hdGNoKC89W2EtZjAtOV17MCwxfSQvaSlcclxuICAgICAgICAgIGlmIChtYXRjaCkge1xyXG4gICAgICAgICAgICB0aGlzLl9saW5lUmVtYWluZGVyID0gbWF0Y2hbMF1cclxuICAgICAgICAgICAgY3VyTGluZSA9IGN1ckxpbmUuc3Vic3RyKDAsIGN1ckxpbmUubGVuZ3RoIC0gdGhpcy5fbGluZVJlbWFpbmRlci5sZW5ndGgpXHJcbiAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICB0aGlzLl9saW5lUmVtYWluZGVyID0gJydcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIHRoaXMuX2JvZHlCdWZmZXIgKz0gY3VyTGluZVxyXG4gICAgICAgICAgYnJlYWtcclxuICAgICAgICB9XHJcbiAgICAgICAgY2FzZSAnN2JpdCc6XHJcbiAgICAgICAgY2FzZSAnOGJpdCc6XHJcbiAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgIHRoaXMuX2JvZHlCdWZmZXIgKz0gKHRoaXMuX2xpbmVDb3VudCA+IDEgPyAnXFxuJyA6ICcnKSArIGxpbmVcclxuICAgICAgICAgIGJyZWFrXHJcbiAgICAgIH1cclxuICAgIH1cclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIEVtaXRzIGEgY2h1bmsgb2YgdGhlIGJvZHlcclxuICAqL1xyXG4gIF9lbWl0Qm9keSAoKSB7XHJcbiAgICB0aGlzLl9kZWNvZGVCb2R5QnVmZmVyKClcclxuICAgIGlmICh0aGlzLl9pc011bHRpcGFydCB8fCAhdGhpcy5fYm9keUJ1ZmZlcikge1xyXG4gICAgICByZXR1cm5cclxuICAgIH1cclxuXHJcbiAgICB0aGlzLl9wcm9jZXNzRmxvd2VkVGV4dCgpXHJcbiAgICB0aGlzLmNvbnRlbnQgPSBzdHIyYXJyKHRoaXMuX2JvZHlCdWZmZXIpXHJcbiAgICB0aGlzLl9wcm9jZXNzSHRtbFRleHQoKVxyXG4gICAgdGhpcy5fYm9keUJ1ZmZlciA9ICcnXHJcbiAgfVxyXG5cclxuICBfcHJvY2Vzc0Zsb3dlZFRleHQgKCkge1xyXG4gICAgY29uc3QgaXNUZXh0ID0gL150ZXh0XFwvKHBsYWlufGh0bWwpJC9pLnRlc3QodGhpcy5jb250ZW50VHlwZS52YWx1ZSlcclxuICAgIGNvbnN0IGlzRmxvd2VkID0gL15mbG93ZWQkL2kudGVzdChwYXRoT3IoJycsIFsnY29udGVudFR5cGUnLCAncGFyYW1zJywgJ2Zvcm1hdCddKSh0aGlzKSlcclxuICAgIGlmICghaXNUZXh0IHx8ICFpc0Zsb3dlZCkgcmV0dXJuXHJcblxyXG4gICAgY29uc3QgZGVsU3AgPSAvXnllcyQvaS50ZXN0KHRoaXMuY29udGVudFR5cGUucGFyYW1zLmRlbHNwKVxyXG4gICAgdGhpcy5fYm9keUJ1ZmZlciA9IHRoaXMuX2JvZHlCdWZmZXIuc3BsaXQoJ1xcbicpXHJcbiAgICAgIC5yZWR1Y2UoZnVuY3Rpb24gKHByZXZpb3VzVmFsdWUsIGN1cnJlbnRWYWx1ZSkge1xyXG4gICAgICAgIC8vIHJlbW92ZSBzb2Z0IGxpbmVicmVha3MgYWZ0ZXIgc3BhY2Ugc3ltYm9scy5cclxuICAgICAgICAvLyBkZWxzcCBhZGRzIHNwYWNlcyB0byB0ZXh0IHRvIGJlIGFibGUgdG8gZm9sZCBpdC5cclxuICAgICAgICAvLyB0aGVzZSBzcGFjZXMgY2FuIGJlIHJlbW92ZWQgb25jZSB0aGUgdGV4dCBpcyB1bmZvbGRlZFxyXG4gICAgICAgIGNvbnN0IGVuZHNXaXRoU3BhY2UgPSAvICQvLnRlc3QocHJldmlvdXNWYWx1ZSlcclxuICAgICAgICBjb25zdCBpc0JvdW5kYXJ5ID0gLyhefFxcbiktLSAkLy50ZXN0KHByZXZpb3VzVmFsdWUpXHJcbiAgICAgICAgcmV0dXJuIChkZWxTcCA/IHByZXZpb3VzVmFsdWUucmVwbGFjZSgvWyBdKyQvLCAnJykgOiBwcmV2aW91c1ZhbHVlKSArICgoZW5kc1dpdGhTcGFjZSAmJiAhaXNCb3VuZGFyeSkgPyAnJyA6ICdcXG4nKSArIGN1cnJlbnRWYWx1ZVxyXG4gICAgICB9KVxyXG4gICAgICAucmVwbGFjZSgvXiAvZ20sICcnKSAvLyByZW1vdmUgd2hpdGVzcGFjZSBzdHVmZmluZyBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmMzNjc2I3NlY3Rpb24tNC40XHJcbiAgfVxyXG5cclxuICBfcHJvY2Vzc0h0bWxUZXh0ICgpIHtcclxuICAgIGNvbnN0IGNvbnRlbnREaXNwb3NpdGlvbiA9ICh0aGlzLmhlYWRlcnNbJ2NvbnRlbnQtZGlzcG9zaXRpb24nXSAmJiB0aGlzLmhlYWRlcnNbJ2NvbnRlbnQtZGlzcG9zaXRpb24nXVswXSkgfHwgcGFyc2VIZWFkZXJWYWx1ZSgnJylcclxuICAgIGNvbnN0IGlzSHRtbCA9IC9edGV4dFxcLyhwbGFpbnxodG1sKSQvaS50ZXN0KHRoaXMuY29udGVudFR5cGUudmFsdWUpXHJcbiAgICBjb25zdCBpc0F0dGFjaG1lbnQgPSAvXmF0dGFjaG1lbnQkL2kudGVzdChjb250ZW50RGlzcG9zaXRpb24udmFsdWUpXHJcbiAgICBpZiAoaXNIdG1sICYmICFpc0F0dGFjaG1lbnQpIHtcclxuICAgICAgaWYgKCF0aGlzLmNoYXJzZXQgJiYgL150ZXh0XFwvaHRtbCQvaS50ZXN0KHRoaXMuY29udGVudFR5cGUudmFsdWUpKSB7XHJcbiAgICAgICAgdGhpcy5jaGFyc2V0ID0gdGhpcy5kZXRlY3RIVE1MQ2hhcnNldCh0aGlzLl9ib2R5QnVmZmVyKVxyXG4gICAgICB9XHJcblxyXG4gICAgICAvLyBkZWNvZGUgXCJiaW5hcnlcIiBzdHJpbmcgdG8gYW4gdW5pY29kZSBzdHJpbmdcclxuICAgICAgaWYgKCEvXnV0ZlstX10/OCQvaS50ZXN0KHRoaXMuY2hhcnNldCkpIHtcclxuICAgICAgICB0aGlzLmNvbnRlbnQgPSBjb252ZXJ0KHN0cjJhcnIodGhpcy5fYm9keUJ1ZmZlciksIHRoaXMuY2hhcnNldCB8fCAnaXNvLTg4NTktMScpXHJcbiAgICAgIH0gZWxzZSBpZiAodGhpcy5jb250ZW50VHJhbnNmZXJFbmNvZGluZy52YWx1ZSA9PT0gJ2Jhc2U2NCcpIHtcclxuICAgICAgICB0aGlzLmNvbnRlbnQgPSB1dGY4U3RyMmFycih0aGlzLl9ib2R5QnVmZmVyKVxyXG4gICAgICB9XHJcblxyXG4gICAgICAvLyBvdmVycmlkZSBjaGFyc2V0IGZvciB0ZXh0IG5vZGVzXHJcbiAgICAgIHRoaXMuY2hhcnNldCA9IHRoaXMuY29udGVudFR5cGUucGFyYW1zLmNoYXJzZXQgPSAndXRmLTgnXHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBEZXRlY3QgY2hhcnNldCBmcm9tIGEgaHRtbCBmaWxlXHJcbiAgICpcclxuICAgKiBAcGFyYW0ge1N0cmluZ30gaHRtbCBJbnB1dCBIVE1MXHJcbiAgICogQHJldHVybnMge1N0cmluZ30gQ2hhcnNldCBpZiBmb3VuZCBvciB1bmRlZmluZWRcclxuICAgKi9cclxuICBkZXRlY3RIVE1MQ2hhcnNldCAoaHRtbCkge1xyXG4gICAgbGV0IGNoYXJzZXQsIGlucHV0XHJcblxyXG4gICAgaHRtbCA9IGh0bWwucmVwbGFjZSgvXFxyP1xcbnxcXHIvZywgJyAnKVxyXG4gICAgbGV0IG1ldGEgPSBodG1sLm1hdGNoKC88bWV0YVxccytodHRwLWVxdWl2PVtcIidcXHNdKmNvbnRlbnQtdHlwZVtePl0qPz4vaSlcclxuICAgIGlmIChtZXRhKSB7XHJcbiAgICAgIGlucHV0ID0gbWV0YVswXVxyXG4gICAgfVxyXG5cclxuICAgIGlmIChpbnB1dCkge1xyXG4gICAgICBjaGFyc2V0ID0gaW5wdXQubWF0Y2goL2NoYXJzZXRcXHM/PVxccz8oW2EtekEtWlxcLV86MC05XSopOz8vKVxyXG4gICAgICBpZiAoY2hhcnNldCkge1xyXG4gICAgICAgIGNoYXJzZXQgPSAoY2hhcnNldFsxXSB8fCAnJykudHJpbSgpLnRvTG93ZXJDYXNlKClcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIG1ldGEgPSBodG1sLm1hdGNoKC88bWV0YVxccytjaGFyc2V0PVtcIidcXHNdKihbXlwiJzw+L1xcc10rKS9pKVxyXG4gICAgaWYgKCFjaGFyc2V0ICYmIG1ldGEpIHtcclxuICAgICAgY2hhcnNldCA9IChtZXRhWzFdIHx8ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKVxyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBjaGFyc2V0XHJcbiAgfVxyXG59XHJcblxyXG5jb25zdCBzdHIyYXJyID0gc3RyID0+IG5ldyBVaW50OEFycmF5KHN0ci5zcGxpdCgnJykubWFwKGNoYXIgPT4gY2hhci5jaGFyQ29kZUF0KDApKSlcclxuY29uc3QgdXRmOFN0cjJhcnIgPSBzdHIgPT4gbmV3IFRleHRFbmNvZGVyKCd1dGYtOCcpLmVuY29kZShzdHIpXHJcbiJdfQ==