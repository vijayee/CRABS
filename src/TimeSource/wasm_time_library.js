// wasm_time_library.js — emscripten JS library providing the host-side
// HTTPS time fetch for the WASM build.
//
// The C transport seam (_wasm_fetch_server_time) is synchronous, so this
// glue must block until the fetch completes:
//   - Browser: synchronous XMLHttpRequest (async: false).
//   - Node:    child_process.execFileSync running a small https fetch script.
//
// Returns Unix seconds as a double, or a negative value on failure. The
// response body is parsed for the Cloudflare trace format ("ts=...") and the
// worldtimeapi JSON format ("\"unixtime\":...").
mergeInto(LibraryManager.library, {
  js_fetch_server_time: function (urlPtr, timeoutMs) {
    var url = UTF8ToString(urlPtr);
    // R7-05: reject non-https URLs. The native transport enforces https:// in
    // _parse_url; the JS glue must too, or an http:// config becomes a
    // cleartext timestamp-forgery channel.
    if (url.indexOf('https://') !== 0) return -1.0;
    // The C signature uses uint64_t, so emscripten passes timeoutMs as a
    // BigInt. Convert to a Number (timeouts are small) before bitwise use.
    var timeout = Number(timeoutMs) >>> 0;
    var body = null;

    if (typeof XMLHttpRequest !== 'undefined') {
      // Browser: synchronous request so the C caller blocks until done.
      // Note: the XHR spec does not apply `timeout` to synchronous requests,
      // and setting it in a Window context throws InvalidAccessError. The
      // browser path therefore cannot bound sync XHR; timeout_ms is only
      // honored on the Node path below.
      var xhr = new XMLHttpRequest();
      xhr.open('GET', url, false);
      try {
        xhr.send(null);
        if (xhr.status >= 200 && xhr.status < 300) {
          body = xhr.responseText;
        }
      } catch (err) {
        body = null;
      }
    } else if (typeof require !== 'undefined') {
      // Node: run a synchronous child process that performs the HTTPS fetch.
      // execFileSync with an args array avoids shell quoting of the script.
      var script = [
        'var https = require("https");',
        'var url = process.argv[1];',
        'var timeout = parseInt(process.argv[2], 10);',
        'var req = https.get(url, { timeout: timeout }, function (res) {',
        '  var data = "";',
        '  res.on("data", function (chunk) { data += chunk; });',
        '  res.on("end", function () { process.stdout.write(data); });',
        '});',
        'req.on("error", function () { process.exit(1); });',
        'req.setTimeout(timeout, function () { req.destroy(); });'
      ].join('\n');
      try {
        var child = require('child_process');
        body = child.execFileSync(process.execPath,
            ['-e', script, url, String(timeout)], {
          timeout: timeout,
          stdio: ['ignore', 'pipe', 'ignore']
        }).toString();
      } catch (err) {
        body = null;
      }
    }

    if (body === null) return -1.0;

    // R7-16: anchor "ts=" to a line start and bound the digit count so a huge
    // digit string cannot become a double >= 2^53 (precision loss) or >= 2^64
    // (undefined behavior when cast to uint64_t on the C side).
    var match = body.match(/^ts=(\d{1,19})(?:\.(\d{1,9}))?/m);
    if (match) {
      var seconds = parseFloat(match[1]);
      if (seconds > 9007199254740991) return -1.0;  // > Number.MAX_SAFE_INTEGER
      var frac = match[2] ? parseFloat('0.' + match[2]) : 0.0;
      return seconds + frac;
    }
    var unixtime = body.match(/"unixtime":\s*(\d{1,19})/);
    if (unixtime) {
      var ut = parseFloat(unixtime[1]);
      if (ut > 9007199254740991) return -1.0;
      return ut;
    }
    return -1.0;
  }
});
