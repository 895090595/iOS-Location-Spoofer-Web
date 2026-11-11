/**
 * WLOC 现场取证探针 (wloc-probe.js)
 *
 * 用途：不改动任何改写逻辑，只把 /clls/wloc 响应的真实特征打印到 Shadowrocket 日志，
 * 用于判断失效发生在「脚本未执行 / 响应被压缩 / 封装格式变更 / 字段结构变更」哪一层。
 * 判定结果以 VERDICT: 开头单独一行输出，便于直接回传。
 *
 * 作者：zj
 * 日期：2026-11-11 12:40
 *
 * 参数：
 *   dumpBase64=true   额外输出完整响应体 base64（分段），用于离线复现
 *   hexLimit=64       头部 hex 字节数，默认 64
 */
(function () {
    "use strict";

    var GZIP_MAGIC = [0x1f, 0x8b];
    var ZSTD_MAGIC = [0x28, 0xb5, 0x2f, 0xfd];
    var SYNTHETIC_PREFIX = [0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
    var MARKER = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
    var CELL_FIELDS = { 22: true, 24: true };

    function log(tag, msg) {
        console.log("[WLOC-PROBE][" + tag + "] " + msg);
    }

    // 检查运行时是否提供某个解压函数（旧脚本 decompressBody 依赖这里的结果）
    function hasUtil(name) {
        if (typeof $utils === "undefined" || !$utils) {
            return false;
        }
        try {
            return typeof $utils[name] === "function";
        } catch (e) {
            return false;
        }
    }

    function parseArgs(input) {
        var out = {};
        if (!input || typeof input !== "string") {
            return out;
        }
        var pairs = input.split(/[&;]/);
        for (var i = 0; i < pairs.length; i += 1) {
            var part = pairs[i];
            if (!part) {
                continue;
            }
            var eq = part.indexOf("=");
            var key = eq >= 0 ? part.slice(0, eq) : part;
            var value = eq >= 0 ? part.slice(eq + 1) : "true";
            try {
                out[decodeURIComponent(key)] = decodeURIComponent(value);
            } catch (e) {
                out[key] = value;
            }
        }
        return out;
    }

    // 统一把各种 body 形态（二进制字符串 / ArrayBuffer / 数组）转成 Uint8Array
    function toBytes(body) {
        if (body == null) {
            return null;
        }
        var i;
        if (typeof body === "string") {
            var fromStr = new Uint8Array(body.length);
            for (i = 0; i < body.length; i += 1) {
                fromStr[i] = body.charCodeAt(i) & 0xff;
            }
            return fromStr;
        }
        if (typeof ArrayBuffer !== "undefined" && body instanceof ArrayBuffer) {
            return new Uint8Array(body);
        }
        if (body && typeof body.length === "number") {
            var fromArr = new Uint8Array(body.length);
            for (i = 0; i < body.length; i += 1) {
                fromArr[i] = body[i] & 0xff;
            }
            return fromArr;
        }
        if (body && typeof body.byteLength === "number") {
            return new Uint8Array(body);
        }
        return null;
    }

    function bodyKind(body) {
        if (body == null) {
            return "null";
        }
        if (typeof body === "string") {
            return "string/" + body.length;
        }
        if (typeof ArrayBuffer !== "undefined" && body instanceof ArrayBuffer) {
            return "ArrayBuffer/" + body.byteLength;
        }
        if (body && typeof body.length === "number") {
            return "array-like/" + body.length;
        }
        if (body && typeof body.byteLength === "number") {
            return "buffer/" + body.byteLength;
        }
        return typeof body;
    }

    function hexOf(bytes, limit) {
        if (!bytes) {
            return "<none>";
        }
        var n = Math.min(limit || 64, bytes.length);
        var parts = [];
        for (var i = 0; i < n; i += 1) {
            var h = bytes[i].toString(16);
            parts.push(h.length < 2 ? "0" + h : h);
        }
        return parts.join(" ");
    }

    function startsWith(bytes, magic) {
        if (!bytes || bytes.length < magic.length) {
            return false;
        }
        for (var i = 0; i < magic.length; i += 1) {
            if (bytes[i] !== magic[i]) {
                return false;
            }
        }
        return true;
    }

    function findSequence(bytes, seq) {
        if (!bytes || bytes.length < seq.length) {
            return -1;
        }
        for (var i = 0; i <= bytes.length - seq.length; i += 1) {
            var ok = true;
            for (var j = 0; j < seq.length; j += 1) {
                if (bytes[i + j] !== seq[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                return i;
            }
        }
        return -1;
    }

    function sniffEncoding(bytes, contentEncoding) {
        if (!bytes || bytes.length === 0) {
            return "empty";
        }
        if (startsWith(bytes, GZIP_MAGIC)) {
            return "gzip-magic";
        }
        if (startsWith(bytes, ZSTD_MAGIC)) {
            return "zstd-magic";
        }
        if (bytes[0] === 0x78 && (bytes[1] === 0x01 || bytes[1] === 0x9c || bytes[1] === 0xda)) {
            return "zlib-magic";
        }
        if (contentEncoding) {
            return "claims-" + contentEncoding + "-but-no-known-magic";
        }
        return "plain";
    }

    function readVarint(bytes, offset) {
        var value = 0;
        var shift = 0;
        var pos = offset;
        var count = 0;
        while (pos < bytes.length && count < 10) {
            var b = bytes[pos];
            value += (b & 0x7f) * Math.pow(2, shift);
            shift += 7;
            pos += 1;
            count += 1;
            if ((b & 0x80) === 0) {
                return { ok: true, value: value, offset: pos };
            }
        }
        return { ok: false, reason: "varint truncated at " + offset };
    }

    // 按 protobuf 逐字段走位，失败时返回已解析部分与出错原因
    function walkFields(bytes, limit) {
        var fields = [];
        var offset = 0;
        var max = typeof limit === "number" ? Math.min(limit, bytes.length) : bytes.length;
        while (offset < max) {
            var key = readVarint(bytes, offset);
            if (!key.ok) {
                return { ok: offset === 0, fields: fields, at: offset, reason: key.reason };
            }
            var fieldNumber = Math.floor(key.value / 8);
            var wireType = key.value % 8;
            offset = key.offset;
            if (fieldNumber === 0) {
                return { ok: false, fields: fields, at: offset, reason: "field number 0 at " + offset };
            }
            var valueLen = 0;
            if (wireType === 0) {
                var v = readVarint(bytes, offset);
                if (!v.ok) {
                    return { ok: false, fields: fields, at: offset, reason: v.reason };
                }
                valueLen = v.offset - offset;
                offset = v.offset;
            } else if (wireType === 2) {
                var l = readVarint(bytes, offset);
                if (!l.ok) {
                    return { ok: false, fields: fields, at: offset, reason: l.reason };
                }
                valueLen = l.value;
                offset = l.offset;
                if (offset + valueLen > bytes.length) {
                    return {
                        ok: false,
                        fields: fields,
                        at: offset,
                        reason: "len " + valueLen + " exceeds buffer at " + offset
                    };
                }
                fields.push({ n: fieldNumber, w: wireType, start: offset, len: valueLen });
                offset += valueLen;
                continue;
            } else if (wireType === 5) {
                offset += 4;
            } else if (wireType === 1) {
                offset += 8;
            } else {
                return { ok: false, fields: fields, at: offset, reason: "wire type " + wireType + " at " + offset };
            }
            if (offset > bytes.length) {
                return { ok: false, fields: fields, at: offset, reason: "value overruns buffer at " + offset };
            }
            if (wireType === 0) {
                fields.push({ n: fieldNumber, w: wireType, start: key.offset, len: valueLen });
            }
        }
        return { ok: true, fields: fields, at: offset, reason: "" };
    }

    function histogram(fields) {
        var map = {};
        for (var i = 0; i < fields.length; i += 1) {
            var key = fields[i].n + "/w" + fields[i].w;
            map[key] = (map[key] || 0) + 1;
        }
        var keys = Object.keys(map).sort();
        var out = [];
        for (var j = 0; j < keys.length; j += 1) {
            out.push(keys[j] + "x" + map[keys[j]]);
        }
        return out.join(", ");
    }

    function trySynthetic(bytes) {
        if (bytes.length < 10 || !startsWith(bytes, SYNTHETIC_PREFIX)) {
            return null;
        }
        var payloadLen = (bytes[8] << 8) | bytes[9];
        if (payloadLen <= 0 || 10 + payloadLen > bytes.length) {
            return { kind: "synthetic", ok: false, reason: "declared len " + payloadLen + " but body " + bytes.length };
        }
        return { kind: "synthetic", ok: true, payload: bytes.subarray(10, 10 + payloadLen), head: 10 };
    }

    function tryArpc(bytes) {
        var offset = 4;
        var strings = ["locale", "appIdentifier", "osVersion"];
        for (var i = 0; i < strings.length; i += 1) {
            if (offset + 2 > bytes.length) {
                return { kind: "arpc", ok: false, reason: "truncated before " + strings[i] };
            }
            var len = (bytes[offset] << 8) | bytes[offset + 1];
            offset += 2;
            if (offset + len > bytes.length) {
                return { kind: "arpc", ok: false, reason: strings[i] + " len " + len + " overruns" };
            }
            offset += len;
        }
        if (offset + 12 > bytes.length) {
            return { kind: "arpc", ok: false, reason: "truncated header at " + offset };
        }
        var version = ((bytes[offset] << 24) | (bytes[offset + 1] << 16) |
            (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
        var functionId = ((bytes[offset + 4] << 24) | (bytes[offset + 5] << 16) |
            (bytes[offset + 6] << 8) | bytes[offset + 7]) >>> 0;
        var payloadLen = ((bytes[offset + 8] << 24) | (bytes[offset + 9] << 16) |
            (bytes[offset + 10] << 8) | bytes[offset + 11]) >>> 0;
        offset += 12;
        if (payloadLen <= 0 || offset + payloadLen > bytes.length) {
            return {
                kind: "arpc",
                ok: false,
                reason: "version=" + version + " fn=" + functionId + " len=" + payloadLen + " body=" + bytes.length
            };
        }
        return {
            kind: "arpc",
            ok: true,
            payload: bytes.subarray(offset, offset + payloadLen),
            head: offset,
            meta: "version=" + version + " functionId=" + functionId + " payloadLen=" + payloadLen
        };
    }

    function tryMarker(bytes) {
        var idx = findSequence(bytes, MARKER);
        if (idx < 0) {
            return null;
        }
        var lenOffset = idx + MARKER.length;
        if (lenOffset + 2 > bytes.length) {
            return { kind: "marker", ok: false, reason: "marker at " + idx + " but no length field" };
        }
        var payloadLen = (bytes[lenOffset] << 8) | bytes[lenOffset + 1];
        var head = lenOffset + 2;
        if (payloadLen <= 0 || head + payloadLen > bytes.length) {
            return { kind: "marker", ok: false, reason: "marker at " + idx + " len " + payloadLen + " overruns" };
        }
        return { kind: "marker", ok: true, payload: bytes.subarray(head, head + payloadLen), head: head, markerAt: idx };
    }

    // 取出指定实体里携带坐标的子消息（wifi 在 field 2，基站在 field 5），并列出其字段表
    function locationFields(entityBytes, locationField) {
        var walk = walkFields(entityBytes);
        for (var i = 0; i < walk.fields.length; i += 1) {
            if (walk.fields[i].n === locationField && walk.fields[i].w === 2) {
                var inner = entityBytes.subarray(walk.fields[i].start, walk.fields[i].start + walk.fields[i].len);
                return histogram(walkFields(inner).fields);
            }
        }
        return "<no location submessage>";
    }

    // 统计根级字段里的 wifi(field 2) 与基站(22/24) 实体数量，并给出首个实体的字段表
    function summarizeWloc(payload) {
        var walk = walkFields(payload);
        if (!walk.ok) {
            return { ok: false, reason: walk.reason, fields: walk.fields };
        }
        var wifi = 0;
        var cell = 0;
        var sample = "";
        for (var i = 0; i < walk.fields.length; i += 1) {
            var f = walk.fields[i];
            if (f.n === 2 && f.w === 2) {
                wifi += 1;
                if (!sample) {
                    var wifiBytes = payload.subarray(f.start, f.start + f.len);
                    sample = "wifi[entity:" + histogram(walkFields(wifiBytes).fields) +
                        " loc:" + locationFields(wifiBytes, 2) + "]";
                }
            } else if (CELL_FIELDS[f.n] && f.w === 2) {
                cell += 1;
                if (!sample || sample.indexOf("cell[") < 0) {
                    var cellBytes = payload.subarray(f.start, f.start + f.len);
                    sample += (sample ? " | " : "") + "cell" + f.n + "[entity:" +
                        histogram(walkFields(cellBytes).fields) + " loc:" + locationFields(cellBytes, 5) + "]";
                }
            }
        }
        return { ok: true, wifi: wifi, cell: cell, root: histogram(walk.fields), sample: sample };
    }

    function base64Of(bytes) {
        var table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var out = [];
        var i;
        for (i = 0; i + 2 < bytes.length; i += 3) {
            var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
            out.push(table[(n >> 18) & 63] + table[(n >> 12) & 63] + table[(n >> 6) & 63] + table[n & 63]);
        }
        var rest = bytes.length - i;
        if (rest === 1) {
            var a = bytes[i] << 16;
            out.push(table[(a >> 18) & 63] + table[(a >> 12) & 63] + "==");
        } else if (rest === 2) {
            var b = (bytes[i] << 16) | (bytes[i + 1] << 8);
            out.push(table[(b >> 18) & 63] + table[(b >> 12) & 63] + table[(b >> 6) & 63] + "=");
        }
        return out.join("");
    }

    function dumpBase64(bytes) {
        var b64 = base64Of(bytes);
        var step = 400;
        var total = Math.ceil(b64.length / step);
        log("B64", "len=" + bytes.length + " chunks=" + total);
        for (var i = 0; i < total; i += 1) {
            log("B64", "[" + (i + 1) + "/" + total + "] " + b64.slice(i * step, (i + 1) * step));
        }
    }

    function main() {
        var args = typeof $argument === "string" ? parseArgs($argument) : {};
        var hexLimit = args.hexLimit ? parseInt(args.hexLimit, 10) : 64;
        var hasResponse = typeof $response !== "undefined" && $response != null;
        var hasRequest = typeof $request !== "undefined" && $request != null;

        log("BANNER", "script alive, response=" + hasResponse + " request=" + hasRequest +
            " argument=" + (typeof $argument === "string" ? $argument : "<none>"));

        var utilsKeys = "<undefined>";
        if (typeof $utils !== "undefined" && $utils) {
            try {
                utilsKeys = Object.keys($utils).join(",") || "<empty>";
            } catch (e) {
                utilsKeys = "<unreadable>";
            }
        }
        log("ENV", "$utils=" + (typeof $utils) + " methods=" + utilsKeys +
            " ungzip=" + hasUtil("ungzip") + " inflate=" + hasUtil("inflate") +
            " brotli=" + hasUtil("brotliDecompress"));

        if (!hasResponse) {
            log("VERDICT", "NO-RESPONSE 脚本被执行但没有 $response，说明命中的是请求阶段（检查模块 type 是否为 http-response）");
            $done({});
            return;
        }

        var headers = $response.headers || {};
        var headerKeys = [];
        for (var k in headers) {
            if (Object.prototype.hasOwnProperty.call(headers, k)) {
                headerKeys.push(k + "=" + headers[k]);
            }
        }
        log("HEADERS", headerKeys.join(" | ") || "<none>");
        log("STATUS", "status=" + ($response.status || $response.statusCode || "<none>") +
            " url=" + (typeof $request !== "undefined" && $request && $request.url ? $request.url : "<none>"));

        var body = $response.body != null ? $response.body : $response.bodyBytes;
        log("BODY", "slot=" + ($response.body != null ? "body" : "bodyBytes") + " kind=" + bodyKind(body));

        var bytes = toBytes(body);
        if (!bytes || bytes.length < 2) {
            log("VERDICT", "EMPTY-BODY 响应体为空或未注入，检查模块 requires-body=1 与 binary-body-mode=1 是否仍生效");
            $done({});
            return;
        }

        var contentEncoding = "";
        for (var hk in headers) {
            if (Object.prototype.hasOwnProperty.call(headers, hk) && hk.toLowerCase() === "content-encoding") {
                contentEncoding = String(headers[hk]);
            }
        }
        var sniff = sniffEncoding(bytes, contentEncoding);
        log("ENCODING", "content-encoding=" + (contentEncoding || "none") + " sniff=" + sniff);
        log("HEX", "len=" + bytes.length + " head=" + hexOf(bytes, hexLimit));

        var compressed = sniff === "gzip-magic" || sniff === "zstd-magic" || sniff === "zlib-magic";
        if (compressed) {
            log("COMPRESSION", "响应体仍是 " + sniff + " 压缩流（content-encoding=" + (contentEncoding || "none") +
                "），可用解压函数：ungzip=" + hasUtil("ungzip") + " inflate=" + hasUtil("inflate") +
                " brotli=" + hasUtil("brotliDecompress"));
        }

        var synthetic = trySynthetic(bytes);
        var arpc = synthetic ? null : tryArpc(bytes);
        var marker = synthetic || (arpc && arpc.ok) ? null : tryMarker(bytes);
        var direct = walkFields(bytes);

        log("TRY-SYNTHETIC", synthetic ? (synthetic.ok ? "HIT payload=" + synthetic.payload.length : "MISS " + synthetic.reason) : "MISS no 0001....0000 prefix");
        log("TRY-ARPC", arpc ? (arpc.ok ? "HIT " + arpc.meta : "MISS " + arpc.reason) : "SKIPPED");
        log("TRY-MARKER", marker ? (marker.ok ? "HIT at " + marker.markerAt + " payload=" + marker.payload.length : "MISS " + marker.reason) : "MISS marker not found");
        log("TRY-BARE", "head fields=[" + histogram(direct.fields) + "] " + (direct.ok ? "parse=clean" : "parse=broken@" + direct.at + " " + direct.reason));

        var hit = null;
        if (synthetic && synthetic.ok) {
            hit = synthetic;
        } else if (arpc && arpc.ok) {
            hit = arpc;
        } else if (marker && marker.ok) {
            hit = marker;
        } else if (direct.ok && direct.fields.length > 0) {
            hit = { kind: "bare", payload: bytes, head: 0 };
        }

        if (hit) {
            var summary = summarizeWloc(hit.payload);
            if (summary.ok) {
                log("WLOC", "kind=" + hit.kind + " payload=" + hit.payload.length + " wifi=" + summary.wifi +
                    " cell=" + summary.cell + " root=[" + summary.root + "]");
                if (summary.sample) {
                    log("WLOC-SAMPLE", summary.sample);
                }
            } else {
                log("WLOC", "kind=" + hit.kind + " payload=" + hit.payload.length + " 解析失败: " + summary.reason);
            }
            if (hit.kind !== "bare") {
                var tail = bytes.length - (hit.head + hit.payload.length);
                log("TAIL", "payload 之后还有 " + tail + " 字节，尾部 hex=" +
                    hexOf(bytes.subarray(hit.head + hit.payload.length), 16));
            }
        }

        // 结论只输出一行，按优先级取最上游的失败点
        if (compressed) {
            log("VERDICT", "COMPRESSED 响应体是 " + sniff + " 压缩流；旧脚本拿不到可用的解压函数时必然解析失败并放行");
        } else if (hit) {
            log("VERDICT", "ENVELOPE-" + hit.kind.toUpperCase() + " 封装可识别；若定位仍不生效，看 WLOC-SAMPLE 与 root 是否出现未知字段，或响应被改成了非法结构");
        } else {
            log("VERDICT", "ENVELOPE-UNKNOWN 四种已知封装全部不匹配，Apple 改了响应结构，需按 HEX 头新增分支");
        }

        if (args.dumpBase64 === "true" || args.dumpBase64 === true) {
            dumpBase64(bytes);
        }

        $done({});
    }

    try {
        main();
    } catch (err) {
        log("FATAL", "探针自身异常: " + (err && err.message ? err.message : String(err)));
        $done({});
    }
}());
