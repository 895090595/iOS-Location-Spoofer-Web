/**
 * Apple 请求 URL 记录器 (url-logger.js)
 *
 * 用途：把所有命中 MITM 的 Apple 请求的 method / 完整 URL / 关键 header 打印出来，
 * 用于确认 WLOC 定位请求当前的真实入口（是否已从 gs-loc.apple.com 迁到别的域名）。
 * 只读不写，透传请求，不拉 body，对现有链路无侵入。
 *
 * 作者：zj
 * 日期：2026-11-11 14:10
 */
(function () {
    "use strict";

    // 判定是否可能是定位请求，命中时加醒目前缀便于日志里检索
    function isLocationUrl(url) {
        var lower = String(url || "").toLowerCase();
        return lower.indexOf("wloc") >= 0 || lower.indexOf("clls") >= 0 ||
            lower.indexOf("location") >= 0 || lower.indexOf("-ld.") >= 0 ||
            lower.indexOf("ls.apple.com") >= 0;
    }

    function main() {
        var request = typeof $request !== "undefined" ? $request : null;
        if (!request) {
            $done({});
            return;
        }

        var headers = request.headers || {};
        var keys = [];
        for (var name in headers) {
            if (Object.prototype.hasOwnProperty.call(headers, name)) {
                keys.push(name);
            }
        }

        var url = request.url || "<no url>";
        var flag = isLocationUrl(url) ? "*** LOCATION *** " : "";
        var bodyLen = request.body ? String(request.body).length : 0;

        console.log("[URL-LOG] " + flag + (request.method || "GET") + " " + url +
            " headers=" + keys.join(",") + " bodyLen=" + bodyLen);

        $done({});
    }

    try {
        main();
    } catch (err) {
        console.log("[URL-LOG] FATAL " + (err && err.message ? err.message : String(err)));
        $done({});
    }
}());
