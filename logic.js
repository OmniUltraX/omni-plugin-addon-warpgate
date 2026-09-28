/**
 * Warpgate 网关插件 L2（QuickJS）。
 *
 * 合同：全局 call(method, argsJson) -> JSON 字符串。
 * 网络走 host.netFetch；凭据可由明文或 vault key 传入。
 *
 * 方法：
 *   listSshTargets        — 拉取 SSH targets（堡垒入口）
 *   resolveSshViaGateway  — 解析为可直连的 SSH 参数
 *   testGateway           — 探测 API / 登录用户
 */

function authHeaders(token) {
  var headers = { Accept: "application/json" };
  if (token) {
    headers["X-Warpgate-Token"] = token;
    headers.Authorization = "Bearer " + token;
  }
  return headers;
}

function isTrue(value) {
  return value === true || value === "true" || value === 1 || value === "1";
}

function readSecret(plain, key) {
  var value = String(plain || "").trim();
  if (value) return value;
  if (!key) return "";
  try {
    return String(host.vaultGet(String(key)) || "").trim();
  } catch (e) {
    return "";
  }
}

function hostFromBase(baseUrl) {
  var after = String(baseUrl || "").replace(/^https?:\/\//i, "");
  var hostPort = after.split("/")[0] || "";
  if (hostPort.charAt(0) === "[") {
    var end = hostPort.indexOf("]");
    return end > 0 ? hostPort.slice(1, end) : hostPort;
  }
  return hostPort.split(":")[0];
}

function portFromAddress(address) {
  var s = String(address || "");
  var i = s.lastIndexOf(":");
  if (i < 0) return 0;
  var n = Number(s.slice(i + 1));
  return n > 0 ? n : 0;
}

function defaultPort(kind) {
  if (kind === "ssh") return 2222;
  if (kind === "mysql") return 33306;
  if (kind === "postgres") return 55432;
  return 0;
}

function parseKind(raw) {
  var k = String(raw || "").toLowerCase();
  if (k === "ssh" || k === "s") return "ssh";
  if (k === "mysql" || k === "mariadb") return "mysql";
  if (k === "postgres" || k === "postgresql") return "postgres";
  return null;
}

function fetchJson(url, headers, insecure) {
  var body = host.netFetch(
    JSON.stringify({ url: url, headers: headers, insecure: insecure === true }),
  );
  try {
    return JSON.parse(body);
  } catch (e) {
    throw new Error("Warpgate 返回非 JSON（请确认地址指向 Warpgate HTTP API）");
  }
}

function asList(parsed) {
  if (Array.isArray(parsed)) return parsed;
  if (parsed && Array.isArray(parsed.targets)) return parsed.targets;
  return null;
}

function isFixtureItem(item) {
  return !!(item && typeof item === "object" && item.bastionHost && item.kind);
}

function fetchTargetsList(baseUrl, headers, insecure) {
  try {
    var admin = asList(fetchJson(baseUrl + "/@warpgate/admin/api/targets", headers, insecure));
    if (admin) return admin;
  } catch (e) {
    var adminErr = String(e && e.message ? e.message : e);
    try {
      var raw = asList(fetchJson(baseUrl + "/targets", headers, insecure));
      var fixtures = [];
      if (raw) {
        for (var i = 0; i < raw.length; i++) {
          if (isFixtureItem(raw[i])) fixtures.push(raw[i]);
        }
      }
      if (fixtures.length > 0) return fixtures;
    } catch (e2) {
      throw new Error(adminErr);
    }
    throw new Error(adminErr);
  }
  throw new Error("无法拉取目标列表");
}

function fetchListenerPorts(baseUrl, headers, insecure) {
  var ports = {};
  try {
    var listeners = fetchJson(baseUrl + "/@warpgate/admin/api/network/listeners", headers, insecure);
    if (!Array.isArray(listeners)) return ports;
    for (var i = 0; i < listeners.length; i++) {
      var name = String((listeners[i] && listeners[i].name) || "").toLowerCase();
      var port = portFromAddress(listeners[i] && listeners[i].address);
      if (!port) continue;
      if (name.indexOf("ssh") >= 0) ports.ssh = port;
      else if (name.indexOf("mysql") >= 0 || name.indexOf("mariadb") >= 0) ports.mysql = port;
      else if (name.indexOf("postgres") >= 0) ports.postgres = port;
    }
  } catch (e) {
    /* 监听端口失败时用默认值 */
  }
  return ports;
}

function protocolUser(loginUser, targetName, kind) {
  var user = String(loginUser || "").trim();
  var target = String(targetName || "").trim();
  if (user && (user.indexOf(":") >= 0 || user.indexOf("#") >= 0)) {
    return user;
  }
  if (user && target) {
    return kind === "mysql" || kind === "postgres" ? user + "#" + target : user + ":" + target;
  }
  return user || target;
}

function fetchLoginUser(baseUrl, headers, insecure) {
  var urls = [baseUrl + "/@warpgate/api/info", baseUrl + "/@warpgate/admin/api/info"];
  for (var i = 0; i < urls.length; i++) {
    try {
      var info = fetchJson(urls[i], headers, insecure);
      var user =
        (info && (info.username || info.user)) ||
        (info && info.user_info && info.user_info.username);
      if (user) return String(user);
    } catch (e) {
      /* 继续试下一个 */
    }
  }
  return "";
}

function parseArgs(argsJson) {
  try {
    return JSON.parse(argsJson || "{}");
  } catch (e) {
    throw new Error("args 非法 JSON");
  }
}

function gatewayContext(args) {
  var baseUrl = String(args.baseUrl || "").replace(/\/+$/, "");
  if (!/^https?:\/\//.test(baseUrl)) {
    throw new Error("baseUrl 必须以 http(s):// 开头");
  }
  var token = readSecret(args.token, args.tokenKey);
  if (!token) {
    throw new Error("请填写 API Token");
  }
  var password = readSecret(args.password, args.passwordKey);
  var insecure = isTrue(args.insecureTls) || isTrue(args.insecure);
  var headers = authHeaders(token);
  var bastionHost = hostFromBase(baseUrl);
  if (!bastionHost) {
    throw new Error("无法从 baseUrl 解析堡垒主机");
  }
  var loginUser = String(args.loginUser || "").trim() || fetchLoginUser(baseUrl, headers, insecure);
  var ports = fetchListenerPorts(baseUrl, headers, insecure);
  return {
    baseUrl: baseUrl,
    token: token,
    password: password,
    insecure: insecure,
    headers: headers,
    bastionHost: bastionHost,
    loginUser: loginUser,
    ports: ports,
  };
}

function mapSshTarget(raw, ctx) {
  if (!raw || typeof raw !== "object") return null;
  if (raw.bastionHost && raw.kind) {
    var fixtureKind = parseKind(raw.kind);
    if (fixtureKind !== "ssh") return null;
    return {
      id: String(raw.id || raw.name || ""),
      name: String(raw.name || raw.id || ""),
      kind: "ssh",
      bastionHost: String(raw.bastionHost),
      bastionPort: Number(raw.bastionPort) || ctx.ports.ssh || defaultPort("ssh"),
      loginUser: String(raw.loginUser || raw.username || ctx.loginUser || ""),
    };
  }
  var options = raw.options && typeof raw.options === "object" ? raw.options : raw;
  var kind = parseKind(options.kind || raw.kind || options.protocol);
  if (kind !== "ssh") return null;
  return {
    id: String(raw.id || raw.name || ""),
    name: String(raw.name || raw.id || ""),
    kind: "ssh",
    bastionHost: ctx.bastionHost,
    bastionPort: ctx.ports.ssh || defaultPort("ssh"),
    loginUser: String(raw.loginUser || ctx.loginUser || ""),
  };
}

function listSshTargets(args) {
  var ctx = gatewayContext(args);
  var rawList = fetchTargetsList(ctx.baseUrl, ctx.headers, ctx.insecure);
  var targets = [];
  var skipped = 0;
  for (var i = 0; i < rawList.length; i++) {
    var mapped = mapSshTarget(rawList[i], ctx);
    if (mapped && mapped.id) targets.push(mapped);
    else skipped += 1;
  }
  return {
    targets: targets,
    skipped: skipped,
    loginUser: ctx.loginUser,
    bastionHost: ctx.bastionHost,
    bastionPort: ctx.ports.ssh || defaultPort("ssh"),
    fetchedAt: Date.now(),
  };
}

function resolveSshViaGateway(args) {
  var ctx = gatewayContext(args);
  var targetId = String(args.targetId || "").trim();
  var targetName = String(args.targetName || "").trim();
  if (!targetId && !targetName) {
    throw new Error("请指定 targetId 或 targetName");
  }
  var listed = listSshTargets(args);
  var match = null;
  for (var i = 0; i < listed.targets.length; i++) {
    var t = listed.targets[i];
    if (targetId && t.id === targetId) {
      match = t;
      break;
    }
    if (!match && targetName && t.name === targetName) match = t;
  }
  if (!match) {
    // 列表失败或 target 对当前 Token 不可见时，仍可按名称拼协议用户
    if (!targetName) throw new Error("未找到指定的 Warpgate SSH target");
    match = {
      id: targetId || targetName,
      name: targetName,
      kind: "ssh",
      bastionHost: ctx.bastionHost,
      bastionPort: ctx.ports.ssh || defaultPort("ssh"),
      loginUser: ctx.loginUser,
    };
  }
  var user = protocolUser(match.loginUser || ctx.loginUser, match.name, "ssh");
  var out = {
    host: match.bastionHost,
    port: match.bastionPort || ctx.ports.ssh || defaultPort("ssh"),
    user: user,
    targetId: match.id,
    targetName: match.name,
    via: "warpgate-bastion",
  };
  if (ctx.password) out.password = ctx.password;
  return out;
}

function testGateway(args) {
  var ctx = gatewayContext(args);
  return {
    ok: true,
    loginUser: ctx.loginUser,
    bastionHost: ctx.bastionHost,
    bastionPort: ctx.ports.ssh || defaultPort("ssh"),
  };
}

globalThis.call = function (method, argsJson) {
  var args = parseArgs(argsJson);
  if (method === "listSshTargets") return JSON.stringify(listSshTargets(args));
  if (method === "resolveSshViaGateway") return JSON.stringify(resolveSshViaGateway(args));
  if (method === "testGateway") return JSON.stringify(testGateway(args));
  throw new Error("未知方法: " + method);
};
