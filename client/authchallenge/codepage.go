package authchallenge

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// codePageHTML 是短信 / 动态 / 设备验证码的输入页面。
//
// 与图形验证码页面保持一致的交互形态：都是「打开一个网页、在里面操作、提交」，
// 用户不必区分这次是哪种验证码，也不必回到终端敲命令。
// 两类验证码不会同时出现，所以复用同一个监听端口即可。
var codePageHTML = template.Must(template.New("code").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>zju-connect 验证码</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans CJK SC",sans-serif;
         background:#f0f2f5; display:flex; justify-content:center; align-items:center; min-height:100vh; }
  .card { background:#fff; border-radius:12px; box-shadow:0 2px 12px rgba(0,0,0,.1);
          padding:32px; width:420px; text-align:center; }
  h2 { color:#333; margin-bottom:10px; font-size:20px; }
  .msg { color:#666; font-size:14px; margin-bottom:20px; line-height:1.6; word-break:break-word; }
  input { width:100%; padding:11px 12px; font-size:17px; text-align:center; letter-spacing:3px;
          border:1px solid #d9d9d9; border-radius:6px; outline:none; }
  input:focus { border-color:#1890ff; box-shadow:0 0 0 2px rgba(24,144,255,.12); }
  button { width:100%; margin-top:14px; padding:11px; background:#1890ff; color:#fff; border:none;
           border-radius:6px; font-size:16px; cursor:pointer; }
  button:hover { background:#40a9ff; }
  button:disabled { background:#d9d9d9; cursor:not-allowed; }
  .ok { color:#52c41a; font-size:17px; margin-top:18px; display:none; }
  .err { color:#e74c3c; font-size:13px; margin-top:10px; min-height:18px; }
</style>
</head>
<body>
<div class="card">
  <h2>{{.Title}}</h2>
  <p class="msg">{{.Message}}</p>
  <form id="f" onsubmit="return submitCode()">
    <input id="code" type="text" autocomplete="one-time-code" autofocus
           placeholder="在此输入验证码">
    <button id="btn" type="submit">提 交</button>
  </form>
  <div class="err" id="err"></div>
  <div class="ok" id="ok">提交成功，可以关闭此页面</div>
</div>
<script>
var pageNonce = new URLSearchParams(location.search).get('n') || '';
var AUTO_CLOSE_MS = 3000;
// 提交成功后自动关闭标签页。标签页由 xdg-open 打开，不是脚本 window.open
// 打开的，部分浏览器会拒绝脚本关闭它；失败时退化为清屏，至少不把
// 验证码/成功态留在屏幕上。
function autoCloseTab() {
  setTimeout(function () {
    try { window.open('', '_self', ''); window.close(); } catch (e) {}
    setTimeout(function () {
      document.body.innerHTML =
        '<div style="font-family:sans-serif;color:#999;text-align:center;padding:48px">已提交，本页可以关闭</div>';
    }, 400);
  }, AUTO_CLOSE_MS);
}

function submitCode() {
  var code = document.getElementById('code').value.trim();
  var err = document.getElementById('err');
  if (!code) { err.textContent = '请先输入验证码'; return false; }
  var btn = document.getElementById('btn');
  btn.disabled = true; btn.textContent = '提交中...';
  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/submit', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.onload = function () {
    if (xhr.status === 200) {
      document.getElementById('f').style.display = 'none';
      err.textContent = '';
      document.getElementById('ok').style.display = 'block';
      autoCloseTab();
    } else if (xhr.status === 409) {
      btn.disabled = false; btn.textContent = '提 交';
      err.textContent = '本页验证码已过期，请在新打开的页面重新操作';
    } else {
      btn.disabled = false; btn.textContent = '提 交';
      err.textContent = '提交失败，请重试';
    }
  };
  xhr.onerror = function () {
    btn.disabled = false; btn.textContent = '提 交';
    err.textContent = '网络错误，请重试';
  };
  // 带上本轮 nonce：旧标签页的提交会被服务端拒绝
  xhr.send('code=' + encodeURIComponent(code) + '&n=' + encodeURIComponent(pageNonce));
  return false;
}
</script>
</body>
</html>`))

// codePageServer 承载验证码输入页面，收集用户提交的验证码原文。
type codePageServer struct {
	srv      *http.Server
	listener net.Listener
	resultCh chan string
	// nonce 标识本轮挑战，用于区分同一端口上的新旧两轮（见 newChallengeNonce）
	nonce string
}

func startCodePageServer(bind, kind, message string) (*codePageServer, error) {
	title := "请输入验证码"
	switch kind {
	case "sms":
		title = "请输入短信验证码"
	case "totp":
		title = "请输入动态口令"
	case "radius":
		title = "请输入 RADIUS 验证码"
	case "device":
		title = "请输入设备验证码"
	}

	resultCh := make(chan string, 1)
	nonce := newChallengeNonce()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = codePageHTML.Execute(w, struct {
			Title   string
			Message string
		}{Title: title, Message: message})
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.FormValue("n") != nonce {
			http.Error(w, "stale captcha page, please use the newly opened one", http.StatusConflict)
			return
		}
		code := strings.TrimSpace(r.FormValue("code"))
		if code == "" {
			http.Error(w, "empty code", http.StatusBadRequest)
			return
		}
		select {
		case resultCh <- code:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		default:
			http.Error(w, "already submitted", http.StatusConflict)
		}
	})

	listener, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, fmt.Errorf("failed to start code page server on %q: %w", bind, err)
	}

	srv := &codePageServer{
		srv:      &http.Server{Handler: mux},
		listener: listener,
		resultCh: resultCh,
		nonce:    nonce,
	}
	go srv.srv.Serve(listener)

	return srv, nil
}

// URL 返回宿主可直接访问的地址（监听通配地址时改写为回环）。
func (c *codePageServer) URL() string {
	addr, ok := c.listener.Addr().(*net.TCPAddr)
	if !ok {
		return "http://" + c.listener.Addr().String()
	}

	host := addr.IP.String()
	if addr.IP.IsUnspecified() {
		host = "127.0.0.1"
	}

	// 带上 nonce：每轮 URL 都不同，浏览器才会新开标签页而不是复用旧页
	return fmt.Sprintf("http://%s/?n=%s", net.JoinHostPort(host, strconv.Itoa(addr.Port)), c.nonce)
}

func (c *codePageServer) Close() {
	_ = c.srv.Shutdown(context.Background())
}
