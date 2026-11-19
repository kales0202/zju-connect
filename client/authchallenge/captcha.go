package authchallenge

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

const captchaPageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>zju-connect 验证码</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f0f2f5;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
  }
  .card {
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.1);
    padding: 32px;
    text-align: center;
  }
  h2 { color: #333; margin-bottom: 16px; font-size: 20px; }
  .hint { color: #666; font-size: 14px; margin-bottom: 12px; }
  .img-wrap {
    position: relative;
    display: inline-block;
    cursor: crosshair;
    user-select: none;
    margin-bottom: 16px;
  }
  .img-wrap img {
    display: block;
    /* no width/height constraints: render at natural pixel size */
  }
  .marker {
    position: absolute;
    width: 28px; height: 28px;
    border-radius: 50%;
    background: rgba(24,144,255,0.85);
    color: #fff;
    font-size: 14px; font-weight: bold;
    line-height: 28px; text-align: center;
    transform: translate(-50%, -50%);
    pointer-events: none;
    box-shadow: 0 1px 4px rgba(0,0,0,0.3);
  }
  .actions { margin-bottom: 16px; }
  .actions button {
    padding: 6px 18px;
    margin: 0 6px;
    border: 1px solid #d9d9d9;
    border-radius: 6px;
    background: #fff;
    color: #333;
    font-size: 14px;
    cursor: pointer;
    transition: all 0.2s;
  }
  .actions button:hover { border-color: #1890ff; color: #1890ff; }
  #submitBtn {
    width: 100%;
    padding: 10px;
    background: #1890ff;
    color: #fff;
    border: none;
    border-radius: 6px;
    font-size: 16px;
    cursor: pointer;
    transition: background 0.2s;
  }
  #submitBtn:hover { background: #40a9ff; }
  #submitBtn:disabled { background: #d9d9d9; cursor: not-allowed; }
  .status { margin-top: 12px; font-size: 14px; color: #888; }
  details.debug-panel { margin-top: 8px; text-align: left; }
  details.debug-panel > summary { cursor: pointer; color: #999; font-size: 12px; }
  .debug {
    margin-top: 6px; height: 100px; overflow-y: auto;
    font-size: 12px; color: #aaa; white-space: pre;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }
  .success { color: #52c41a; font-size: 18px; margin-top: 20px; display: none; }
</style>
</head>
<body>
<div class="card">
  <h2 id="headline">请按顺序点击图中指定的文字</h2>
  <p class="hint" id="hint">在验证码图片上依次点击对应文字的位置</p>
  <div class="img-wrap" id="imgWrap">
    <img id="captchaImg" src="/captcha.img" alt="验证码" draggable="false">
  </div>
  <div class="actions">
    <button id="undoBtn" type="button" onclick="undoClick()">撤销上一个</button>
    <button id="clearBtn" type="button" onclick="clearClicks()">全部清除</button>
  </div>
  <p class="status" id="status">已选择 0 个点</p>
  <details class="debug-panel" id="debugPanel">
    <summary id="debugSummary">Debug</summary>
    <pre class="debug" id="debug"></pre>
  </details>
  <button id="submitBtn" onclick="submitClicks()" disabled>提 交</button>
  <div class="success" id="success">提交成功，可以关闭此页面</div>
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

var clicks = [];
var imgWrap = document.getElementById('imgWrap');
var captchaImg = document.getElementById('captchaImg');
var statusEl = document.getElementById('status');
var submitBtn = document.getElementById('submitBtn');
var debugPanelEl = document.getElementById('debugPanel');
var debugSummaryEl = document.getElementById('debugSummary');
var debugEl = document.getElementById('debug');
var headlineEl = document.getElementById('headline');
var hintEl = document.getElementById('hint');
var undoBtnEl = document.getElementById('undoBtn');
var clearBtnEl = document.getElementById('clearBtn');
var successEl = document.getElementById('success');
var isSubmitting = false;

var I18N = {
  zh: {
    title: 'zju-connect 验证码',
    heading: '请按顺序点击图中指定的文字',
    hint: '在验证码图片上依次点击对应文字的位置',
    undo: '撤销上一个', clear: '全部清除',
    status: function(n) { return '已选择 ' + n + ' 个点'; },
    submit: '提 交', submitting: '提交中...',
    success: '提交成功，可以关闭此页面',
    submitFailed: '提交失败，请重试',
    stalePage: '本页验证码已过期，请在新打开的页面重新操作',
    networkError: '网络错误，请重试',
    imgAlt: '验证码',
    debugSummary: '调试信息'
  },
  en: {
    title: 'zju-connect Captcha',
    heading: 'Click the specified characters in order',
    hint: 'Click the matching characters on the captcha image in sequence.',
    undo: 'Undo', clear: 'Clear',
    status: function(n) { return 'Selected ' + n + ' point' + (n !== 1 ? 's' : ''); },
    submit: 'Submit', submitting: 'Submitting...',
    success: 'Submitted. You may close this page.',
    submitFailed: 'Submission failed. Please retry.',
    stalePage: 'This captcha has expired. Use the newly opened page.',
    networkError: 'Network error. Please retry.',
    imgAlt: 'Captcha',
    debugSummary: 'Debug'
  }
};

var lang = (function() {
  var l = ((navigator.languages && navigator.languages[0]) || navigator.language || '').toLowerCase();
  return l.indexOf('zh') === 0 ? 'zh' : 'en';
})();

function tr(key) { return (I18N[lang] || I18N.en)[key]; }

function applyLang() {
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  document.title = tr('title');
  headlineEl.textContent = tr('heading');
  hintEl.textContent = tr('hint');
  undoBtnEl.textContent = tr('undo');
  clearBtnEl.textContent = tr('clear');
  captchaImg.alt = tr('imgAlt');
  debugSummaryEl.textContent = tr('debugSummary');
  successEl.textContent = tr('success');
  renderStatus();
}

function renderStatus() {
  statusEl.textContent = tr('status')(clicks.length);
  submitBtn.textContent = isSubmitting ? tr('submitting') : tr('submit');
  submitBtn.disabled = clicks.length === 0 || isSubmitting;
}

captchaImg.onload = function() { updateDebug(); };

captchaImg.addEventListener('click', function(e) {
  if (isSubmitting) return;
  var rect = captchaImg.getBoundingClientRect();
  var nw = captchaImg.naturalWidth || Math.round(rect.width);
  var nh = captchaImg.naturalHeight || Math.round(rect.height);
  var dw = rect.width || nw;
  var dh = rect.height || nh;

  var x = Math.max(0, Math.min(nw - 1, Math.round((e.clientX - rect.left) * nw / dw)));
  var y = Math.max(0, Math.min(nh - 1, Math.round((e.clientY - rect.top) * nh / dh)));

  clicks.push({x: x, y: y});
  renderMarkers();
  renderStatus();
  updateDebug();
});

function updateDebug() {
  var rect = captchaImg.getBoundingClientRect();
  var lines = ['natural: ' + captchaImg.naturalWidth + 'x' + captchaImg.naturalHeight
    + ', display: ' + Math.round(rect.width) + 'x' + Math.round(rect.height)
    + ', dpr: ' + window.devicePixelRatio];
  for (var i = 0; i < clicks.length; i++) {
    lines.push((i+1) + ': (' + clicks[i].x + ', ' + clicks[i].y + ')');
  }
  debugEl.textContent = lines.join('\n');
}

function renderMarkers() {
  var old = imgWrap.querySelectorAll('.marker');
  for (var i = 0; i < old.length; i++) old[i].remove();

  var rect = captchaImg.getBoundingClientRect();
  var nw = captchaImg.naturalWidth || Math.round(rect.width);
  var nh = captchaImg.naturalHeight || Math.round(rect.height);
  var dw = rect.width || nw;
  var dh = rect.height || nh;

  for (var i = 0; i < clicks.length; i++) {
    var m = document.createElement('div');
    m.className = 'marker';
    m.textContent = i + 1;
    m.style.left = (clicks[i].x * dw / nw) + 'px';
    m.style.top = (clicks[i].y * dh / nh) + 'px';
    imgWrap.appendChild(m);
  }
}

function undoClick() {
  if (isSubmitting) return;
  clicks.pop();
  renderMarkers();
  renderStatus();
  updateDebug();
}

function clearClicks() {
  if (isSubmitting) return;
  clicks = [];
  renderMarkers();
  renderStatus();
  updateDebug();
}

function submitClicks() {
  if (clicks.length === 0 || isSubmitting) return;
  var rect = captchaImg.getBoundingClientRect();
  var width = captchaImg.naturalWidth || Math.round(rect.width);
  var height = captchaImg.naturalHeight || Math.round(rect.height);
  var payload = JSON.stringify({
    coordinates: clicks.map(function(p) { return [p.x, p.y]; }),
    width: width, height: height
  });

  isSubmitting = true;
  renderStatus();

  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/submit', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.onload = function() {
    if (xhr.status === 200) {
      imgWrap.style.display = 'none';
      document.querySelector('.actions').style.display = 'none';
      statusEl.style.display = 'none';
      submitBtn.style.display = 'none';
      debugPanelEl.style.display = 'none';
      successEl.style.display = 'block';
      autoCloseTab();
    } else if (xhr.status === 409) {
      // 验证码已换新：旧页面作废，提示去看新开的标签页
      isSubmitting = false;
      renderStatus();
      alert(tr('stalePage'));
    } else {
      isSubmitting = false;
      renderStatus();
      alert(tr('submitFailed'));
    }
  };
  xhr.onerror = function() {
    isSubmitting = false;
    renderStatus();
    alert(tr('networkError'));
  };
  // 带上本轮 nonce：验证码答错后上游会换一张新图并重启服务，
  // 旧标签页若继续提交必须被拒绝，否则会把上一轮的坐标喂给新一轮。
  xhr.send('code=' + encodeURIComponent(payload) + '&n=' + encodeURIComponent(pageNonce));
  return false;
}

applyLang();
</script>
</body>
</html>`

// captchaServer 是一个临时 HTTP 服务：渲染点击式验证码页面并回收坐标。
type captchaServer struct {
	srv      *http.Server
	listener net.Listener
	resultCh chan ClickCaptchaResponse
	// nonce 标识「本轮」验证码。验证码答错时上游会重新发起挑战，
	// 服务会在同一端口重启；带上 nonce 才能区分新旧两轮，
	// 避免旧标签页把过期坐标提交给新一轮。
	nonce string
}

// startCaptchaServer 在 bind 指定的地址上启动验证码页面服务。
//
// bind 为空时沿用上游行为：只监听 127.0.0.1 的随机端口（容器内不可达）。
// bind 形如 "0.0.0.0:18080" 时监听固定端口，配合容器端口映射即可让宿主机
// 浏览器直接打开，无需 --network host。
func startCaptchaServer(imgData []byte, bind string) (*captchaServer, error) {
	if bind == "" {
		bind = "127.0.0.1:0"
	}

	resultCh := make(chan ClickCaptchaResponse, 1)
	nonce := newChallengeNonce()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(captchaPageHTML))
	})

	mux.HandleFunc("/captcha.img", func(w http.ResponseWriter, r *http.Request) {
		contentType := http.DetectContentType(imgData)
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Write(imgData)
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
		code := r.FormValue("code")
		if code == "" {
			http.Error(w, "empty code", http.StatusBadRequest)
			return
		}
		response, err := parseClickCaptchaResponse(code)
		if err != nil {
			http.Error(w, "invalid code: "+err.Error(), http.StatusBadRequest)
			return
		}
		select {
		case resultCh <- response:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		default:
			http.Error(w, "already submitted", http.StatusConflict)
		}
	})

	listener, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, fmt.Errorf("failed to start captcha server on %q: %w", bind, err)
	}

	cs := &captchaServer{
		srv:      &http.Server{Handler: mux},
		listener: listener,
		resultCh: resultCh,
		nonce:    nonce,
	}

	go cs.srv.Serve(listener)

	return cs, nil
}

// URL 返回宿主可直接访问的地址。监听通配地址时改写为 127.0.0.1，
// 因为容器外看到的就是宿主自己的回环。
func (c *captchaServer) URL() string {
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

func (c *captchaServer) Close() {
	_ = c.srv.Shutdown(context.Background())
}

// serveCaptchaInBrowser starts a temporary HTTP server to display the captcha
// image in the user's browser and waits for the user to click on character
// positions and submit the coordinates.
func serveCaptchaInBrowser(imgData []byte, timeout time.Duration, output io.Writer) (ClickCaptchaResponse, error) {
	return serveCaptchaInBrowserBind(imgData, timeout, output, "")
}

// serveCaptchaInBrowserBind 与 serveCaptchaInBrowser 相同，但可指定监听地址。
func serveCaptchaInBrowserBind(imgData []byte, timeout time.Duration, output io.Writer, bind string) (ClickCaptchaResponse, error) {
	cs, err := startCaptchaServer(imgData, bind)
	if err != nil {
		return ClickCaptchaResponse{}, err
	}
	defer cs.Close()

	url := cs.URL()
	_, _ = fmt.Fprintf(output, "Captcha server started at %s\n", url)

	openBrowser(url, output)

	select {
	case response := <-cs.resultCh:
		return response, nil
	case <-time.After(timeout):
		return ClickCaptchaResponse{}, fmt.Errorf("captcha input timed out after %v", timeout)
	}
}

// openBrowser tries to open the given URL in the system's default browser.
func openBrowser(url string, output io.Writer) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		_, _ = fmt.Fprintf(output, "Unsupported platform for auto-opening browser, please visit: %s\n", url)
		return
	}
	if err := cmd.Start(); err != nil {
		_, _ = fmt.Fprintf(output, "Failed to open browser: %v. Please visit: %s\n", err, url)
	}
}
