package authchallenge

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tinyPNG 是一张 1x1 的合法 PNG，够验证码页面渲染即可。
func tinyPNG() []byte {
	return []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
		0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41,
		0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
		0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xdd, 0x8d,
		0xb0, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e,
		0x44, 0xae, 0x42, 0x60, 0x82,
	}
}

// readState 读取并解析 state.json。
func readState(t *testing.T, dir string) map[string]any {
	t.Helper()
	path := filepath.Join(dir, StateFile)
	waitFor(t, 2*time.Second, func() bool { _, err := os.Stat(path); return err == nil })

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}

	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	return state
}

// stateURL 取出 state.json 里的页面地址，并返回 nonce。
func stateURL(t *testing.T, state map[string]any) (pageURL, nonce string) {
	t.Helper()
	pageURL, _ = state["url"].(string)
	if !strings.Contains(pageURL, "?n=") {
		t.Fatalf("state.url should carry a nonce, got %q", pageURL)
	}
	nonce = strings.SplitN(pageURL, "?n=", 2)[1]
	return pageURL, nonce
}

// 图形验证码：页面可访问，提交坐标后返回。
func TestWebBridgeClickCaptchaViaHTTP(t *testing.T) {
	dir := t.TempDir()
	h := NewWebBridgeHandler(WebBridgeOptions{
		Dir:            dir,
		CaptchaBind:    "127.0.0.1:18099",
		CaptchaTimeout: 5 * time.Second,
		Output:         io.Discard,
	})

	done := make(chan ClickCaptchaResponse, 1)
	go func() {
		response, err := h.HandleClickCaptcha(ClickCaptchaChallenge{
			Image:   tinyPNG(),
			Message: "Please enter the graph check code JSON:",
		})
		if err != nil {
			t.Errorf("HandleClickCaptcha: %v", err)
		}
		done <- response
	}()

	_, nonce := stateURL(t, readState(t, dir))
	base := "http://127.0.0.1:18099"

	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "验证码") {
		t.Fatalf("captcha page looks wrong")
	}

	resp, err = http.Get(base + "/captcha.img")
	if err != nil {
		t.Fatalf("GET /captcha.img: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("captcha.img status = %d", resp.StatusCode)
	}

	// 不带 nonce 的旧页面提交必须被拒绝，否则会把上一轮坐标喂给新一轮
	staleForm := url.Values{"code": {`{"coordinates":[[1,1]],"width":1,"height":1}`}}
	staleResp, err := http.Post(base+"/submit", "application/x-www-form-urlencoded",
		strings.NewReader(staleForm.Encode()))
	if err != nil {
		t.Fatalf("POST /submit (stale): %v", err)
	}
	staleResp.Body.Close()
	if staleResp.StatusCode != http.StatusConflict {
		t.Fatalf("stale submit status = %d, want 409", staleResp.StatusCode)
	}

	payload := `{"coordinates":[[10,20],[30,40]],"width":1,"height":1}`
	form := url.Values{"code": {payload}, "n": {nonce}}
	resp, err = http.Post(base+"/submit", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("submit status = %d", resp.StatusCode)
	}

	select {
	case response := <-done:
		if len(response.Points) != 2 {
			t.Fatalf("got %d points, want 2", len(response.Points))
		}
		if response.Points[0].X != 10 || response.Points[0].Y != 20 {
			t.Fatalf("point[0] = %+v, want {10 20}", response.Points[0])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return after HTTP submit")
	}

	// 完成后 state.json 必须消失，否则宿主 watcher 会以为还需要输入
	if _, err := os.Stat(filepath.Join(dir, StateFile)); !os.IsNotExist(err) {
		t.Fatalf("state.json should be removed after completion")
	}
}

// 短信验证码：同样走网页，且页面标题体现类型。
func TestWebBridgeCodeChallengeViaHTTP(t *testing.T) {
	dir := t.TempDir()
	h := NewWebBridgeHandler(WebBridgeOptions{
		Dir:         dir,
		CaptchaBind: "127.0.0.1:18098",
		CodeTimeout: 5 * time.Second,
		Output:      io.Discard,
	})

	done := make(chan CodeResponse, 1)
	go func() {
		response, err := h.HandleCodeChallenge(CodeChallenge{
			Kind:    CodeSMS,
			Message: "Please enter the SMS verification code:",
		})
		if err != nil {
			t.Errorf("HandleCodeChallenge: %v", err)
		}
		done <- response
	}()

	state := readState(t, dir)
	if state["kind"] != "sms" {
		t.Fatalf("state.kind = %v, want sms", state["kind"])
	}
	pageURL, nonce := stateURL(t, state)
	if !strings.HasPrefix(pageURL, "http://127.0.0.1:18098/?n=") {
		t.Fatalf("state.url = %v", pageURL)
	}

	base := "http://127.0.0.1:18098"
	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "请输入短信验证码") {
		t.Fatalf("code page should name the challenge type")
	}

	form := url.Values{"code": {"246810"}, "n": {nonce}}
	resp, err = http.Post(base+"/submit", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("submit status = %d", resp.StatusCode)
	}

	select {
	case response := <-done:
		if response.Code != "246810" {
			t.Fatalf("code = %q, want 246810", response.Code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return after HTTP submit")
	}
}

// $ 前缀跳过二次认证的上游语义必须保留。
func TestWebBridgeCodeChallengeSkipSecondary(t *testing.T) {
	dir := t.TempDir()
	h := NewWebBridgeHandler(WebBridgeOptions{
		Dir:         dir,
		CaptchaBind: "127.0.0.1:18097",
		CodeTimeout: 5 * time.Second,
		Output:      io.Discard,
	})

	done := make(chan CodeResponse, 1)
	go func() {
		response, err := h.HandleCodeChallenge(CodeChallenge{
			Kind:                 CodeDevice,
			Message:              "code:",
			CanSkipSecondaryAuth: true,
		})
		if err != nil {
			t.Errorf("HandleCodeChallenge: %v", err)
		}
		done <- response
	}()

	_, nonce := stateURL(t, readState(t, dir))
	form := url.Values{"code": {"$778899"}, "n": {nonce}}
	resp, err := http.Post("http://127.0.0.1:18097/submit", "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	resp.Body.Close()

	select {
	case response := <-done:
		if !response.SkipSecondaryAuth {
			t.Fatalf("SkipSecondaryAuth should be true for $ prefix, got %+v", response)
		}
		if response.Code != "778899" {
			t.Fatalf("code = %q, want 778899 (prefix stripped)", response.Code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return")
	}
}

// 没配 captcha_bind 时必须明确报错：否则容器里会静默挂起，
// 用户在宿主端根本无从得知要去哪里操作。
func TestWebBridgeRequiresBind(t *testing.T) {
	h := NewWebBridgeHandler(WebBridgeOptions{
		Dir:    t.TempDir(),
		Output: io.Discard,
	})

	if _, err := h.HandleClickCaptcha(ClickCaptchaChallenge{Image: tinyPNG()}); err == nil {
		t.Fatal("expected an error when captcha_bind is empty")
	}
	if _, err := h.HandleCodeChallenge(CodeChallenge{Kind: CodeSMS, Message: "code:"}); err == nil {
		t.Fatal("expected an error when captcha_bind is empty")
	}
}

// 超时必须报错，并且留下「需要人工」标记：
// 容器入口据此决定不自动重试，避免重新发起登录又发一条短信。
func TestWebBridgeTimeout(t *testing.T) {
	dir := t.TempDir()
	h := NewWebBridgeHandler(WebBridgeOptions{
		Dir:         dir,
		CaptchaBind: "127.0.0.1:18096",
		CodeTimeout: 150 * time.Millisecond,
		Output:      io.Discard,
	})

	if _, err := h.HandleCodeChallenge(CodeChallenge{Kind: CodeSMS, Message: "code:"}); err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	markerPath := filepath.Join(dir, NeedsHumanFile)
	data, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("needs-human marker should exist after timeout: %v", err)
	}

	var marker map[string]any
	if err := json.Unmarshal(data, &marker); err != nil {
		t.Fatalf("marker should be valid JSON: %v", err)
	}
	if marker["kind"] != "sms" {
		t.Fatalf("marker.kind = %v, want sms", marker["kind"])
	}
	if marker["url"] == "" {
		t.Fatal("marker should carry the page url so the operator knows what to open")
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}
