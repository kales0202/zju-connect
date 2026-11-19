package authchallenge

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// StateFile 描述「当前正在等待什么交互」，没有该文件就说明无需人工介入。
//
// 它只是给宿主侧 watcher 的提示（用来弹通知、自动打开浏览器），
// 不承担收集答案的职责——答案只从网页提交回来。
const StateFile = "state.json"

// ResultFile 记录最近一次已回收的输入，便于事后核对。
const ResultFile = "result.json"

// NeedsHumanFile 表示「上次退出是因为等不到人工输入」。
// 容器入口据此判定不要自动重试：重试会重新发起登录，
// 也就可能再发一条短信，把人不在场放大成风控风险。
const NeedsHumanFile = "needs-human.json"

const (
	defaultCodeTimeout  = 10 * time.Minute
	defaultPollInterval = 500 * time.Millisecond
)

// WebBridgeOptions 配置网页交互通路。
type WebBridgeOptions struct {
	// Dir 是宿主与容器共享的目录，只用来放 state.json / result.json。
	Dir string
	// CaptchaBind 是验证码页面服务的监听地址，必须能从宿主访问
	// （例如 0.0.0.0:18080，配合容器端口映射）。
	CaptchaBind string
	// CaptchaTimeout 是等待图形验证码的上限，默认 5 分钟（与上游一致）。
	CaptchaTimeout time.Duration
	// CodeTimeout 是等待短信等验证码的上限，默认 10 分钟。
	CodeTimeout time.Duration
	// PollInterval 预留给状态刷新。
	PollInterval time.Duration
	// Output 是提示输出，默认 os.Stdout。
	Output io.Writer
}

// WebBridgeHandler 通过网页与用户交互，不依赖 stdin / tty。
//
// 这样 `docker compose up -d` 的后台容器也能完成需要人工输入的登录：
// 程序把「需要什么」写进 state.json（宿主 watcher 据此自动打开浏览器），
// 用户在网页里操作，答案由页面直接提交回来。
//
// 与默认 CLIHandler 的差别只在于「答案从哪来」：这里是 HTTP POST，不是 stdin。
type WebBridgeHandler struct {
	opts WebBridgeOptions
	mu   sync.Mutex
}

func NewWebBridgeHandler(options WebBridgeOptions) *WebBridgeHandler {
	if options.CaptchaTimeout <= 0 {
		options.CaptchaTimeout = defaultCaptchaTimeout
	}
	if options.CodeTimeout <= 0 {
		options.CodeTimeout = defaultCodeTimeout
	}
	if options.PollInterval <= 0 {
		options.PollInterval = defaultPollInterval
	}
	if options.Output == nil {
		options.Output = os.Stdout
	}

	return &WebBridgeHandler{opts: options}
}

func (h *WebBridgeHandler) logf(format string, args ...any) {
	_, _ = fmt.Fprintf(h.opts.Output, "[challenge] "+format+"\n", args...)
}

func (h *WebBridgeHandler) path(name string) string {
	return filepath.Join(h.opts.Dir, name)
}

// HandleClickCaptcha 等待用户在网页上点选图形验证码。
func (h *WebBridgeHandler) HandleClickCaptcha(challenge ClickCaptchaChallenge) (ClickCaptchaResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.opts.CaptchaBind == "" {
		return ClickCaptchaResponse{}, fmt.Errorf(
			"graph captcha needs a reachable web page: set captcha_bind (e.g. 0.0.0.0:18080)")
	}

	if err := os.MkdirAll(h.opts.Dir, 0o755); err != nil {
		return ClickCaptchaResponse{}, fmt.Errorf("create challenge dir: %w", err)
	}

	srv, err := startCaptchaServer(challenge.Image, h.opts.CaptchaBind)
	if err != nil {
		return ClickCaptchaResponse{}, fmt.Errorf("start captcha page: %w", err)
	}
	defer srv.Close()

	statePath := h.path(StateFile)
	captchaURL := srv.URL()

	if err := h.writeState(statePath, map[string]any{
		"kind":    "click_captcha",
		"message": challenge.Message,
		"url":     captchaURL,
		"since":   time.Now().Format(time.RFC3339Nano),
	}); err != nil {
		return ClickCaptchaResponse{}, err
	}

	h.logf("需要完成图形验证码（%v 内有效）：%s", h.opts.CaptchaTimeout, captchaURL)

	timer := time.NewTimer(h.opts.CaptchaTimeout)
	defer timer.Stop()

	select {
	case response := <-srv.resultCh:
		h.finish(statePath, map[string]any{"kind": "click_captcha", "via": "browser"})
		return response, nil
	case <-timer.C:
		h.clearState(statePath)
		h.markNeedsHuman("click_captcha", captchaURL, h.opts.CaptchaTimeout)
		return ClickCaptchaResponse{}, fmt.Errorf("captcha input timed out after %v", h.opts.CaptchaTimeout)
	}
}

// HandleCodeChallenge 等待用户在网页上输入短信 / 动态 / 设备验证码。
func (h *WebBridgeHandler) HandleCodeChallenge(challenge CodeChallenge) (CodeResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.opts.CaptchaBind == "" {
		return CodeResponse{}, fmt.Errorf(
			"%s code needs a reachable web page: set captcha_bind (e.g. 0.0.0.0:18080)", challenge.Kind)
	}

	if err := os.MkdirAll(h.opts.Dir, 0o755); err != nil {
		return CodeResponse{}, fmt.Errorf("create challenge dir: %w", err)
	}

	srv, err := startCodePageServer(h.opts.CaptchaBind, string(challenge.Kind), challenge.Message)
	if err != nil {
		return CodeResponse{}, fmt.Errorf("start code page: %w", err)
	}
	defer srv.Close()

	statePath := h.path(StateFile)
	codeURL := srv.URL()

	if err := h.writeState(statePath, map[string]any{
		"kind":    string(challenge.Kind),
		"message": challenge.Message,
		"url":     codeURL,
		"since":   time.Now().Format(time.RFC3339Nano),
	}); err != nil {
		return CodeResponse{}, err
	}

	h.logf("需要输入验证码（%s，%v 内有效）：%s", challenge.Kind, h.opts.CodeTimeout, codeURL)

	timer := time.NewTimer(h.opts.CodeTimeout)
	defer timer.Stop()

	var raw string
	select {
	case raw = <-srv.resultCh:
	case <-timer.C:
		h.clearState(statePath)
		h.markNeedsHuman(string(challenge.Kind), codeURL, h.opts.CodeTimeout)
		return CodeResponse{}, fmt.Errorf("timed out after %v waiting for %s", h.opts.CodeTimeout, challenge.Kind)
	}

	response := CodeResponse{Code: strings.TrimSpace(raw)}

	// 保留上游语义：$ 前缀表示跳过二次认证
	if challenge.CanSkipSecondaryAuth {
		if code, found := strings.CutPrefix(response.Code, "$"); found {
			response.Code = strings.TrimSpace(code)
			response.SkipSecondaryAuth = true
		}
	}
	if response.Code == "" {
		h.clearState(statePath)
		return CodeResponse{}, fmt.Errorf("authentication code is empty")
	}

	h.finish(statePath, map[string]any{"kind": string(challenge.Kind), "via": "browser"})
	return response, nil
}

// HandleTextCaptcha 属于 easyconnect 协议的文本验证码，本项目只走 aTrust 协议，
// 没有稳定的网页形态可复用，因此明确报错而不是给出半成品交互。
func (h *WebBridgeHandler) HandleTextCaptcha(challenge TextCaptchaChallenge) (TextCaptchaResponse, error) {
	return TextCaptchaResponse{}, fmt.Errorf(
		"text captcha is not supported by the web bridge; use the default stdin handler for easyconnect protocol")
}

// HandleExternalLogin 需要浏览器跳转登录，网页桥无法完成。
func (h *WebBridgeHandler) HandleExternalLogin(challenge ExternalLoginChallenge) (ExternalLoginResponse, error) {
	return ExternalLoginResponse{}, fmt.Errorf(
		"external login (%s) is not supported by the web bridge; login url: %s",
		challenge.Kind, challenge.LoginURL)
}

func (h *WebBridgeHandler) writeState(path string, state map[string]any) error {
	state["updated_at"] = time.Now().Format(time.RFC3339)

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal challenge state: %w", err)
	}

	// 先写临时文件再改名：宿主 watcher 不会读到写了一半的内容
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write challenge state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("publish challenge state: %w", err)
	}

	return nil
}

func (h *WebBridgeHandler) finish(statePath string, result map[string]any) {
	result["finished_at"] = time.Now().Format(time.RFC3339)
	if data, err := json.MarshalIndent(result, "", "  "); err == nil {
		_ = os.WriteFile(h.path(ResultFile), data, 0o644)
	}
	h.clearState(statePath)
	h.logf("已收到输入，继续登录")
}

// markNeedsHuman 写一个标记文件，供容器入口判断「该停下来等人」而不是重试。
func (h *WebBridgeHandler) markNeedsHuman(kind, url string, timeout time.Duration) {
	marker := map[string]any{
		"kind":        kind,
		"url":         url,
		"timeout":     timeout.String(),
		"finished_at": time.Now().Format(time.RFC3339),
		"hint":        "需要人工完成验证码；容器已停止自动重试，请手动 docker compose up -d",
	}

	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(h.path(NeedsHumanFile), data, 0o644)
	h.logf("等待人工输入超时，已写入 %s（容器将停止而不是自动重试）", h.path(NeedsHumanFile))
}

func (h *WebBridgeHandler) clearState(statePath string) {
	_ = os.Remove(statePath)
}
