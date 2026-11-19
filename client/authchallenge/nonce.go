package authchallenge

import (
	"crypto/rand"
	"encoding/hex"
)

// newChallengeNonce 生成一轮挑战的随机标识。
//
// 用途：验证码答错后上游会重新发起挑战，服务在同一端口重启。
// 每轮 URL 带不同 nonce，才能做到两件事：
//   - 宿主浏览器每次都会新开标签页，而不是复用上一轮那个已失效的页面
//   - 旧标签页的提交因 nonce 不匹配被拒绝，不会把过期答案喂给新一轮
func newChallengeNonce() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand 失败时退回固定串：nonce 只用于区分轮次，
		// 不承担安全职责，失败不应阻断登录。
		return "fallback"
	}
	return hex.EncodeToString(buf)
}
