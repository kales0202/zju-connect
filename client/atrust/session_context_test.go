package atrust

import (
	"context"
	"errors"
	"testing"
	"time"
)

// SetupContext 返回时会 defer 取消 setupCtx。
// 会话若绑定在 setupCtx 上，则 Setup 之后的每一次会话刷新都会立刻收到
// context canceled——表现为日志里每分钟一条
// "aTrust authConfig refresh failed: ... context canceled"，
// 而会话永远不会真正被维护。
func TestSessionContextOutlivesSetup(t *testing.T) {
	client := NewClient(ClientOptions{})

	setupCtx, cancelSetup := context.WithCancel(context.Background())
	sessCtx, detach := client.newSessionContext(setupCtx)

	detach()      // setup 正常结束：解除联动
	cancelSetup() // SetupContext 的 defer cancelSetup()

	if err := sessCtx.Err(); err != nil {
		t.Fatalf("setup 结束后会话上下文不应被取消，实际: %v", err)
	}
}

// 反向契约：setup 阶段被取消时，进行中的登录请求必须能中止。
func TestSessionContextAbortsWithSetup(t *testing.T) {
	client := NewClient(ClientOptions{})

	setupCtx, cancelSetup := context.WithCancel(context.Background())
	sessCtx, detach := client.newSessionContext(setupCtx)
	defer detach()

	cancelSetup()

	select {
	case <-sessCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("setup 被取消后会话上下文应当结束")
	}
	if !errors.Is(sessCtx.Err(), context.Canceled) {
		t.Fatalf("会话上下文错误 = %v, want context.Canceled", sessCtx.Err())
	}
}

// 客户端关闭时会话上下文必须结束，否则刷新协程无法退出。
func TestSessionContextCanceledOnClientClose(t *testing.T) {
	client := NewClient(ClientOptions{})

	sessCtx, detach := client.newSessionContext(context.Background())
	detach()

	client.Close()

	select {
	case <-sessCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("客户端关闭后会话上下文应当结束")
	}
}
