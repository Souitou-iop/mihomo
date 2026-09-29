package route

import (
	"context"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

type tailscaleStatusProvider interface {
	TailscaleStatus(context.Context) (any, error)
}

func getTailscaleStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	for _, proxy := range tunnel.Proxies() {
		provider, ok := unwrapProxyAdapter(proxy.Adapter()).(tailscaleStatusProvider)
		if !ok {
			continue
		}
		status, err := provider.TailscaleStatus(ctx)
		if err != nil {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.JSON(w, r, status)
		return
	}
	render.Status(r, http.StatusNotFound)
	render.JSON(w, r, ErrNotFound)
}

// unwrapProxyAdapter 穿透 parser.go 施加在 outbound 外层的包装（autoClose / singMux）。
// 包装器内嵌接口而非具体类型，不穿透则对 *Tailscale 的方法断言永远失败。
func unwrapProxyAdapter(a C.ProxyAdapter) C.ProxyAdapter {
	for i := 0; i < 4; i++ {
		u, ok := a.(interface{ UnwrapProxyAdapter() C.ProxyAdapter })
		if !ok {
			return a
		}
		a = u.UnwrapProxyAdapter()
	}
	return a
}
