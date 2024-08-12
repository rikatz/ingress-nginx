package crossplane

import (
	"fmt"
	"strings"

	ngx_crossplane "github.com/nginxinc/nginx-go-crossplane"
	"k8s.io/ingress-nginx/internal/ingress/controller/config"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
	utilingress "k8s.io/ingress-nginx/pkg/util/ingress"
)

const useForwardedHeaders = `local redirectScheme
if not ngx.var.http_x_forwarded_proto then
  redirectScheme = ngx.var.scheme
else
  redirectScheme = ngx.var.http_x_forwarded_proto
end
`

const nonForwardedHeaders = `local redirectScheme = ngx.var.scheme`

const redirectBlock = `local request_uri = ngx.var.request_uri
if string.sub(request_uri, -1) == "/" then
  request_uri = string.sub(request_uri, 1, -2)
  end
%s
return string.format("%%s://%s:%d%%s", redirectScheme, request_uri)`

func buildRedirectServerBlock(cfg *config.TemplateConfig, redirect *utilingress.Redirect) *ngx_crossplane.Directive {
	serverDirectives := ngx_crossplane.Directives{
		buildDirective("server_name", redirect.From),
		buildBlockDirective("ssl_certificate_by_lua_block", nil, ngx_crossplane.Directives{buildDirective("certificate.call()")}),
	}
	serverDirectives = append(serverDirectives, listenDirectives(*cfg, false, redirect.From)...)
	serverDirectives = append(serverDirectives, listenDirectives(*cfg, true, redirect.From)...)

	if len(cfg.Cfg.BlockUserAgents) > 0 {
		serverDirectives = append(serverDirectives, buildBlockDirective(
			"if",
			[]string{"$block_ua"},
			ngx_crossplane.Directives{buildDirective("return", 403)}))
	}

	if len(cfg.Cfg.BlockReferers) > 0 {
		serverDirectives = append(serverDirectives, buildBlockDirective(
			"if",
			[]string{"$block_ref"},
			ngx_crossplane.Directives{buildDirective("return", 403)}))
	}

	forwardHeaders := nonForwardedHeaders
	if cfg.Cfg.UseForwardedHeaders {
		forwardHeaders = useForwardedHeaders
	}

	luaBlock := buildBlockDirective("set_by_lua_block",
		[]string{"$redirect_to"},
		ngx_crossplane.Directives{
			buildDirective(fmt.Sprintf(redirectBlock,
				forwardHeaders,
				redirect.To,
				cfg.ListenPorts.HTTP)),
		})

	serverDirectives = append(serverDirectives, luaBlock)
	// TODO: Add the lua block
	serverDirectives = append(serverDirectives, buildDirective("return", cfg.Cfg.HTTPRedirectCode, "$redirect_to"))
	return buildBlockDirective("server", nil, serverDirectives)
}

func buildServerBlock(cfg *config.TemplateConfig, server *ingress.Server) *ngx_crossplane.Directive {
	serverBlock := ngx_crossplane.Directives{
		buildDirective("server_name", buildServerName(server.Hostname), server.Aliases),
	}

	serverBlock = append(serverBlock, buildDirective("http2", cfg.Cfg.UseHTTP2))

	if len(cfg.Cfg.BlockUserAgents) > 0 {
		serverBlock = append(serverBlock, buildBlockDirective(
			"if",
			[]string{"$block_ua"},
			ngx_crossplane.Directives{buildDirective("return", 403)}))
	}

	if len(cfg.Cfg.BlockReferers) > 0 {
		serverBlock = append(serverBlock, buildBlockDirective(
			"if",
			[]string{"$block_ref"},
			ngx_crossplane.Directives{buildDirective("return", 403)}))
	}

	// TODO:  (rikatz) Add Server Template
	buildCustomError(buildCustomErrorDeps("upstream-default-backend", cfg.Cfg.CustomHTTPErrors, cfg.EnableMetrics), serverBlock)

	return buildBlockDirective("server", nil, serverBlock)
}

func buildCustomError(customError customError, block ngx_crossplane.Directives) {
	for _, errorCode := range customError.ErrorCodes {
		locationBlock := ngx_crossplane.Directives{
			buildDirective("internal"),
			buildDirective("proxy_intercept_errors", "off"),
			buildDirective("proxy_set_header", "X-Code", errorCode),
			buildDirective("proxy_set_header", "X-Format", "$http_accept"),
			buildDirective("proxy_set_header", "X-Original-URI", "$request_uri"),
			buildDirective("proxy_set_header", "X-Namespace", "$namespace"),
			buildDirective("proxy_set_header", "X-Ingress-Name", "$ingress_name"),
			buildDirective("proxy_set_header", "X-Service-Name", "$service_name"),
			buildDirective("proxy_set_header", "X-Service-Port", "$service_port"),
			buildDirective("proxy_set_header", "X-Request-ID", "$req_id"),
			buildDirective("proxy_set_header", "X-Forwarded-For", "$remote_addr"),
			buildDirective("proxy_set_header", "Host", "$best_http_host"),
			buildDirective("set", "$proxy_upstream_name", customError.UpstreamName),
			buildDirective("rewrite", "(.*)", "/", "break"),
			buildDirective("proxy_pass", "http://upstream_balancer"),
		}
		if customError.EnableMetrics {
			locationBlock = append(locationBlock, buildBlockDirective("log_by_lua_block", nil, ngx_crossplane.Directives{
				buildDirective("monitor.call()"),
			}))
		}
		locationName := fmt.Sprintf("@custom_%s_%d", customError.UpstreamName, errorCode)
		block = append(block, buildBlockDirective("location", []string{locationName}, locationBlock))
	}
}

func buildServerName(hostname string) string {
	if !strings.HasPrefix(hostname, "*") {
		return hostname
	}

	hostname = strings.Replace(hostname, "*.", "", 1)
	parts := strings.Split(hostname, ".")

	return `~^(?<subdomain>[\w-]+)\.` + strings.Join(parts, "\\.") + `$`
}
