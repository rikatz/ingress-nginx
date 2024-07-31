package crossplane

import (
	ngx_crossplane "github.com/nginxinc/nginx-go-crossplane"
	"k8s.io/ingress-nginx/internal/ingress/controller/config"
	utilingress "k8s.io/ingress-nginx/pkg/util/ingress"
)

func buildRedirectServerBlock(cfg config.TemplateConfig, redirect *utilingress.Redirect) *ngx_crossplane.Directive {
	serverDirectives := ngx_crossplane.Directives{
		buildDirective("server_name", redirect.From),
		buildBlockDirective("ssl_certificate_by_lua_block", nil, ngx_crossplane.Directives{buildDirective("certificate.call()")}),
	}
	serverDirectives = append(serverDirectives, listenDirectives(cfg, false, redirect.From)...)
	serverDirectives = append(serverDirectives, listenDirectives(cfg, true, redirect.From)...)

	return buildBlockDirective("server", nil, serverDirectives)
}
