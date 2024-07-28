/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package crossplane

import (
	"fmt"
	"strconv"
	"strings"

	ngx_crossplane "github.com/nginxinc/nginx-go-crossplane"
)

func (c *Template) initHTTPDirectives() ngx_crossplane.Directives {
	cfg := c.tplConfig.Cfg
	httpBlock := ngx_crossplane.Directives{
		buildDirective("lua_package_path", "/etc/nginx/lua/?.lua;;"),
		buildDirective("include", c.mimeFile),
		buildDirective("default_type", cfg.DefaultType),
		buildDirective("real_ip_recursive", "on"),
		buildDirective("aio", "threads"),
		buildDirective("aio_write", cfg.EnableAioWrite),
		buildDirective("server_tokens", cfg.ShowServerTokens),
		buildDirective("resolver", buildResolversInternal(cfg.Resolver, cfg.DisableIpv6DNS)),
		buildDirective("tcp_nopush", "on"),
		buildDirective("tcp_nodelay", "on"),
		buildDirective("log_subrequest", "on"),
		buildDirective("reset_timedout_connection", "on"),
		buildDirective("keepalive_timeout", seconds(cfg.KeepAlive)),
		buildDirective("keepalive_requests", cfg.KeepAliveRequests),
		buildDirective("client_body_temp_path", "/tmp/nginx/client-body"),
		buildDirective("fastcgi_temp_path", "/tmp/nginx/fastcgi-temp"),
		buildDirective("proxy_temp_path", "/tmp/nginx/proxy-temp"),
		buildDirective("client_header_buffer_size", cfg.ClientHeaderBufferSize),
		buildDirective("client_header_timeout", seconds(cfg.ClientHeaderTimeout)),
		buildDirective("large_client_header_buffers", strings.Split(cfg.LargeClientHeaderBuffers, " ")),
		buildDirective("client_body_buffer_size", cfg.ClientBodyBufferSize),
		buildDirective("client_body_timeout", seconds(cfg.ClientBodyTimeout)),
		buildDirective("types_hash_max_size", "2048"),
		buildDirective("server_names_hash_max_size", cfg.ServerNameHashMaxSize),
		buildDirective("server_names_hash_bucket_size", cfg.ServerNameHashBucketSize),
		buildDirective("map_hash_bucket_size", cfg.MapHashBucketSize),
		buildDirective("proxy_headers_hash_max_size", cfg.ProxyHeadersHashMaxSize),
		buildDirective("proxy_headers_hash_bucket_size", cfg.ProxyHeadersHashBucketSize),
		buildDirective("variables_hash_bucket_size", cfg.VariablesHashBucketSize),
		buildDirective("variables_hash_max_size", cfg.VariablesHashMaxSize),
		buildDirective("underscores_in_headers", cfg.EnableUnderscoresInHeaders),
		buildDirective("ignore_invalid_headers", cfg.IgnoreInvalidHeaders),
		buildDirective("limit_req_status", cfg.LimitReqStatusCode),
		buildDirective("limit_conn_status", cfg.LimitConnStatusCode),
		buildDirective("uninitialized_variable_warn", "off"),
		buildDirective("server_name_in_redirect", "off"),
		buildDirective("port_in_redirect", "off"),
		buildDirective("http2_max_concurrent_streams", cfg.HTTP2MaxConcurrentStreams),
		buildDirective("ssl_protocols", strings.Split(cfg.SSLProtocols, " ")),
		buildDirective("ssl_early_data", cfg.SSLEarlyData),
		buildDirective("ssl_session_tickets", cfg.SSLSessionTickets),
		buildDirective("ssl_buffer_size", cfg.SSLBufferSize),
		buildDirective("ssl_ecdh_curve", cfg.SSLECDHCurve),
		buildDirective("ssl_certificate", cfg.DefaultSSLCertificate.PemFileName),
		buildDirective("ssl_certificate_key", cfg.DefaultSSLCertificate.PemFileName),
		buildDirective("proxy_ssl_session_reuse", "on"),
		buildDirective("proxy_cache_path", []string{
			"/tmp/nginx/nginx-cache-auth", "levels=1:2", "keys_zone=auth_cache:10m",
			"max_size=128m", "inactive=30m", "use_temp_path=off",
		}),
	}
	return httpBlock
}

func (c *Template) buildHTTP() {
	cfg := c.tplConfig.Cfg
	httpBlock := c.initHTTPDirectives()
	httpBlock = append(httpBlock, buildLuaSharedDictionaries(&c.tplConfig.Cfg)...)

	// Real IP dealing
	if (cfg.UseForwardedHeaders || cfg.UseProxyProtocol) || cfg.EnableRealIP {
		if cfg.UseProxyProtocol {
			httpBlock = append(httpBlock, buildDirective("real_ip_header", "proxy_protocol"))
		} else {
			httpBlock = append(httpBlock, buildDirective("real_ip_header", cfg.ForwardedForHeader))
		}

		for k := range cfg.ProxyRealIPCIDR {
			httpBlock = append(httpBlock, buildDirective("set_real_ip_from", cfg.ProxyRealIPCIDR[k]))
		}
	}

	if cfg.GRPCBufferSizeKb > 0 {
		httpBlock = append(httpBlock, buildDirective("grpc_buffer_size", strconv.Itoa(cfg.GRPCBufferSizeKb)+"k"))
	}

	// HTTP2 Configuration
	if cfg.HTTP2MaxHeaderSize != "" && cfg.HTTP2MaxFieldSize != "" {
		httpBlock = append(httpBlock, buildDirective("http2_max_field_size", cfg.HTTP2MaxFieldSize))
		httpBlock = append(httpBlock, buildDirective("http2_max_header_size", cfg.HTTP2MaxHeaderSize))
	}

	if cfg.HTTP2MaxRequests > 0 {
		httpBlock = append(httpBlock, buildDirective("http2_max_requests", cfg.HTTP2MaxRequests))
	}

	if cfg.UseGzip {
		httpBlock = append(httpBlock, buildDirective("gzip", "on"))
		httpBlock = append(httpBlock, buildDirective("gzip_comp_level", cfg.GzipLevel))
		httpBlock = append(httpBlock, buildDirective("gzip_http_version", "1.1"))
		httpBlock = append(httpBlock, buildDirective("gzip_min_length", cfg.GzipMinLength))
		httpBlock = append(httpBlock, buildDirective("gzip_types", cfg.GzipTypes))
		httpBlock = append(httpBlock, buildDirective("gzip_proxied", "any"))
		httpBlock = append(httpBlock, buildDirective("gzip_vary", "on"))

		if cfg.GzipDisable != "" {
			httpBlock = append(httpBlock, buildDirective("gzip_disable", strings.Split(cfg.GzipDisable, " ")))
		}
	}

	if !cfg.ShowServerTokens {
		httpBlock = append(httpBlock, buildDirective("more_clear_headers", "Server"))
	}

	if len(c.tplConfig.AddHeaders) > 0 {
		additionalHeaders := make([]string, 0)
		for headerName, headerValue := range c.tplConfig.AddHeaders {
			additionalHeaders = append(additionalHeaders, fmt.Sprintf("%s: %s", headerName, headerValue))
		}
		httpBlock = append(httpBlock, buildDirective("more_set_headers", additionalHeaders))
	}

	escape := ""
	if cfg.LogFormatEscapeNone {
		escape = "escape=none"
	} else if cfg.LogFormatEscapeJSON {
		escape = "escape=json"
	}

	httpBlock = append(httpBlock, buildDirective("log_format", "upstreaminfo", escape, cfg.LogFormatUpstream))

	loggableMap := make(ngx_crossplane.Directives, 0)
	for k := range cfg.SkipAccessLogURLs {
		loggableMap = append(loggableMap, buildDirective(cfg.SkipAccessLogURLs[k], "0"))
	}
	loggableMap = append(loggableMap, buildDirective("default", "1"))
	httpBlock = append(httpBlock, buildMapDirective("$request_uri", "$loggable", loggableMap))

	if cfg.DisableAccessLog || cfg.DisableHTTPAccessLog {
		httpBlock = append(httpBlock, buildDirective("access_log", "off"))
	} else {
		logDirectives := []string{"upstreaminfo", "if=$loggable"}
		if cfg.EnableSyslog {
			httpBlock = append(httpBlock, buildDirective("access_log", fmt.Sprintf("syslog:server%s:%d", cfg.SyslogHost, cfg.SyslogPort), logDirectives))
		} else {
			accessLog := cfg.AccessLogPath
			if cfg.HTTPAccessLogPath != "" {
				accessLog = cfg.HTTPAccessLogPath
			}
			httpBlock = append(httpBlock, buildDirective("access_log", accessLog, logDirectives))
		}
	}

	if cfg.EnableSyslog {
		httpBlock = append(httpBlock, buildDirective("error_log", fmt.Sprintf("syslog:server%s:%d", cfg.SyslogHost, cfg.SyslogPort), cfg.ErrorLogLevel))
	} else {
		httpBlock = append(httpBlock, buildDirective("error_log", cfg.ErrorLogPath, cfg.ErrorLogLevel))
	}

	if cfg.SSLSessionCache {
		httpBlock = append(httpBlock,
			buildDirective("ssl_session_cache", fmt.Sprintf("shared:SSL:%s", cfg.SSLSessionCacheSize)),
			buildDirective("ssl_session_timeout", cfg.SSLSessionTimeout),
		)
	}

	if cfg.SSLSessionTicketKey != "" {
		httpBlock = append(httpBlock, buildDirective("ssl_session_ticket_key", "/etc/ingress-controller/tickets.key"))
	}

	if cfg.SSLCiphers != "" {
		httpBlock = append(httpBlock,
			buildDirective("ssl_ciphers", cfg.SSLCiphers),
			buildDirective("ssl_prefer_server_ciphers", "on"),
		)
	}

	if cfg.SSLDHParam != "" {
		httpBlock = append(httpBlock, buildDirective("ssl_dhparam", cfg.SSLDHParam))
	}

	if len(cfg.CustomHTTPErrors) > 0 && !cfg.DisableProxyInterceptErrors {
		httpBlock = append(httpBlock, buildDirective("proxy_intercept_errors", "on"))
	}

	httpUpgradeMap := ngx_crossplane.Directives{buildDirective("default", "upgrade")}
	if cfg.UpstreamKeepaliveConnections < 1 {
		httpUpgradeMap = append(httpUpgradeMap, buildDirective("", "close"))
	}
	httpBlock = append(httpBlock, buildMapDirective("$http_upgrade", "$connection_upgrade", httpUpgradeMap))

	reqIDMap := ngx_crossplane.Directives{buildDirective("default", "$http_x_request_id")}
	if cfg.GenerateRequestID {
		reqIDMap = append(reqIDMap, buildDirective("", "$request_id"))
	}
	httpBlock = append(httpBlock, buildMapDirective("$http_x_request_id", "$req_id", reqIDMap))

	if cfg.UseForwardedHeaders && cfg.ComputeFullForwardedFor {
		forwardForMap := make(ngx_crossplane.Directives, 0)
		if cfg.UseProxyProtocol {
			forwardForMap = append(forwardForMap,
				buildDirective("default", "$http_x_forwarded_for, $proxy_protocol_addr"),
				buildDirective("", "$http_x_forwarded_for, $proxy_protocol_addr"),
			)
		} else {
			forwardForMap = append(forwardForMap,
				buildDirective("default", "$http_x_forwarded_for, $realip_remote_addr"),
				buildDirective("", "$realip_remote_addr"),
			)
		}
		httpBlock = append(httpBlock, buildMapDirective("$http_x_forwarded_for", "$full_x_forwarded_for", forwardForMap))
	}

	if cfg.AllowBackendServerHeader {
		httpBlock = append(httpBlock, buildDirective("proxy_pass_header", "Server"))
	}

	if cfg.EnableBrotli {
		httpBlock = append(httpBlock,
			buildDirective("brotli", "on"),
			buildDirective("brotli_comp_level", cfg.BrotliLevel),
			buildDirective("brotli_min_length", cfg.BrotliMinLength),
			buildDirective("brotli_types", strings.Split(cfg.BrotliTypes, " ")),
		)
	}

	if len(cfg.HideHeaders) > 0 {
		for k := range cfg.HideHeaders {
			httpBlock = append(httpBlock, buildDirective("proxy_hide_header", cfg.HideHeaders[k]))
		}
	}

	blockUpstreamDirectives := ngx_crossplane.Directives{
		buildDirective("server", "0.0.0.1"),
		buildBlockDirective("balancer_by_lua_block", nil, ngx_crossplane.Directives{buildDirective("balancer.balance()")}),
	}
	if c.tplConfig.Cfg.UpstreamKeepaliveConnections > 0 {
		blockUpstreamDirectives = append(blockUpstreamDirectives,
			buildDirective("keepalive", c.tplConfig.Cfg.UpstreamKeepaliveConnections),
			buildDirective("keepalive_time", c.tplConfig.Cfg.UpstreamKeepaliveTime),
			buildDirective("keepalive_timeout", seconds(c.tplConfig.Cfg.UpstreamKeepaliveTimeout)),
			buildDirective("keepalive_requests", c.tplConfig.Cfg.UpstreamKeepaliveRequests),
		)
	}
	httpBlock = append(httpBlock, buildBlockDirective("upstream", []string{"upstream_balancer"}, blockUpstreamDirectives))

	for i := range cfg.BlockCIDRs {
		httpBlock = append(httpBlock, buildDirective("deny", strings.TrimSpace(cfg.BlockCIDRs[i])))
	}

	if len(cfg.BlockUserAgents) > 0 {
		uaDirectives := ngx_crossplane.Directives{buildDirective("default", 0)}
		for i := range cfg.BlockUserAgents {
			uaDirectives = append(uaDirectives, buildDirective(strings.TrimSpace(cfg.BlockUserAgents[i]), 1))
		}
		httpBlock = append(httpBlock, buildMapDirective("$http_user_agent", "$block_ua", uaDirectives))
	}

	c.config.Parsed = append(c.config.Parsed, &ngx_crossplane.Directive{
		Directive: "http",
		Block:     httpBlock,
	})
}
