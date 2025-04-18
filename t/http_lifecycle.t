# Copyright 2022 Shenzhen ZhiLiu Technology Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
use t::WASM 'no_plan';

log_level('debug');
run_tests();

__DATA__

=== TEST 1: manage ctx
--- config
location /t {
    content_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local plugin = assert(wasm.load("plg1", "t/testdata/http_lifecycle/main.go.wasm"))
        local ctx = assert(wasm.on_configure(plugin, '{"body":512}'))
        assert(wasm.on_http_request_headers(ctx))
        assert(wasm.on_http_request_headers(ctx))
    }
}
--- grep_error_log eval
qr/plugin plg1 .* context 2 .*/
--- grep_error_log_out eval
qr/plugin plg1 create http context 2 consumed \d+
plugin plg1 http context 2 consumed \d+ during cleanup/



=== TEST 2: ensure plugin ctx is free after http ctx
--- config
location /t {
    content_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local plugin = assert(wasm.load("plg1", "t/testdata/http_lifecycle/main.go.wasm"))
        do
            local ctx = assert(wasm.on_configure(plugin, '{"body":512}'))
            assert(wasm.on_http_request_headers(ctx))
        end
        collectgarbage()
    }
}
--- grep_error_log eval
qr/plugin plg1 (http|context) .* (cleanup|lifetime)/
--- grep_error_log_out eval
qr/plugin plg1 http context 2 consumed \d+ during cleanup
plugin plg1 context 1 consumed \d+ during its lifetime/



=== TEST 3: multiple http ctx
--- http_config
    init_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local plugin = assert(wasm.load("plg1", "t/testdata/http_lifecycle/main.go.wasm"))
        package.loaded.ctx = assert(wasm.on_configure(plugin, '{"body":512}'))
    }
--- config
location /t {
    content_by_lua_block {
        local http = require "resty.http"
        local uri = "http://127.0.0.1:" .. ngx.var.server_port
                    .. "/hit"

        for _ = 1, 2 do
            local t = {}
            for i = 1, 9 do
                local th = assert(ngx.thread.spawn(function(i)
                    local httpc = http.new()
                    local res, err = httpc:request_uri(uri..i, {method = "GET"})
                    if not res then
                        ngx.log(ngx.ERR, err)
                        return
                    end
                end, i))
                table.insert(t, th)
            end
            for i, th in ipairs(t) do
                ngx.thread.wait(th)
            end
            -- check if the ctx id is reused
        end
    }
}
location /hit {
    content_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local ctx = package.loaded.ctx
        assert(wasm.on_http_request_headers(ctx))
        ngx.sleep(math.random() / 10)
    }
}
--- grep_error_log eval
qr/plugin plg1 http context (1|11) consumed \d+ during cleanup/
--- grep_error_log_out



=== TEST 4: multi plugin ctx in same req
--- config
location /t {
    content_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local plugin = assert(wasm.load("plugin", "t/testdata/http_lifecycle/main.go.wasm"))
        local ctx1 = assert(wasm.on_configure(plugin, '{"body":512}'))
        local ctx2 = assert(wasm.on_configure(plugin, '{"body":256}'))
        assert(wasm.on_http_request_headers(ctx1))
        assert(wasm.on_http_request_headers(ctx2))
    }
}
--- grep_error_log eval
qr/run http ctx \d+ with conf \S+ on http request headers,/
--- grep_error_log_out
run http ctx 3 with conf {"body":512} on http request headers,
run http ctx 4 with conf {"body":256} on http request headers,



=== TEST 5: multi plugin in same req
--- config
location /t {
    content_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local plugin1 = assert(wasm.load("plugin", "t/testdata/http_lifecycle/main.go.wasm"))
        local plugin2 = assert(wasm.load("plugin", "t/testdata/http_lifecycle/main.go.wasm"))
        local ctx1 = assert(wasm.on_configure(plugin1, '{"body":512}'))
        local ctx2 = assert(wasm.on_configure(plugin2, '{"body":256}'))
        assert(wasm.on_http_request_headers(ctx1))
        assert(wasm.on_http_request_headers(ctx2))
    }
}
--- grep_error_log eval
qr/run http ctx \d+ with conf \S+ on http request headers,/
--- grep_error_log_out
run http ctx 2 with conf {"body":512} on http request headers,
run http ctx 2 with conf {"body":256} on http request headers,



=== TEST 6: on response headers
--- config
location /t {
    content_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local plugin = assert(wasm.load("plugin", "t/testdata/http_lifecycle/main.go.wasm"))
        local ctx = assert(wasm.on_configure(plugin, '{"body":512}'))
        ngx.ctx.ctx = ctx
        assert(wasm.on_http_request_headers(ctx))
    }
    header_filter_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local ctx = ngx.ctx.ctx
        assert(wasm.on_http_response_headers(ctx))
    }
}
--- grep_error_log eval
qr/run http ctx \d+ with conf \S+ on [^,]+,/
--- grep_error_log_out
run http ctx 2 with conf {"body":512} on http request headers,
run http ctx 2 with conf {"body":512} on http response headers,



=== TEST 7: crash on response headers
--- config
location /t {
    content_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local plugin = assert(wasm.load("plugin", "t/testdata/http_lifecycle/main.go.wasm"))
        ngx.ctx.plugin = plugin
    }
    header_filter_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local plugin = ngx.ctx.plugin
        local ctx = assert(wasm.on_configure(plugin, 'panic_on_http_response_headers'))
        local ok, err = wasm.on_http_response_headers(ctx)
        ngx.log(ngx.ERR, err)
    }
}
--- error_log
failed to call function
failed to run proxy_on_http_response_headers



=== TEST 8: reuse plugin ctx id with freed http ctx
--- config
location /hit {
    content_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local ctx = package.loaded.ctx
        assert(wasm.on_http_request_headers(ctx))
    }
}
location /t {
    content_by_lua_block {
        local wasm = require("resty.proxy-wasm")
        local plugin = wasm.load("plg1", "t/testdata/http_lifecycle/main.go.wasm")
        local http = require "resty.http"
        local uri = "http://127.0.0.1:" .. ngx.var.server_port
                    .. "/hit"
        for i = 1, 2 do
            do
                local ctx = assert(wasm.on_configure(plugin, '{"body":512}'))
                package.loaded.ctx = ctx
                local httpc = http.new()
                local res, err = httpc:request_uri(uri)
                if not res then
                    ngx.log(ngx.ERR, err)
                    return
                end
                package.loaded.ctx = nil
            end
            collectgarbage()
        end
    }
}
--- grep_error_log eval
qr/(create )?plugin plg1 .*/
--- grep_error_log_out eval
qr/create plugin plg1 context 1 consumed \d+
plugin plg1 create http context 2 consumed \d+
plugin plg1 http context 2 consumed \d+ during cleanup
plugin plg1 context 1 consumed \d+ during its lifetime
create plugin plg1 context 1 consumed \d+
plugin plg1 create http context 3 consumed \d+
plugin plg1 http context 3 consumed \d+ during cleanup
plugin plg1 context 1 consumed \d+ during its lifetime
/
