/*
 * Copyright 2022 Shenzhen ZhiLiu Technology Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <wasi.h>
#include <wasm.h>
#include <wasmtime.h>
#include <http/ngx_http_wasm_api_wasmtime.h>
#include "vm.h"

typedef struct {
    uint64_t    fuel_limit_call;
    uint64_t    fuel_limit_lifetime;
} ngx_wasm_wasmtime_resources_t;

typedef struct {
    wasm_engine_t                  *vm_engine;
    wasmtime_module_t              *module;
    wasmtime_store_t               *store;
    wasmtime_context_t             *context;
    wasmtime_linker_t              *linker;
    wasmtime_instance_t             instance;
    wasmtime_memory_t               memory;
    ngx_wasm_wasmtime_resources_t   limits;
} ngx_wasm_wasmtime_plugin_t;


static ngx_str_t      vm_name = ngx_string("wasmtime");
static wasmtime_val_t   param_int32[1] = {{ .kind = WASMTIME_I32 }};
static wasmtime_val_t   param_int32_int32[2] = {{ .kind = WASMTIME_I32 }, { .kind = WASMTIME_I32 }};
static wasmtime_val_t   param_int32_int32_int32[3] = {
    { .kind = WASMTIME_I32 }, { .kind = WASMTIME_I32 }, { .kind = WASMTIME_I32 },
};
static wasmtime_val_t   param_int32_int32_int32_int32[4] = {
    { .kind = WASMTIME_I32 }, { .kind = WASMTIME_I32 }, { .kind = WASMTIME_I32 },
    { .kind = WASMTIME_I32 },
};
static wasmtime_val_t   param_int32_int32_int32_int32_int32[5] = {
    { .kind = WASMTIME_I32 }, { .kind = WASMTIME_I32 }, { .kind = WASMTIME_I32 },
    { .kind = WASMTIME_I32 }, { .kind = WASMTIME_I32 },
};
static ngx_wasm_wasmtime_plugin_t *cur_plugin;


static wasm_functype_t *
ngx_http_wasmtime_host_api_func(const ngx_wasm_wasmtime_host_api_t *api)
{
    int                i;
    wasm_valtype_vec_t param_vec, result_vec;
    wasm_valtype_t    *param[MAX_WASM_API_ARG];
    wasm_valtype_t    *result[1];
    wasm_functype_t   *f;

    for (i = 0; i < api->param_num; i++) {
        param[i] = wasm_valtype_new(api->param_type[i]);
    }

    result[0] = wasm_valtype_new(WASM_I32);
    wasm_valtype_vec_new(&param_vec, api->param_num, param);
    wasm_valtype_vec_new(&result_vec, 1, result);

    f = wasm_functype_new(&param_vec, &result_vec);
    return f;
}


static ngx_int_t
ngx_wasm_wasmtime_report_error(ngx_log_t *log, const char *message,
    wasmtime_error_t *error, wasm_trap_t *trap)
{
    wasm_byte_vec_t         error_message;
    wasmtime_trap_code_t    code;

    if (error != NULL) {
        wasmtime_error_message(error, &error_message);
        wasmtime_error_delete(error);
    } else {
        if (wasmtime_trap_code(trap, &code)
            && code == WASMTIME_TRAP_CODE_OUT_OF_FUEL) {
            wasm_trap_delete(trap);
            ngx_log_error(NGX_LOG_WARN, log, 0, "%s%s",
                          message, "all fuel consumed");
            return NGX_ABORT;
        }

        wasm_trap_message(trap, &error_message);
        wasm_trap_delete(trap);
    }

    ngx_log_error(NGX_LOG_ERR, log, 0, "%s%*s",
                  message, error_message.size, error_message.data);
    wasm_byte_vec_delete(&error_message);

    return NGX_ERROR;
}


static ngx_int_t
ngx_wasm_wasmtime_init(void)
{
    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "init wasm vm: wasmtime");

    return NGX_OK;
}


static void
ngx_wasm_wasmtime_cleanup(void)
{
    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "cleanup wasm vm: wasmtime");
}


static ngx_int_t
ngx_wasm_wasmtime_update_fuel(ngx_wasm_wasmtime_plugin_t *plugin,
                              uint64_t *consumed, uint64_t *remaining) {
    bool                            fuel_enabled;
    uint64_t                        limit;
    wasmtime_context_t             *context = plugin->context;
    ngx_wasm_wasmtime_resources_t  *limits = &plugin->limits;

    fuel_enabled = wasmtime_context_fuel_consumed(context, consumed);
    if (!fuel_enabled) {
        return NGX_OK;
    }

    if (limits->fuel_limit_lifetime > 0
        && limits->fuel_limit_lifetime <= *consumed) {
        *remaining = 0;
        return NGX_ABORT;
    }

    // get how much is remaining in the context
    // TODO: replace this with remaining_fuel in Wasmtime 11
    wasmtime_context_consume_fuel(context, 0, remaining);

    if (limits->fuel_limit_call == 0) {
        return NGX_OK;
    }

    if (limits->fuel_limit_lifetime > 0) {
        limit = ngx_min(limits->fuel_limit_call,
                        limits->fuel_limit_lifetime - *consumed);
    } else {
        limit = limits->fuel_limit_call;
    }

    if (limit > *remaining) {
        wasmtime_context_add_fuel(context, limit - *remaining);
        *remaining = limit;
    } else if (limit < *remaining) {
        wasmtime_context_consume_fuel(context, *remaining - limit, remaining);
    }

    return NGX_OK;
}


static ngx_wasm_vm_resources_t
ngx_wasm_wasmtime_get_resources(void *data) {
    ngx_wasm_vm_resources_t     resources = { 0 };
    ngx_wasm_wasmtime_plugin_t *plugin = data;

    if (plugin == NULL || plugin->context == NULL) {
        return resources;
    }

    // TODO: once wasmtime supports more granular API, add memory limits & fuel left
    wasmtime_context_fuel_consumed(plugin->context, &resources.fuel_consumed);
    return resources;
}


static void *
ngx_wasm_wasmtime_load(const char *bytecode, size_t size, ngx_wasm_vm_limits_t *limits)
{
    bool                          ok;
    size_t                        i;
    wasm_trap_t                  *trap = NULL;
    wasi_config_t                *wasi_config;
    wasm_config_t                *config;
    wasm_engine_t                *vm_engine;
    wasmtime_error_t             *error;
    wasmtime_store_t             *store;
    wasmtime_extern_t             item;
    wasmtime_linker_t            *linker;
    wasmtime_module_t            *module;
    wasmtime_context_t           *context;
    ngx_wasm_wasmtime_plugin_t   *plugin;

    config = wasm_config_new();
    if (config == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "failed to create new config");
        return NULL;
    }

    if (limits != NULL && (limits->fuel_limit_call > 0
                           || limits->fuel_limit_lifetime > 0)) {
        wasmtime_config_consume_fuel_set(config, true);
    }

    vm_engine = wasm_engine_new_with_config(config);
    if (vm_engine == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "failed to create new engine");
        return NULL;
    }

    error = wasmtime_module_new(vm_engine, (const uint8_t*) bytecode,
                                size, &module);
    if (error != NULL) {
        ngx_wasm_wasmtime_report_error(ngx_cycle->log,
                                       "failed to create new module: ",
                                       error, NULL);
        goto free_engine;
    }

    store = wasmtime_store_new(vm_engine, NULL, NULL);
    if (store == NULL) {
        goto free_module;
    }

    context = wasmtime_store_context(store);
    if (limits != NULL) {
        if (limits->fuel_limit_call > 0) {
            wasmtime_context_add_fuel(context,limits->fuel_limit_call);
        } else if (limits->fuel_limit_lifetime > 0) {
            wasmtime_context_add_fuel(context,limits->fuel_limit_lifetime);
        }
    }

    wasi_config = wasi_config_new();
    if (wasi_config == NULL) {
        goto free_store;
    }

    wasi_config_inherit_env(wasi_config);
    wasi_config_inherit_stdin(wasi_config);
    wasi_config_inherit_stdout(wasi_config);
    wasi_config_inherit_stderr(wasi_config);

    error = wasmtime_context_set_wasi(context, wasi_config);
    if (error != NULL) {
        ngx_wasm_wasmtime_report_error(ngx_cycle->log,
                                       "failed to init WASI: ", error, NULL);
        goto free_store;
    }

    linker = wasmtime_linker_new(vm_engine);
    if (linker == NULL) {
        goto free_store;
    }

    error = wasmtime_linker_define_wasi(linker);
    if (error != NULL) {
        ngx_wasm_wasmtime_report_error(ngx_cycle->log,
                                       "failed to init WASI: ", error, NULL);
        goto free_linker;
    }

    for (i = 0; host_apis[i].name.len; i++) {
        ngx_wasm_wasmtime_host_api_t *api = &host_apis[i];
        wasm_functype_t     *f;

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "define wasm host API %V", &api->name);

        f = ngx_http_wasmtime_host_api_func(api);
        if (f == NULL) {
            goto free_linker;
        }

        error = wasmtime_linker_define_func(linker, "env", 3,
                                            (const char *) api->name.data,
                                            api->name.len, f,
                                            api->cb, NULL, NULL);
        wasm_functype_delete(f);

        if (error != NULL) {
            ngx_wasm_wasmtime_report_error(ngx_cycle->log,
                                           "failed to define API ",
                                           error, NULL);
            goto free_linker;
        }
    }

    plugin = ngx_alloc(sizeof(ngx_wasm_wasmtime_plugin_t), ngx_cycle->log);
    if (plugin == NULL) {
        goto free_linker;
    }

    error = wasmtime_linker_instantiate(linker, context, module,
                                        &plugin->instance, &trap);
    if (error != NULL) {
        ngx_wasm_wasmtime_report_error(ngx_cycle->log,
                                       "failed to new instance: ", error, NULL);
        goto free_plugin;
    }

    ok = wasmtime_instance_export_get(context, &plugin->instance,
                                      "memory", strlen("memory"), &item);
    if (!ok || item.kind != WASMTIME_EXTERN_MEMORY) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "the wasm plugin doesn't export memory");
        goto free_plugin;
    }
    plugin->memory = item.of.memory;


    plugin->vm_engine = vm_engine;
    plugin->module = module;
    plugin->store = store;
    plugin->context = context;
    plugin->linker = linker;
    if (limits != NULL) {
        plugin->limits.fuel_limit_call = limits->fuel_limit_call;
        plugin->limits.fuel_limit_lifetime = limits->fuel_limit_lifetime;
    } else {
        plugin->limits.fuel_limit_call = 0;
        plugin->limits.fuel_limit_lifetime = 0;
    }

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "wasmtime loaded plugin");

    return plugin;

free_plugin:
    ngx_free(plugin);

free_linker:
    wasmtime_linker_delete(linker);

free_store:
    wasmtime_store_delete(store);

free_module:
    wasmtime_module_delete(module);

free_engine:
    wasm_engine_delete(vm_engine);

    return NULL;
}


static void
ngx_wasm_wasmtime_unload(void *data)
{
    ngx_wasm_wasmtime_plugin_t *plugin = data;

    wasmtime_module_delete(plugin->module);
    wasmtime_store_delete(plugin->store);
    wasmtime_linker_delete(plugin->linker);
    wasm_engine_delete(plugin->vm_engine);

    ngx_free(plugin);

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "wasmtime unloaded plugin");
}


static ngx_int_t
ngx_wasm_wasmtime_call(void *data, ngx_str_t *name, bool has_result, int param_type, ...)
{
    bool                        found;
    size_t                      param_num = 0;
    va_list                     args;
    uint64_t                    fc, fct = 0, fr = 0;
    ngx_int_t                   rc;
    wasm_trap_t                *trap = NULL;
    wasmtime_val_t             *params = NULL;
    wasmtime_val_t              results[1];
    wasmtime_error_t           *error;
    wasmtime_extern_t           func;
    ngx_wasm_wasmtime_plugin_t *plugin = data;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "wasmtime call function %V", name);

    if (plugin == NULL) {
        plugin = cur_plugin;
    } else {
        cur_plugin = plugin;
    }

    found = wasmtime_instance_export_get(plugin->context, &plugin->instance,
                                         (const char *) name->data, name->len, &func);
    if (!found) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "wasmtime function %V not defined", name);
        return NGX_OK;
    }

    va_start(args, param_type);

    switch (param_type) {
    case NGX_WASM_PARAM_VOID:
        break;

    case NGX_WASM_PARAM_I32:
        params = param_int32;
        params[0].of.i32 = va_arg(args, int32_t);
        param_num = 1;
        break;

    case NGX_WASM_PARAM_I32_I32:
        params = param_int32_int32;
        params[0].of.i32 = va_arg(args, int32_t);
        params[1].of.i32 = va_arg(args, int32_t);
        param_num = 2;
        break;

    case NGX_WASM_PARAM_I32_I32_I32:
        params = param_int32_int32_int32;
        params[0].of.i32 = va_arg(args, int32_t);
        params[1].of.i32 = va_arg(args, int32_t);
        params[2].of.i32 = va_arg(args, int32_t);
        param_num = 3;
        break;

    case NGX_WASM_PARAM_I32_I32_I32_I32:
        params = param_int32_int32_int32_int32;
        params[0].of.i32 = va_arg(args, int32_t);
        params[1].of.i32 = va_arg(args, int32_t);
        params[2].of.i32 = va_arg(args, int32_t);
        params[3].of.i32 = va_arg(args, int32_t);
        param_num = 4;
        break;

    case NGX_WASM_PARAM_I32_I32_I32_I32_I32:
        params = param_int32_int32_int32_int32_int32;
        params[0].of.i32 = va_arg(args, int32_t);
        params[1].of.i32 = va_arg(args, int32_t);
        params[2].of.i32 = va_arg(args, int32_t);
        params[3].of.i32 = va_arg(args, int32_t);
        params[4].of.i32 = va_arg(args, int32_t);
        param_num = 5;
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "unknown param type: %d", param_type);
        va_end(args);
        return NGX_ERROR;
    }

    va_end(args);

    rc = ngx_wasm_wasmtime_update_fuel(plugin, &fct, &fr);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "not enough resources to execute, consumed [%L/%L]",
                      fct, plugin->limits.fuel_limit_lifetime);
        return rc;
    }
    fc = fct;

    error = wasmtime_func_call(plugin->context, &func.of.func,
                               params, param_num, results,
                               has_result ? 1 : 0, &trap);

    ngx_wasm_wasmtime_update_fuel(plugin, &fct, &fr);
    fc = fct - fc;

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                  "%V%s consumed [%L/%L], total [%L/%L]",
                  name, (error != NULL || trap != NULL) ? " failed" : "",
                  fc, plugin->limits.fuel_limit_call, fct,
                  plugin->limits.fuel_limit_lifetime);

    if (error != NULL || trap != NULL) {
        return ngx_wasm_wasmtime_report_error(ngx_cycle->log,
                                              "failed to call function: ",
                                              error, trap);
    }

    if (!has_result) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "wasmtime call function done");
        return NGX_OK;
    }

    if (results[0].kind != WASMTIME_I32) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "function returns unexpected type: %d",
                      results[0].kind);
        return NGX_ERROR;
    }

    rc = results[0].of.i32;
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "wasmtime call function result: %d", rc);

    return rc;
}


static bool
ngx_wasm_wasmtime_has(void *data, ngx_str_t *name)
{
    ngx_wasm_wasmtime_plugin_t *plugin = data;
    wasmtime_extern_t           func;

    return wasmtime_instance_export_get(plugin->context,
                                        &plugin->instance,
                                        (const char *) name->data,
                                        name->len, &func);
}


u_char *
ngx_wasm_wasmtime_get_memory(ngx_log_t *log, int32_t addr, int32_t size)
{
    size_t bound;

    bound = wasmtime_memory_data_size(cur_plugin->context, &cur_plugin->memory);
    if (bound < (size_t) (addr + size)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "access memory addr %d with size %d, but the max addr is %z",
                      addr, size, bound);
        return NULL;
    }

    return wasmtime_memory_data(cur_plugin->context, &cur_plugin->memory) + addr;
}


ngx_wasm_vm_t ngx_wasm_wasmtime_vm = {
    &vm_name,
    ngx_wasm_wasmtime_init,
    ngx_wasm_wasmtime_cleanup,
    ngx_wasm_wasmtime_load,
    ngx_wasm_wasmtime_unload,
    ngx_wasm_wasmtime_get_resources,
    ngx_wasm_wasmtime_get_memory,
    ngx_wasm_wasmtime_call,
    ngx_wasm_wasmtime_has,
};
