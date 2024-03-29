/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/*
 * Apache module to implement RFC3744 WebDav Access Control Protocol.
 *
 *  Author: Graham Leggett
 *
 * DavAccessPrincipalUrl /dav/principals/%{escape:%{REMOTE_USER}}
 *
 */
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_escape.h>

#include "ap_expr.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"

#include "mod_dav.h"

module AP_MODULE_DECLARE_DATA dav_access_module;

typedef struct
{
    unsigned int dav_access_set :1;
    unsigned int dav_access_principal_set :1;
    unsigned int priviledge_set :1;
    unsigned int principal_url_set :1;
    ap_expr_info_t *principal_url;
    const char *priviledge;
    int dav_access;
    int dav_access_principal;
} dav_access_config_rec;

/* forward-declare the hook structures */
static const dav_hooks_liveprop dav_hooks_liveprop_access;

#define DAV_XML_NAMESPACE "DAV:"

/*
** The namespace URIs that we use. This list and the enumeration must
** stay in sync.
*/
static const char * const dav_access_namespace_uris[] =
{
    DAV_XML_NAMESPACE,

    NULL        /* sentinel */
};
enum {
    DAV_ACCESS_URI_DAV            /* the DAV: namespace URI */
};

enum {
    DAV_ACCESS_PROPID_acl = 1,
    DAV_ACCESS_PROPID_acl_restrictions,
    DAV_ACCESS_PROPID_alternate_uri_set,
    DAV_ACCESS_PROPID_current_user_principal,
    DAV_ACCESS_PROPID_current_user_privilege_set,
    DAV_ACCESS_PROPID_group,
    DAV_ACCESS_PROPID_group_membership,
    DAV_ACCESS_PROPID_group_member_set,
    DAV_ACCESS_PROPID_inherited_acl_set,
    DAV_ACCESS_PROPID_owner,
    DAV_ACCESS_PROPID_principal_collection_set,
    DAV_ACCESS_PROPID_principal_url,
    DAV_ACCESS_PROPID_supported_privilege_set
};

static const dav_liveprop_spec dav_access_props[] =
{
    /* standard acl properties */
    {
        DAV_ACCESS_URI_DAV,
        "acl",
        DAV_ACCESS_PROPID_acl,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "acl-restrictions",
        DAV_ACCESS_PROPID_acl_restrictions,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "alternate-URI-set",
        DAV_ACCESS_PROPID_alternate_uri_set,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "current-user-principal",
        DAV_ACCESS_PROPID_current_user_principal,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "current-user-privilege-set",
        DAV_ACCESS_PROPID_current_user_privilege_set,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "group",
        DAV_ACCESS_PROPID_group,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "group-membership",
        DAV_ACCESS_PROPID_group_membership,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "group-member-set",
        DAV_ACCESS_PROPID_group_member_set,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "inherited-acl-set",
        DAV_ACCESS_PROPID_inherited_acl_set,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "owner",
        DAV_ACCESS_PROPID_owner,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "principal-collection-set",
        DAV_ACCESS_PROPID_principal_collection_set,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "principal-URL",
        DAV_ACCESS_PROPID_principal_url,
        0
    },
    {
        DAV_ACCESS_URI_DAV,
        "supported-privilege-set",
        DAV_ACCESS_PROPID_supported_privilege_set,
        0
    },

    { 0 }        /* sentinel */
};

static const dav_liveprop_group dav_access_liveprop_group =
{
    dav_access_props,
    dav_access_namespace_uris,
    &dav_hooks_liveprop_access
};

static const char *dav_access_principal(request_rec *r)
{
    dav_access_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                &dav_access_module);

    if (r->user && conf->principal_url) {
        const char *err = NULL, *url;

        url = ap_expr_str_exec(r, conf->principal_url, &err);
        if (err) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                            "Failure while evaluating the principal URL expression for '%s', "
                            "no principal URL returned: %s", r->uri, err);
            return NULL;
        }

        return url;
    }

    return NULL;
}

static const char *dav_access_current_user_privilege_set(const dav_resource *resource)
{
    request_rec *r = resource->hooks->get_request_rec(resource);

    dav_access_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                &dav_access_module);

    /* for now, people are allowed */
    if (conf->priviledge) {
        return "<D:privilege><D:read/></D:privilege><D:privilege><D:write/></D:privilege><D:privilege><D:bind/></D:privilege><D:privilege><D:unbind/></D:privilege>";
    }

    return NULL;
}

static const char *dav_access_current_user_principal(const dav_resource *resource)
{
    request_rec *r = resource->hooks->get_request_rec(resource);

    return dav_access_principal(r);
}

static dav_prop_insert dav_access_insert_prop(const dav_resource *resource,
        int propid, dav_prop_insert what, apr_text_header *phdr)
{
    const char *value;
    const char *s;
    apr_pool_t *p = resource->pool;
    const dav_liveprop_spec *info;
    int global_ns;

    switch (propid) {
    case DAV_ACCESS_PROPID_principal_url:

        value = dav_access_current_user_principal(resource);
        if (value)
            value = apr_psprintf(p, "<D:href>%s</D:href>",
                    apr_pescape_entity(p, value, 1));
        else
            return DAV_PROP_INSERT_NOTDEF;
        break;

    case DAV_ACCESS_PROPID_current_user_principal:

        value = dav_access_current_user_principal(resource);
        if (value)
            value = apr_psprintf(p, "<D:href>%s</D:href>",
                    apr_pescape_entity(p, value, 1));
        else
            value = "<D:unauthenticated/>";
        break;

    case DAV_ACCESS_PROPID_current_user_privilege_set:

        value = dav_access_current_user_privilege_set(resource);
        if (!value) {
            return DAV_PROP_INSERT_NOTDEF;
        }
        break;

    default:
        /* ### what the heck was this property? */
        return DAV_PROP_INSERT_NOTDEF;
    }

    /* assert: value != NULL */

    /* get the information and global NS index for the property */
    global_ns = dav_get_liveprop_info(propid, &dav_access_liveprop_group, &info);

    /* assert: info != NULL && info->name != NULL */

    if (what == DAV_PROP_INSERT_VALUE) {
        s = apr_psprintf(p, "<lp%d:%s>%s</lp%d:%s>" DEBUG_CR,
                         global_ns, info->name, value, global_ns, info->name);
    }
    else if (what == DAV_PROP_INSERT_NAME) {
        s = apr_psprintf(p, "<lp%d:%s/>" DEBUG_CR, global_ns, info->name);
    }
    else {
        /* assert: what == DAV_PROP_INSERT_SUPPORTED */
        s = apr_pstrcat(p,
                        "<D:supported-live-property D:name=\"",
                        info->name,
                        "\" D:namespace=\"",
                        dav_access_namespace_uris[info->ns],
                        "\"/>" DEBUG_CR, NULL);
    }
    apr_text_append(p, phdr, s);

    /* we inserted what was asked for */
    return what;
}

static int dav_access_is_writable(const dav_resource *resource, int propid)
{
    const dav_liveprop_spec *info;

    (void) dav_get_liveprop_info(propid, &dav_access_liveprop_group, &info);
    return info->is_writable;
}

static dav_error *dav_access_patch_validate(const dav_resource *resource,
    const apr_xml_elem *elem, int operation, void **context, int *defer_to_dead)
{
    /* We have no writable properties */
    return NULL;
}

static dav_error *dav_access_patch_exec(const dav_resource *resource,
    const apr_xml_elem *elem, int operation, void *context,
    dav_liveprop_rollback **rollback_ctx)
{
    /* We have no writable properties */
    return NULL;
}

static void dav_access_patch_commit(const dav_resource *resource, int operation,
    void *context, dav_liveprop_rollback *rollback_ctx)
{
    /* We have no writable properties */
}

static dav_error *dav_access_patch_rollback(const dav_resource *resource,
    int operation, void *context, dav_liveprop_rollback *rollback_ctx)
{
    /* We have no writable properties */
    return NULL;
}

static const dav_hooks_liveprop dav_hooks_liveprop_access =
{
    dav_access_insert_prop,
    dav_access_is_writable,
    dav_access_namespace_uris,
    dav_access_patch_validate,
    dav_access_patch_exec,
    dav_access_patch_commit,
    dav_access_patch_rollback
};

static int dav_access_find_liveprop(const dav_resource *resource,
    const char *ns_uri, const char *name, const dav_hooks_liveprop **hooks)
{
    return dav_do_find_liveprop(ns_uri, name, &dav_access_liveprop_group, hooks);
}

static dav_error *dav_access_options_header(request_rec *r,
        const dav_resource *resource, apr_text_header *phdr)
{
    dav_access_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &dav_access_module);

    if (conf && conf->dav_access) {
        apr_text_append(r->pool, phdr, "access-control");
    }

    return NULL;
}

static dav_error *dav_access_options_method(request_rec *r,
        const dav_resource *resource, apr_text_header *phdr)
{
    dav_access_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &dav_access_module);

    if (conf && conf->dav_access) {
        // apr_text_append(r->pool, phdr, "ACL");
        // apr_text_append(r->pool, phdr, "REPORT");
    }

    return NULL;
}

static dav_options_provider options =
{
    dav_access_options_header,
    dav_access_options_method,
    NULL
};

static int dav_access_get_resource_type(const dav_resource *resource,
                                        const char **type, const char **uri)
{
    request_rec *r;
    dav_access_config_rec *conf;

    int result = DECLINED;

    *type = *uri = NULL;

    if (resource && resource->hooks && resource->hooks->get_request_rec) {
        r = resource->hooks->get_request_rec(resource);
    }
    else {
        return result;
    }

    conf = ap_get_module_config(r->per_dir_config,
            &dav_access_module);

    if (conf->dav_access_principal) {

        *type = "principal";
        *uri = DAV_XML_NAMESPACE;

        result = OK;
    }

    return result;
}

static dav_resource_type_provider resource_types =
{
    dav_access_get_resource_type
};

static void *create_dav_access_dir_config(apr_pool_t *p, char *d)
{
    dav_access_config_rec *conf = apr_pcalloc(p, sizeof(dav_access_config_rec));

    return conf;
}

static void *merge_dav_access_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    dav_access_config_rec *new = (dav_access_config_rec *) apr_pcalloc(p,
            sizeof(dav_access_config_rec));
    dav_access_config_rec *add = (dav_access_config_rec *) addv;
    dav_access_config_rec *base = (dav_access_config_rec *) basev;

    new->dav_access = (add->dav_access_set == 0) ? base->dav_access : add->dav_access;
    new->dav_access_set = add->dav_access_set || base->dav_access_set;

    new->dav_access_principal = (add->dav_access_principal_set == 0) ? base->dav_access_principal : add->dav_access_principal;
    new->dav_access_principal_set = add->dav_access_principal_set || base->dav_access_principal_set;

    new->principal_url = (add->principal_url_set == 0) ? base->principal_url : add->principal_url;
    new->principal_url_set = add->principal_url_set || base->principal_url_set;

    new->priviledge = (add->priviledge_set == 0) ? base->priviledge : add->priviledge;
    new->priviledge_set = add->priviledge_set || base->priviledge_set;

    return new;
}

static const char *set_dav_access(cmd_parms *cmd, void *dconf, int flag)
{
    dav_access_config_rec *conf = dconf;

    conf->dav_access = flag;
    conf->dav_access_set = 1;

    return NULL;
}

static const char *set_dav_access_principal(cmd_parms *cmd, void *dconf, int flag)
{
    dav_access_config_rec *conf = dconf;

    conf->dav_access_principal = flag;
    conf->dav_access_principal_set = 1;

    return NULL;
}

static const char *set_dav_principal_url(cmd_parms *cmd, void *dconf, const char *url)
{
    dav_access_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->principal_url = ap_expr_parse_cmd(cmd, url, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "Cannot parse expression '", url, "': ",
                expr_err, NULL);
    }

    conf->principal_url_set = 1;

    return NULL;
}

static const char *set_dav_access_priviledge(cmd_parms *cmd, void *dconf, const char *namespace)
{
    dav_access_config_rec *conf = dconf;

    /*
     * In future we plan to support "DavAccessPriviledge namespace +priviledge1 ..."
     *
     * For now, support a future compatible shortcut "DavAccessPriviledge all".
     */
    if (!strcmp(namespace, "all")) {
        conf->priviledge = "<D:privilege><D:read/></D:privilege><D:privilege><D:write/></D:privilege><D:privilege><D:bind/></D:privilege><D:privilege><D:unbind/></D:privilege>";
    }
    else {
        return apr_pstrcat(cmd->temp_pool,
                "DavAccessPriviledge must be set to 'all': '", namespace, NULL);
    }

    conf->priviledge_set = 1;

    return NULL;
}

static const command_rec dav_access_cmds[] =
{
    AP_INIT_FLAG("DavAccess",
        set_dav_access, NULL, RSRC_CONF | ACCESS_CONF,
        "When enabled, the URL space will declared to support the option 'access-control'."),
    AP_INIT_FLAG("DavAccessPrincipal",
        set_dav_access_principal, NULL, RSRC_CONF | ACCESS_CONF,
        "When enabled, the URL space will declared to contain resourcetype 'principal'."),
    AP_INIT_TAKE1("DavAccessPriviledge",
        set_dav_access_priviledge, NULL, RSRC_CONF | ACCESS_CONF,
        "When set to 'all', the URL space will allow all DAV priviledges."),
    AP_INIT_TAKE1("DavAccessPrincipalUrl", set_dav_principal_url, NULL, RSRC_CONF | ACCESS_CONF,
        "Set the URL template to use for the principal URL. Recommended value is \"/principals/%{escape:%{REMOTE_USER}}\"."),
    { NULL }
};

static int dav_access_handler(request_rec *r)
{

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(dav_access_handler, NULL, NULL, APR_HOOK_MIDDLE);

    dav_register_liveprop_group(p, &dav_access_liveprop_group);

    dav_options_provider_register(p, "dav_access", &options);
    dav_resource_type_provider_register(p, "dav_access", &resource_types);

    dav_hook_find_liveprop(dav_access_find_liveprop, NULL, NULL, APR_HOOK_MIDDLE);

}

AP_DECLARE_MODULE(dav_access) =
{
    STANDARD20_MODULE_STUFF,
    create_dav_access_dir_config, /* dir config creater */
    merge_dav_access_dir_config,  /* dir merger --- default is to override */
    NULL,                         /* server config */
    NULL,                         /* merge server config */
    dav_access_cmds,              /* command apr_table_t */
    register_hooks                /* register hooks */
};
