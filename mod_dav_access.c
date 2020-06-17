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
 */
#include <apr_lib.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"

#include "mod_dav.h"

module AP_MODULE_DECLARE_DATA dav_access_module;

/* forward-declare the hook structures */
static const dav_hooks_liveprop dav_hooks_liveprop_access;

/*
** The namespace URIs that we use. This list and the enumeration must
** stay in sync.
*/
static const char * const dav_access_namespace_uris[] =
{
    "DAV:",

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
    /* standard calendar properties */
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
        "alternate-uri-set",
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
        "principal-url",
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


typedef struct
{
    int dav_access_set :1;
    int dav_access;
} dav_calendar_config_rec;

static dav_error *dav_access_options_header(request_rec *r,
		const dav_resource *resource, apr_text_header *phdr)
{
    apr_text_append(r->pool, phdr, "access-control");

    return NULL;
}

static dav_error *dav_access_options_method(request_rec *r,
		const dav_resource *resource, apr_text_header *phdr)
{
//    apr_text_append(r->pool, phdr, "ACL");
//    apr_text_append(r->pool, phdr, "REPORT");

    return NULL;
}

static dav_options_provider options =
{
    dav_access_options_header,
    dav_access_options_method,
    NULL
};

static void *create_dav_access_dir_config(apr_pool_t *p, char *d)
{
	dav_calendar_config_rec *conf = apr_pcalloc(p, sizeof(dav_calendar_config_rec));

    return conf;
}

static void *merge_dav_access_dir_config(apr_pool_t *p, void *basev, void *addv)
{
	dav_calendar_config_rec *new = (dav_calendar_config_rec *) apr_pcalloc(p,
            sizeof(dav_calendar_config_rec));
	dav_calendar_config_rec *add = (dav_calendar_config_rec *) addv;
	dav_calendar_config_rec *base = (dav_calendar_config_rec *) basev;

    new->dav_access = (add->dav_access_set == 0) ? base->dav_access : add->dav_access;
    new->dav_access_set = add->dav_access_set || base->dav_access_set;

    return new;
}

static const char *set_dav_access(cmd_parms *cmd, void *dconf, int flag)
{
    dav_calendar_config_rec *conf = dconf;

    conf->dav_access = flag;
    conf->dav_access_set = 1;

    return NULL;
}

static const command_rec dav_access_cmds[] =
{
    AP_INIT_FLAG("DavAccess",
        set_dav_access, NULL, RSRC_CONF | ACCESS_CONF,
        "When enabled, the URL space will support calendars."),
    { NULL }
};

static int dav_access_handler(request_rec *r)
{

	dav_calendar_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &dav_access_module);

    return DECLINED;

}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(dav_access_handler, NULL, NULL, APR_HOOK_MIDDLE);

    dav_register_liveprop_group(p, &dav_access_liveprop_group);

    dav_options_provider_register(p, "dav_access", &options);
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
