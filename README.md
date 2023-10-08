# mod_dav_access
This module extends a WebDAV server to provide support for the
RFC3744 WebDav Access Control Protocol.

Some mod_dav providers (like Subversion) provide their own support
for ACLs, while other providers (like mod_dav_fs) do not. This module
can be used to provide ACLs where needed, such as for a CalDAV server.

Requires Apache httpd v2.4.52 or higher.

# download

RPM Packages are available at
[COPR](https://copr.fedorainfracloud.org/coprs/minfrin/mod_dav_access/) for EPEL, Fedora and OpenSUSE.

```
dnf copr enable minfrin/mod_dav_access
dnf install mod_dav_access
```

Ubuntu packages are available through
[PPA](https://launchpad.net/~minfrin/+archive/ubuntu/apache2/).

# quick configuration

The configuration below gives the logged in user their own calandar
space.

    <IfModule !alias_module>
      LoadModule alias_module modules/mod_alias.so
    </IfModule>
    <IfModule !authz_core_module>
      LoadModule authz_core_module modules/mod_authz_core.so
    </IfModule>
    <IfModule !autoindex_module>
      LoadModule autoindex_module modules/mod_autoindex.so
    </IfModule>
    <IfModule !dav_module>
      LoadModule dav_module modules/mod_dav.so
    </IfModule>
    <IfModule !dav_fs_module>
      LoadModule dav_fs_module modules/mod_dav_fs.so
    </IfModule>
    <IfModule !dir_module>
      LoadModule dir_module modules/mod_dir.so
    </IfModule>
    <IfModule !setenvif_module>
     LoadModule setenvif_module modules/mod_setenvif.so
    </IfModule>

    Redirect /.well-known/caldav /calendar/

    <Location /calendar>
      Alias /var/www/dav/calendar/
      AliasPreservePath on

      Dav on
      DavAccess on
      DavCalendar on
      Options +Indexes

      DavAccessPriviledge all
      DavAccessPrincipalUrl /calendar/principals/%{escape:%{REMOTE_USER}}/
      DavCalendarHome /calendar/calendars/%{escape:%{REMOTE_USER}}/
      DavCalendarProvision /calendar/calendars/%{escape:%{REMOTE_USER}}/ %{REMOTE_USER}
      DavCalendarTimezone UTC

      IndexOptions FancyIndexing HTMLTable VersionSort XHTML
      DirectoryIndex disabled
      FileETag INode MTime Size

      # limit to logged in users
      AuthType basic

      SetEnvIf REQUEST_URI "^/calendar/calendars/([^/]+)" MATCH_USER=$1

      <RequireAll>
        require valid-user
        require expr %{env:MATCH_USER} == '' || %{unescape:%{env:MATCH_USER}} == %{REMOTE_USER}
      </RequireAll>

    </Location>

    <Location /calendar/principals>

      Alias /var/www/dav/calendar/principals
      AliasPreservePath off

      DavAccessPrincipal on

    </Location>

# configuration in more detail

## find the principal URL

Many WebDAV extensions need to be able to query for information unique
to or shared by a given user. Each user is given a dedicated URL that
can be queried for this information using PROPFIND.

To find the principal URL, a WebDAV client can query anywhere in the
URL space using PROPFIND to find out what the principal URL is. This
module can be asked to tell the client where the principal URL is like
this:

    Alias /calendar /home/calendar
    <Directory /home/calendar>
      DavAccessPrincipalUrl /calendar/principals/%{escape:%{REMOTE_USER}}/
    </Directory>

## declare the principal URL space

You may choose to create concrete collections (directories) representing
each principal user, but that can be avoided by mapping every principal
to the same directory, and then adding relevant properties to the url
space. This is useful when all users have the same permissions.

    <Location /calendar/principals>

      # this directory must exist
      Alias /var/www/dav/calendar/principals
      # map every path underneath /calendar/principals to the above directory
      AliasPreservePath off
      # every collection in the URL space will have the DAV:principal resourcetype
      DavAccessPrincipal on

    </Location>

## specify permissions on a collection

Grant all permissions to the URL space by adding this directive. Is it
left to standard Apache httpd configuration to limit access as normal.

    DavAccessPriviledge all

# configuration directives

The *DavAccess* directive causes "access-control" to be added to the
OPTIONS. This is required by most clients on all principal and calendar
URL spaces.

The *DavAccessPrincipal* directive adds the "principal" resourcetype
to all resources in the URL space.

The *DavAccessPrincipalUrl* directive defines an expression that resolves
to the path of the principal URL. A recommended value is
'/principal/%{escape:%{REMOTE_USER}}', which is derived from the name of
the logged in user.

