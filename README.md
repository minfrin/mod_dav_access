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

    <Location /principal>

      # limit to logged in users
      AuthType basic
      require valid-user

      # configration needed at the principal URL space
    </Location>

    Alias /calendar /home/calendar
    <Directory /home/calendar>
      Dav on

      # limit to logged in users
      AuthType basic
      require valid-user

      DavAccessPrincipalUrl /principal/%{escape:%{REMOTE_USER}}
    </Directory>

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
      DavAccessPrincipalUrl /principal/%{escape:%{REMOTE_USER}}
    </Directory>

## specify permissions on a collection

In the present form, this module advertises that all permissions have been
granted to the URL space. Is it left to standard Apache httpd configuration
to limit access as normal.

# configuration directives

The *DavAccessPrincipalUrl* directive defines an expression that resolves
to the path of the principal URL. A recommended value is
'/principal/%{escape:%{REMOTE_USER}}', which is derived from the name of
the logged in user.

