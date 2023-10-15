NGINX Experimental base image using [alpine](https://www.alpinelinux.org/)

See PACKAGES for the containing packages

## TODO:
Because we need to rebuild NGINX with some custom patches, we need to verify how
to get the source from APK and apply the patch (the most dangerous one right now
is dropping alias and root directives)