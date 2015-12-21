#!/bin/sh
# Move .torrent files into its folders.
# See: http://superuser.com/q/1016517/87805
find . -name "*.torrent" -exec sh -c 'DST=$(find . -type d -name "$(basename "{}" .torrent)" -print -quit); [ -d "$DST" ] && echo mv -v "{}" "$DST/"' ';'
