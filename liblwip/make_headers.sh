#!/bin/sh

echo 'LWIP_HEADERS = """' > $2
cat $1 >> $2
echo '"""' >> $2