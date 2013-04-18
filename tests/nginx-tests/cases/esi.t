#!/usr/bin/perl

# Tests for esi modules

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http esi/)->plan(11);

$t->set_dso("ngx_http_fastcgi_module", "ngx_http_fastcgi_module.so");
$t->set_dso("ngx_http_uwsgi_module", "ngx_http_uwsgi_module.so");
$t->set_dso("ngx_http_scgi_module", "ngx_http_scgi_module.so");
$t->set_dso("ngx_http_upstream_ip_hash_module", "ngx_http_upstream_ip_hash_module.so");
$t->set_dso("ngx_http_upstream_least_conn_module", "ngx_http_upstream_least_conn_module.so");

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

%%TEST_GLOBALS_DSO%%

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            esi on;
            index index.html;
        }

        location /1970 {
            proxy_pass http://127.0.0.1:1970/1970.html;
        }

        location /1971 {
            proxy_pass http://127.0.0.1:1971/1971.html;
        }
    }

    server {
        listen       127.0.0.1:1970;
        server_name  localhost;

        location / {
            index index.html;
        }
    }

    server {
        listen       127.0.0.1:1971;
        server_name  localhost;

        location / {
            index index.html;
        }
    }
}

EOF

my $esi_content;
$esi_content = <<EOF;
<html>
   <body>
      local1=<esi:include src="/local1.html"/>
      local2=<esi:include src="/local2.html"/>
      1970=<esi:include src="/1970"/>
      1971=<esi:include src="/1971"/>
   </body>
</html>
EOF

my $esi_content1;
$esi_content1 = <<EOF;
<html>
   <body>
      local1=<esi:include src="/local3.html"/>
   </body>
</html>
EOF

my $esi_content2;
$esi_content2 = <<EOF;
<html>
   <body>
      local1=<esi:include/>
   </body>
</html>
EOF

my $esi_content3;
$esi_content3 = <<EOF;
<html>
   <body>
      local1=<esi:/>
   </body>
</html>
EOF

my $esi_content4;
$esi_content4 = <<EOF;
<html>
   <body>
      local1=<esi: test="test"/>
   </body>
</html>
EOF

my $esi_content5;
$esi_content5 = <<EOF;
<html>
   <body>
      local1=<esi: test=test/>
   </body>
</html>
EOF

my $esi_content6;
$esi_content6 = <<EOF;
<html>
   <body>
      local1=<esi: aa/>
   </body>
</html>
EOF

my $esi_content7;
$esi_content7 = <<EOF;
<html>
   <body>
      local1=<esi: aa=/>
   </body>
</html>
EOF

$t->write_file('index.html', 'hello, tengine!');
$t->write_file('esi.html', $esi_content);
$t->write_file('esi1.html', $esi_content1);
$t->write_file('esi2.html', $esi_content2);
$t->write_file('esi3.html', $esi_content3);
$t->write_file('esi4.html', $esi_content4);
$t->write_file('esi5.html', $esi_content5);
$t->write_file('esi6.html', $esi_content6);
$t->write_file('esi7.html', $esi_content7);
$t->write_file('local1.html', 'local1');
$t->write_file('local2.html', 'local2');
$t->write_file('1970.html', '1970');
$t->write_file('1971.html', '1971');

$t->run();

###############################################################################

like(http_get('/esi.html'), qr/local1=local1/, 'local1=local1');
like(http_get('/esi.html'), qr/local2=local2/, 'local2=local2');
like(http_get('/esi.html'), qr/1970=1970/, '1970=1970');
like(http_get('/esi.html'), qr/1971=1971/, '1971=1971');
like(http_get('/esi1.html'), qr/404/, 'bad file');
like(http_get('/esi2.html'), qr/an error occurred/, 'bad tag2');
like(http_get('/esi3.html'), qr/an error occurred/, 'bad tag3');
like(http_get('/esi4.html'), qr/an error occurred/, 'bad tag4');
like(http_get('/esi5.html'), qr/an error occurred/, 'bad tag5');
like(http_get('/esi6.html'), qr/an error occurred/, 'bad tag6');
like(http_get('/esi7.html'), qr/an error occurred/, 'bad tag7');

$t->stop();
###############################################################################
