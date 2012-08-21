#! perl
use strict;
use warnings;

use Test::More tests => 11;

use Authen::Daemon::NoMoreCode;
use File::Find; # not needed

sub try_load {
    my ($mod, $want_err) = @_;
    my $fn = "$mod.pm";
    $fn =~ s{::}{/}g;
    ok(!$INC{$fn}, "$fn initially absent");
    eval "require $mod";
    my $err = $@;
    chomp $err;
    if ($want_err) {
        like($err, $want_err, "  Load $mod should fail");
        ok(!$INC{$fn}, "  $fn still absent");
    } else {
        is($err, '', "  Load $mod");
        ok($INC{$fn}, "  $fn now present");
    }
    return;
}

sub main {
    ok($INC{'File/Find.pm'}, "load OK after 'use'"); # we would know

    try_load('Data::Dumper', 0);

    my $ln_close = __LINE__ + 1;
    Authen::Daemon::NoMoreCode->embargo;

    try_load('Sys::Hostname', qr/embargo/);

    my ($src, $ln_eval);
    eval {
        ($src, $ln_eval) = (__FILE__, __LINE__ + 1);
        require Moon::On::Stick;
    };
    my $err = $@;
    like($err, qr{Moon[:/]+On[:/]+Stick}, 'tells the wanted file');
    like($err, qr{Authen::Daemon::NoMoreCode}, 'tells the cause');
    like($err, qr{ at \Q$src\E line $ln_eval}, 'tells trigger line');
    like($err, qr{ from \Q$src\E line $ln_close }, 'tells cause line');
}

main();
