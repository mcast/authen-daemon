#! perl
use strict;
use warnings;

use Test::More tests => 7;

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
    Authen::Daemon::NoMoreCode->embargo;
    try_load('Sys::Hostname', qr/embargo/);
}

main();
