#! perl
use strict;
use warnings;

use Test::More tests => 3;
BEGIN { require overload } # is require'd at runtime

use Authen::Daemon::NoMoreCode 'auto';
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
    try_load('Data::Dumper', qr/embargo/);
}

main();
