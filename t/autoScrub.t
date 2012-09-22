#! perl
use strict;
use warnings;
use Test::More;

use Devel::MemScan;
use Authen::Daemon::AutoScrub;

use lib 't/tlib';
use DiagDump 'diagdump';

sub main {
    plan tests => 26;

    interface_tt(); #  9
    rots_tt();      # 10
    vape_tt();      #  7

    return ();
}


sub interface_tt {
    my $o = Authen::Daemon::AutoScrub->new;
    is_deeply($o, [''], 'blank content');
    ok($o->is_blank, 'is blank');
    $$o[0] = 'sekrit';
    ok(!$o->is_blank, 'is not blank');

    my $o2 = $o->new; # clone
    is($$o2[0], 'sekrit', 'cloned');
    is_deeply($o2, [ 'sekrit' ], 'structure of clone');
    $o2->scrub;
    ok($o2->is_blank, 'blank again');
    is($$o[0], 'sekrit', 'source unaffected');

    my $o3 = Authen::Daemon::AutoScrub->new([ 'stuffything' ]);
    is($$o3[0], 'stuffything', 'initarg');

    my $o4 = $o->new([ 'initmore' ]);
    is($$o4[0], 'initmore', 'initarg on object');
    return ();
}

sub txt_is {
    my ($obj, $expect, $t_name) = @_;
    if (ok($$obj[0] eq $expect, $t_name)) {
        return 1;
    } else {
        diagdump(obj => $obj, expect => $expect, caller => [ caller ]);
        return 0;
    }
}

sub rots_tt {
    my $orig = 'ABCDgoldfish = 2bdIs';
    my $o = Authen::Daemon::AutoScrub->new([ $orig ]);
    $o->rot13;
    txt_is($o, 'NOPQtbyqsvfu = 2oqVf', 'rot13 obj');
    $o->rot128;
    $o->rot128;
    $o->rot13;
    txt_is($o, $orig, 'round trip');

    $orig = "\x00\x21\x42\x63\x84\xa5\xc6\xe7\xf8";
    $o = $o->new([ $orig ]);
    $o->rot128;
    txt_is($o, "\x80\xa1\xc2\xe3\x04\x25\x46\x67\x78", 'rot128 obj');
    $o->rot128;
    txt_is($o, $orig, 'rot128 back');

    my $txt = "B0rk str1ng\n";
    $o = $o->new([ 'mumble' ]);
    $o->rot13(\$txt);
    is($txt, "O0ex fge1at\n", 'rot13 ref');
    txt_is($o, 'mumble', 'rot13 ref: obj remains');
    Authen::Daemon::AutoScrub->rot13(\$txt);
    is($txt, "B0rk str1ng\n", 'restored classily');

    $txt = "\x00-\xff";
    $o->rot128(\$txt);
    is($txt, "\x80\xad\x7f", 'rot128 ref');
    txt_is($o, 'mumble', 'rot128 ref: obj remains');
    Authen::Daemon::AutoScrub->rot128(\$txt);
    is($txt, "\x00-\xff", 'restored');
    return ();
}


sub vape_tt {
    my $orig = '~~x# miff-muffered #~~';

    # first show that search works
    my $o = Authen::Daemon::AutoScrub->new([ $orig ]);
    substr($$o[0], 2, 1, '0');
    $o->rot13;
    my ($fail, @hit) = Devel::MemScan->scan(qr{~~0# \w{4}-\w{8} #~~});
    is(undef, $fail, 'Devel::MemScan 0');
    my @htxt = map { $_->txt } @hit;
    ok(scalar (grep { qr{zvss-zhssrerq} } @htxt), 'sbhaq bevt')
      or diagdump(hit => \@hit, o => $o);

    # show that text can otherwise hang around
    {
        my @txt = ($orig);
        substr($txt[0], 2, 1, '1');
        is(substr($txt[0], 1, 3), '~1#', 'txt exists');
    }
    ($fail, @hit) = Devel::MemScan->scan(qr{~~1# \w{4}-\w{8} #~~});
    is(undef, $fail, 'Devel::MemScan 1');
    cmp_ok(scalar @hit, '>', 0, 'dealloc loiterance'); # fragile?

    # show scrubbing
    $o = Authen::Daemon::AutoScrub->new([ $orig ]);
    substr($$o[0], 2, 1, '2');
    $o->rot13;
    undef $o;
    ($fail, @hit) = Devel::MemScan->scan(qr{~~2# \w{4}-\w{8} #~~});
    is(undef, $fail, 'Devel::MemScan 2');
    is(scalar @hit, 0, 'data scrubbed')
      or diagdump(hit => \@hit);

    return ();
}


main();
