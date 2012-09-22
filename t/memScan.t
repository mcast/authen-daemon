#! perl
use strict;
use warnings;

use Test::More;
use Devel::MemScan;

use lib 't/tlib';
use DiagDump 'diagdump';


our $junk;

sub main {
    my $tot = 27;
    plan tests => $tot;
  SKIP: {
        basic_tt() or
          skip 'no hits in basic test - completely broken?', $tot - 2;

        context_tt();
        patternhit_tt();
        mkregex_tt() or
          skip 'regex maker b0rk', $tot - 4;

        unihit_tt($_) for (0..4);
        # repeat because it seems intermittent (on what conditions?);
        # but it also seems consistent within a Perl instance

      TODO: {
            local $TODO = 'tricky?';
            wipeout_tt(1);
        }
        wipeout_tt(0);
    }
    return ();
}

sub basic_tt {
    $junk = 'bifflefrogulation';
    my ($fail, @hit) = Devel::MemScan->scan(qr{bifflefrogulation});
    is($fail, undef, 'scan A: should not fail');
    like(eval { $hit[0]->hexaddr } || $@, qr{^0x[0-9a-fA-F]+$}, 'scan A: hexaddr');
    is(eval { hex($hit[0]->hexaddr) } || $@,
       eval { $hit[0]->addr } || 'well, it broke', 'scan A: hex equiv');
    return cmp_ok(scalar @hit, '>', 0, 'scan A: want hits');
}

sub context_tt {
    $junk = 'wibblywibblyMATCH_IT_HEREwobblywobbly';
    my ($fail, @hit) = Devel::MemScan->scan
      (qr{[a-z]+MATCH_IT_HERE[a-z]+}); # likely to be slow?
    is($fail, undef, 'scan B: should not fail');
    my @has_context = grep { /wibbly/ && /wobbly/ }
      map { $_->txt } @hit;
    cmp_ok(scalar @has_context, '>', 0, 'scan B: includes context')
      or diagdump(hit => @hit);
    return ();
}

sub patternhit_tt {
    my $pat = qr{my_regex_sel[f]matches};
    # assumption: regex compiler simplifies the [f] to just f
    # and the pattern will then match that representation
    my ($fail, @hit) = Devel::MemScan->scan($pat);
    die "pathit1 fail: $fail" if $fail;
    cmp_ok(scalar @hit, '>', 0, 'pathit1: expect regex match');

    $pat = qr{another_reg(exp|ular_expression)_doesnt_match};
    ($fail, @hit) = Devel::MemScan->scan($pat);
    die "pathit2 fail: $fail" if $fail;
    cmp_ok(scalar @hit, '==', 0, 'pathit2: expect no match')
      or diagdump(hit => @hit);
}

sub mkregex_tt {
    my $N = 3;
    $junk = "Isaw${N}junksgo";
    my $suffix = 'junksgo';
    my ($fail, @hit) = Devel::MemScan->scan(sub{ qr{Isaw\d+$suffix} });
    is($fail, undef, 'scan C: should not fail');
    return cmp_ok(scalar @hit, '>', 0, 'scan C: want hits');
}

sub unihit_tt {
    my ($arg) = @_;
    $junk = "1234goldfish ($arg)MAgoldfish SAR CDBDII";
    substr($junk, 0, 4, 'ABCD');
    my ($fail, @hit) = Devel::MemScan->scan
      (qr{ABCDgold\w+ \($arg\)MA\w+ \w{3} \w+.{0,10}});
    die "D:$fail" if $fail;
    my $jref = \$junk;
    cmp_ok(scalar @hit, '>', 0, "scan D($arg): should hit");
    cmp_ok(scalar @hit, '<=', 3, 'scan D($arg): expect 1..3 hits')
      or diagdump
        (jref => "$jref",
         hit_hexaddr => [ map { $_->hexaddr } @hit ],
         hit => \@hit);
  TODO: {
        local $TODO = 'tricky?';
        cmp_ok(scalar @hit, '==', 1, 'scan D($arg): want one hit - mystery variability');
    }
}

sub wipeout_tt {
    my ($arg) = @_;
    my @junk = ('x' x 16);
    substr($junk[0],3,5,"heff$arg");
    substr($junk[0],8,5,'alump');

    my ($fail, @hit1, @hit2);
    my $pat = qr{...[h]ef+${arg}a\x6cum(?:ock)?\w+};

    if ($arg) {
        ($fail, @hit1) = Devel::MemScan->scan($pat);
        $fail ||= 'not found' unless @hit1;
        die "find1($arg) fail ($fail)" if $fail;
        scrub(\$_->[1]) foreach @hit1; # deref
    }

    scrub(\$junk[0]);

    ($fail, @hit2) = Devel::MemScan->scan($pat);
    die "find2($arg) fail ($fail)" if $fail;

    is(scalar @hit2, 0, "wipeout($arg): gone after scrub")
      or diagdump(hit1 => \@hit1, hit2 => \@hit2, junk => \@junk);
}

sub scrub {
    my ($ref) = @_;
    if (ref($ref) eq 'SCALAR') {
        my $L = length($$ref);
        substr($$ref, 0, $L) = 'x' x $L;
    } else {
        die 'Cannot scrub '.ref($ref).' yet';
    }
    return ();
}

main();
