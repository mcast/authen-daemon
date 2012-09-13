#! perl
use strict;
use warnings;

use Test::More;
use Devel::MemScan;

our $junk;

my $dump =
  ((eval { require YAML     } && \&YAML::Dump    ) ||
   (eval { require YAML::XS } && \&YAML::XS::Dump) ||
   require Data::Dumper && sub { Data::Dumper->Dump([ \@_ ], [ 'data' ]) });

sub main {
    my $tot = 23;
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
    }
    return ();
}

sub basic_tt {
    $junk = 'bifflefrogulation';
    my ($fail, @hit) = Devel::MemScan->scan(qr{bifflefrogulation});
    is($fail, undef, 'scan A: should not fail');
    return cmp_ok(scalar @hit, '>', 0, 'scan A: want hits');
}

sub context_tt {
    $junk = 'wibblywibblyMATCH_IT_HEREwobblywobbly';
    my ($fail, @hit) = Devel::MemScan->scan
      (qr{[a-z]+MATCH_IT_HERE[a-z]+}); # likely to be slow?
    is($fail, undef, 'scan B: should not fail');
    my @has_context = grep { /wibbly/ && /wobbly/ }
      map { $_->[1] } # deref: liable to change
        @hit;
    cmp_ok(scalar @has_context, '>', 0, 'scan B: includes context')
      or diag $dump->(@hit);
    return ();
}

sub patternhit_tt {
    my $pat = qr{my_regex_sel[f]matches};
    # assumption: regex compiler simplifies the [f] to just f
    # and the pattern will then match that representation
    my ($fail, @hit) = Devel::MemScan->scan($pat);
    die "pathit1 fail: $fail" if defined $fail;
    cmp_ok(scalar @hit, '>', 0, 'pathit1: expect regex match');

    $pat = qr{another_reg(exp|ular_expression)_doesnt_match};
    ($fail, @hit) = Devel::MemScan->scan($pat);
    die "pathit2 fail: $fail" if defined $fail;
    cmp_ok(scalar @hit, '==', 0, 'pathit2: expect no match')
      or diag $dump->(@hit);
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
    die "D:$fail" if defined $fail;
    my $jref = \$junk;
    cmp_ok(scalar @hit, '>', 0, "scan D($arg): should hit");
    cmp_ok(scalar @hit, '<=', 3, 'scan D($arg): expect 1..3 hits')
      or diag $dump->("$jref",
                      [ map { sprintf('0x%x', $_->[0]) } @hit ], # deref
                      \@hit);
  TODO: {
        local $TODO = 'tricky?';
        cmp_ok(scalar @hit, '==', 1, 'scan D($arg): want one hit - mystery variability');
    }
}


main();
