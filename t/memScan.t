#! perl
use strict;
use warnings;

use Test::More;
use Devel::MemScan;

use lib 't/tlib';
use DiagDump 'diagdump';


our $junk;

sub main {
    my $tot = 38;
    plan tests => $tot;
  SKIP: {
        basic_tt() # 4
          or skip 'no hits in basic test - completely broken?', $tot - 4;

        token_tt(); # 2
        repeat_tt(); # 6
        context_tt(); # 2
        patternhit_tt(); # 2
        long_tt(); # 3
        mkregex_tt(); # 2

        unihit_tt($_) for (0..4); # 3 * 5
        # repeat because it seems intermittent (on what conditions?);
        # but it also seems consistent within a Perl instance

        wipeout_tt(1); # 1
        wipeout_tt(0); # 1
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

sub token_tt {
    my @t = map { Devel::MemScan->token($_) } (3, 5, undef, 8);
    my @len = map { length($_) } @t;
    is("@len", '3 5 8 8', 'token len');
    isnt($t[2], $t[3], 'token diff');
}

sub repeat_tt {
    my $tok = 'Aec1Mie2'; # 8
    my $N = 4096; # headroom below 10000
    cmp_ok($N, '<=', (Devel::MemScan->scan_params)[1], 'repeat: within params');

    # set them up
    $junk = 'o' x ($N * 16); # assumption: contiguous string storage!
    for (my $i=0; $i<$N; $i++) {
        substr($junk, $i*16,     16) = " $tok+.... -";
        substr($junk, $i*16 + 10, 4) = sprintf('%04d', $i);
    }

    # knock them down
    my ($fail, @hit) = Devel::MemScan->scan(qr{ $tok\+(\d+) });
    is($fail, undef, 'repeat: pass');
    cmp_ok(scalar @hit, '>=', $N, 'repeat: enough');

    # keep score
    my @nhit = (0) x $N; # idx = i, value = hitcount
    foreach my $h (@hit) {
        $nhit[ $h->txt ]++;
    }
    my @n = ([]); # idx = hitcount, value = \@i
    for (my $i=0; $i<@nhit; $i++) {
        my $hitcount = $nhit[$i];
        push @{ $n[$hitcount] }, $i;
    }
    my $ok = 1;
    is_deeply($n[0], [], 'repeat: missing') or $ok=0;
    is(scalar @nhit, $N, 'repeat: extras')  or $ok=0;
#     diagdump(hit => \@hit, nhit => \@nhit, n => \@n) unless $ok; # big noise
    is($#n, 1, 'repeat: max nhit');
}

sub long_tt { # find matches of buflen at any offset
    my ($buflen) = Devel::MemScan->scan_params;
    my $matchlen = $buflen;
    my $offset = int(rand($buflen*2));
    $junk = 'o' x ($buflen*4);
    my @tok = qw( iwaeZ3na naeth2Hu );
    substr($junk, $offset, 8) = $tok[0];
    substr($junk, $offset+$matchlen-8, 8) = $tok[1];

    my ($fail, @hit) = Devel::MemScan->scan(qr{($tok[0]o+$tok[1])});
    is($fail, undef, 'long: pass');
    cmp_ok(scalar @hit, '>', 0, 'long: hit');
    my @len = map { length($_->txt) } @hit;
    ok((scalar grep { $_ == $matchlen } @len), 'long: hitlen')
      or diagdump(len => \@len, offset => $offset);
}

sub context_tt {
    $junk = 'wibblywibblyMATCH_IT_HEREwobblywobbly';
    my ($fail, @hit) = Devel::MemScan->scan
      (qr{([a-z]+)MATCH_IT_HERE([a-z]+)}); # likely to be slow?
    is($fail, undef, 'scan B: should not fail');
    my @has_context = grep {
        $_->txt(0) =~ /wibbly/ && $_->txt(1) =~ /wobbly/
    } @hit;
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
    cmp_ok(scalar @hit, '==', 1, 'scan D($arg): want one hit');
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
