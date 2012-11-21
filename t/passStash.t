#! perl
use strict;
use warnings;
use Test::More;

use Digest::MD5 'md5_hex';
use Try::Tiny;

use Devel::MemScan;
use Authen::Daemon::PassStash;

use lib 't/tlib';
use DiagDump 'diagdump';
use RecipOTron;


sub main {
    plan tests => 28;

    search_tt();  # 2
    fails_tt();   # 3
    plain_tt();   # 5
    tools_tt();   # 6
    blessy_tt();  # 7
    interface_tt(); # 2
    from_term_tt(); # 3
}


sub search_tt {
    my $junk = 'smorking';
    $junk .= 'ton';
    my ($fail, @hit) = Devel::MemScan->scan(qr{smork(?:ing|le)ton});
    is($fail, undef, 'does search work?');
    cmp_ok(scalar @hit, '=', 1, 'does it find?');
}

sub fails_tt {
    my $ps = Authen::Daemon::PassStash->new(undef);
    like(eval { $ps->set('string'); 'ran' } || $@,
         qr{ARRAY ref}, 'require arrayref');
    $ps->set([ 'pass' ]);
    like(eval { $ps->utilise(); 'ran' } || $@,
         qr{no recipient}i, 'Needs the CODEref');
    $ps = Authen::Daemon::PassStash->new(sub { die 'called' });
    like(eval { $ps->utilise(); 'ran' } || $@,
         qr{password.*not set}i, 'Needs the pass');
}

sub plain_tt {
    my $recip = sub {
        my ($self, $pwlist, @arg) = @_;
        my $got = md5_hex("$$pwlist[0]\n@arg\n");
        is($got, 'eb9a196e8ffb84b1ad0d6a034771ecaf', 'plain: utilised')
          or diagdump(pw => $pwlist, arg => \@arg);
        return $got;
    };

    my $pw = Authen::Daemon::PassStash->new($recip, qw( supplied args ));
    my $p = ['uvrX8nut uv6Cnrl5'];
    Authen::Daemon::AutoScrub->rot13(\$p->[0]);
    $pw->set($p);
    is("@$p", '', 'plain: set takes password')
      or diagdump(p => $p, pw => $pw);

    my ($fail, @hit) = Devel::MemScan->scan(qr{hieK\d\whg\shi6Paey5});
    die "plain: search fail: $fail" if $fail;
    cmp_ok(scalar @hit, '=', 1, 'plain: one copy')
      or diagdump(hit => \@hit);
    # keeping it scrambled and/or in kernel store would be neat, but
    # would also invalidate following test assumptions

    my $got2 = $pw->utilise(qw( list here )); # 1 test
    is($got2, 'eb9a196e8ffb84b1ad0d6a034771ecaf', 'scalar return');
    $pw->utilise(qw( list here )); # 1 test
}

sub tools_tt {
    # check the test tool
    my $R = RecipOTron->new; # blessed CODEref
    my $txt = Authen::Daemon::AutoScrub->new([ 'abCde' ]);
    my $out = $R->($R, $txt, qw( first input ));
    $$txt[0] = 'fgHij';
    my @out = $R->($R, $txt, qw( extra args ));
    my @want_stored =
      ({ pw_ref => [ 'fgHij' ],
         pw_copy => [ 'noPqr' ],
         arg => [qw[ first input ]] },
       { pw_ref => [ 'fgHij' ],
         pw_copy => [ 'stUvw' ],
         arg => [qw[ extra args ]] } );
    is($out, 'scalar context', 'tool: scalar call');
    is(ref($out[0]), 'RecipOTron::Storage', 'tool: list call');
    is_deeply($out[0], \@want_stored, 'tool: stored from calls'); # blessedness is not compared

    # Password should be gone after calls, but we kept the ref
    $txt->scrub;
    ok(eval {( $out[0]->[0]{pw_ref}->is_blank &&
               $out[0]->[1]{pw_ref}->is_blank )} || $@,
       'tool: pw_ref goes');

    # RecipOTron::Storage emptying
    is(scalar @{ $out[0] }, 2, 'storage: 2');
    $R->forget;
    is(scalar @{ $out[0] }, 0, 'forget: 0');
}

# The refs have got a bit hairy here, sorry.  This is a yak of order
# approximately six, so it can stay slightly hairy.
sub blessy_tt {
    my $R = RecipOTron->new;
    my $S = Authen::Daemon::PassStash->new($R, 'usual');

    my $pw = [ 'beamMeUp' ];
    my $pwstr = \$pw->[0]; # SCALARref to the string

    # close-up of input password disappearing
    is($$pwstr, 'beamMeUp', 'pw is there');
    $S->set($pw);
    is(ref($pw), 'Authen::Daemon::AutoScrub', 'pw bless');
    is($$pwstr, '', 'pw input scrubbed');

    # get password out
    my @out = $S->utilise('list');
    my $out = $S->utilise('scalar');
    my @want_stored =
      ({ pw_ref => [ 'beamMeUp' ],
         pw_copy => [ 'ornzZrHc' ],
         arg => [qw[ usual list ]] },
       { pw_ref => [ 'beamMeUp' ],
         pw_copy => ['ornzZrHc'],
         arg => [qw[ usual scalar ]] } );
    is($out, 'scalar context', 'utilise: pass wantarray');
    is_deeply($out[0], \@want_stored, 'utilise: two calls'); # blessedness is not compared

    # close-up of 'utilise' password disappearing
    $pwstr = eval { \$out[0][0]->{pw_ref}[0] } || $@;
  SKIP: {
        is(eval { $$pwstr } || "$pwstr:$@", 'beamMeUp', 'yes, that scalarref')
          or skip 'would probably blow up', 1;
        $R->forget;
        is($$pwstr, '', 'pw gone');
    }
}

sub interface_tt {
    my @pw;
    my $S = Authen::Daemon::PassStash->new
      (sub {
           my ($me, $pw) = @_;
           push @pw, $$pw[0]; # generally bad, because it will not be scrubbed
       });
    $S->set([ 'shoulderserf' ]);
    $S->utilise;
    is_deeply(\@pw, [qw[ shoulderserf ]], 'interf: set');
    $S->clear;
    like(eval { $S->utilise } || "$@", qr{password.*not set}i, 'interf: cleared');
}


sub from_term_tt {
    _read_password_stubify();
    my $pw1 = Term::ReadPassword::read_password(qw(foo bar));
    my $want_ascr = get_last_pw_ascr()->new;
    $want_ascr->rot128; # unhide
    my $pw1_want = "$$want_ascr[0]:foo:bar";
    my $pw2 = Term::ReadPassword::read_password(qw( foo bar ));
    unless (is($pw1, $pw1_want, 'stubby password comes back') &&
            isnt($pw2, $pw1, 'stubby password differs next time')) {
        diagdump(pw1__got => $pw1, pw1_want => $pw1_want, pw2__got => $pw2);
    }

    my $got;
    my $S = Authen::Daemon::PassStash->new(sub { (undef, $got) = @_; });
    $S->set_from_term;
    $want_ascr = get_last_pw_ascr()->new;
    $want_ascr->rot128; # unhide
    $S->utilise;
    is($got->[0], "$$want_ascr[0]:Password: :0", 'set_from_term result');

    _stub_check();
}

{
    my $last_pw_ascr;
    sub _new_last_pw {
        my $tok = Devel::MemScan->token;
        $last_pw_ascr = Authen::Daemon::AutoScrub->new([ $tok ]);
        $last_pw_ascr->rot13; # break free of the copy in $tok
        $last_pw_ascr->rot128; # hide it from memscan
        return $last_pw_ascr->new; # return a copy
    }
    sub get_last_pw_ascr { # ascr : an autoscrub object
        return $last_pw_ascr;
    }
}

# here be pokery
sub _read_password_stubify {
    _stub_check();
    $INC{'Term/ReadPassword/Win32.pm'} =
      $INC{'Term/ReadPassword.pm'} = 'STUB';
    my $read = sub {
        my @arg = @_;
        my $new_pw_ascr = _new_last_pw();
        $new_pw_ascr->rot128;
        # return $$new_pw_ascr[0]; # is about to be scrubbed!
        return join ':', $$new_pw_ascr[0], @arg;
    };
    # place the stub where it comes from, and where we import it
    # because we don't fake the importer
    for my $pkg (qw( Term::ReadPassword Term::ReadPassword::Win32 Authen::Daemon::PassStash )) {
        no strict 'refs';
        *{"${pkg}::read_password"} = $read;
    }

    return ();
}
sub _stub_check {
    my $loaded = $INC{'Term/ReadPassword.pm'} ||
      $INC{'Term/ReadPassword/Win32.pm'};
    die "Cannot stubify, a Term::ReadPassword is loaded from $loaded"
      if $loaded && $loaded ne 'STUB';
    return ();
}


main();
