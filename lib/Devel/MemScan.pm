package Devel::MemScan;

use strict;
use warnings;

use Try::Tiny;
use Devel::MemScan::Hit;

=head1 NAME

Devel::MemScan - scan program memory for regex

=head1 SYNOPSIS

 my $re = qr{wi[b]ble}; # obfuscate or see as a hit!
 my ($failed, @hit) = Devel::MemScan->scan($re);
 SKIP: {
    skip "Devel::MemScan failed ($failed)", 1 if $failed;
    is(scalar @hit, 0, "hits for $re") or
       diag explain { hits => \@hit };
 }

=head1 DESCRIPTION

Search the raw memory of the calling process for something and return
any hits found.

This is a nosy, tricky, unstable and not-well-supported thing to need
to do.  If it proceeds without error you're doing well (and probably
running Linux).

In fact it's so likely to fail, the API does the error catching for
you.

=head2 Module in an unrelated dist

This module is provided to support the testing of another module which
is coincidental to its dist.  We are now shaving squared yaks - if you
want B<this> module distributed separately please let me know, or just
go ahead.

=head2 Hit format

Hits returned are instances of the class L<Devel::MemScan::Hit>.

The result may used just for the scalar size of the hit array, for the
exact hit value (where the pattern allows ambiguity), or to capture
flanking data.


=head1 METHODS

=head2 Devel::MemScan->scan($pat)

Class method.  Accepts a Regexp or CODE refs.

CODErefs are called with no arguments and should return a Regexp.
This allows the creation of the regexp to be postponed, possibly into
a child process where it won't cause false positives.
(Implemented but not so useful just yet.)

Returns C<($failed, @hit)>.  Text elements in the hits are the capture
groups C<($1 .. $9)>, truncating the tail of undefined ones.  Hits
matching without captures should be less likely to cause duplicates
further down memory.

C<$failed> is C<undef> for success, otherwise it is a (guaranteed
true) text describing the problem.  The method dies only for want of
list context.

C<@hit> is a list of L<Devel::MemScan::Hit>, as above.  They are in no
particular order.

=cut

sub scan {
    my ($called, $pat) = @_;
    my $hitclass = $called->hitclass;
    my $scan_pid = $$;

    die "expected wantarray" unless wantarray;

    my ($action, $failed, %hit);
    try {

        # if we're forking, do that before invoking CODEref

        $action = 'get regexp';
        if (ref($pat) eq 'CODE') {
            $pat = $pat->();
        }
        die "Pattern ($pat) isn't a Regexp"
          unless ref($pat) eq 'Regexp';

        $action = 'read maps';
        my @region = $called->_maps_linux($scan_pid);

        $action = 'read mem';
        my $fn = "/proc/$scan_pid/mem";
        open my $fh, '<', $fn or die "Read $fn: $!";
        binmode $fh;

        # these tweakbles are positional, and if overridden should
        # take defaults from superclass
        my ($bufflen, $maxhit) = $called->scan_params;

        my $buff = ' ' x (2 * $bufflen);
        foreach my $R (@region) {
            my ($start, $end, $what) = @$R;
            defined(sysseek $fh, $start, 0)
              or die "sysseek($fn, $start): $!";
            my $bpos = $start;
            while ($bpos < $end) {
                my $fetchlen = $end - $bpos;
                $fetchlen = $bufflen if $fetchlen > $bufflen;
                substr($buff, 0, $bufflen) =
                  substr($buff, $bufflen, $bufflen);
                my $readlen = sysread($fh, $buff, $bufflen, $bufflen);
                if (!defined($readlen)) {
                    # error - do next region
                    warn "sysread(at $bpos until $end): $!\n";
                } elsif ($readlen == 0) {
                    last; # eof
                }
                if ($readlen < $bufflen) {
                    substr $buff, $bufflen+$readlen, $bufflen-$readlen,
                      "\x00" x ($bufflen-$readlen);
                }

                while ($buff =~ m{$pat}g) {
                    my $mpos = $bpos +(pos($buff) -$bufflen);
                    # $mpos -= length($whole_match) # we don't have it!
                    $hit{$mpos} = $hitclass->new
                      ([ $mpos, $1, $2, $3, $4, $5, $6, $7, $8, $9 ]);
                    # hash overwrite allows for a more complete hit on
                    # second bufferful; assumes a left-anchored regex
                    die "Abort - too many hits" if keys %hit > $maxhit;
                }

                $bpos += $readlen;
            }
        }
    } catch {
        $failed = "During $action: $::_";
    };

    return ($failed, values %hit);
}



sub hitclass { # for override
    return 'Devel::MemScan::Hit';
}

sub scan_params { # for override
    return (4096, 10000);
}


sub _maps_linux {
    my ($called, $scan_pid) = @_;
    my $mapfn = "/proc/$scan_pid/maps";
    open my $mapfh, '<', $mapfn or die "Read $mapfn: $!";
    my @region;
    while (<$mapfh>) {
        my ($start, $end, $mode) =
          m{^([0-9a-f]+)-([0-9a-f]+) ([-a-z]{4}) [0-9a-f]+ [0-9a-f:]+ \d+\s+(.*)$}
            or die "$mapfn:$.: don't recognise $_";
        push @region, [ hex($start), hex($end), $_ ]
          if $mode =~ /^r/;
    }
    return @region;
}


=head1 PROBLEMS

Reading the process memory needs platform-specific support or a
compiled extension.  In order of preference for false positives and
efficiency,

=head2 Searching from outside

Forking a child process to scan its parent and return results on
STDOUT should produce fewer false positives.

Under (current) Linux it requires messing with C<ptrace>.  It is not
implemented.

=head2 Searching from inside, by XS

Of the "from inside" method, this would be the neatest.

It should also be the most portable.

It is not implemented.

=head2 Searching from inside, via filehandles

While the process searches its own memory space, it may see duplicates
of some regions.  It may also see hits on the regexps used, so try to
avoid that.

Under Linux at least, it is the easiest to do...


=head1 PLATFORMS

Platforms not mentioned are probably not supported.

=head2 Linux

This task looks simple on Linux (read F</proc/$pid/mem>) but it gets
more complicated when the reader is outside the process.

L<http://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux#answer-y6302y>
was useful - thanks @Gilles.


=head1 CAVEATS

=over 4

=item * If you are searching for large patterns you will need to
increase the size of the double-buffer window.

=item * While this implementation runs in-memory, taking hits'
contents is very likely to cause extra hits to show up.  Asserting
that there be "only one" hit is fragile.

XXX: More selective pattern capturing may mitigate this.

=item * During selfsearch, memory for hits is allocated in the process
memory space, but the memory map is not re-read.

This effect might be reduced if we assume memory is appended to the
address space, and work backwards through the memory map...  but I
hope to avoid this sort of futzing.

=item * The "address" of the hit is not covered in the test suite, so
may be off.

=item * During selfsearch, programs using the L<perlvar/$&> capture
variable could reasonably be expected to show repeat matches on the
buffer for that, in addition to all the other problems C<$&> causes.

=back


=head1 SEE ALSO

L<Win32::Process::Memory>.  I haven't looked at this.

=cut

1;
