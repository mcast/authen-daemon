package Devel::MemScan;

use strict;
use warnings;

use Try::Tiny;

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

It's liable to change.  I assumed the most useful part of the result
would be the scalar size of the hit array, but flanking data may also
be handy.


=head1 METHODS

=head2 Devel::MemScan->scan($pat)

Class method.  Accepts a Regexp or CODE refs.

CODErefs are called with no arguments and should return a Regexp.
This allows the creation of the regexp to be postponed, possibly into
a child process where it won't cause false positives.
(Implemented but not so useful just yet.)

Returns C<($failed, @hit)>.

C<$failed> is C<undef> unless there is a problem, then it is text
describing the problem.  The method dies only for want of list
context.

C<@hit> are as above.

=cut

sub scan {
    my ($called, $pat) = @_;
    my $scan_pid = $$;

    die "expected wantarray" unless wantarray;

    my ($action, $failed, %hit);
    try {

        # if we're forking, do that now

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

                while ($buff =~ m{($pat)}g) {
                    my $match = $1;
                    my $mpos = pos($buff) - length($match);
                    obscure(\$match, 1);
                    $hit{ $bpos + ($mpos - $bufflen) } =  $match;
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

    obscure(\$hit{$_}, 0) foreach keys %hit;
    return ($failed, map {[ $_, $hit{$_} ]} sort { $a <=> $b } keys %hit);
}

sub scan_params {
    return (4096, 10000);
}

# an extended rot13-alike, hoping to reduce self-match hits
sub obscure {
    my ($txtref, $hide) = @_;
    $$txtref =~ tr/\x00-\x7f\x80-\xff/\x80-\xff\x00-\x7f/;
    return ();
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
of some regions.  It may also see hits due to the regexps used.

Under Linux at least, it is the easiest to do...


=head1 PLATFORMS

Platforms not mentioned are probably not supported.

=head2 Linux

This task looks simple on Linux (read F</proc/$pid/mem>) but it gets
more complicated when the reader is outside the process.

L<http://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux#answer-y6302y>
was useful - thanks @Gilles.

=head1 SEE ALSO

L<Win32::Process::Memory>.  I haven't looked at this.

=cut

1;
