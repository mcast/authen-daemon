package Devel::MemScan::Hit;
use strict;
use warnings;

=head1 NAME

Devel::MemScan::Hit - result from Devel::MemScan

=head1 DESCRIPTION

This class wraps up hits found by the memory scanner, hopefully in a
way which doesn't cause spurious repeat hits during self-searches.

The methods then allow access to the contents, undoing whatever tricks
are used to obscure them during the search.

=cut

sub new {
    my ($proto, $self) = @_;
    $self ||= [];
    bless $self, ref($proto) || $proto;
    $self->_trim if @$self > 1;
    $self->_hide if @$self > 1;
    return $self;
}

sub _trim {
    my ($self) = @_;
    while (@$self && !defined $$self[-1]) { pop @$self }
    return ();
}

sub _hide {
    my ($self) = @_;
    for (my $i=1; $i<@$self; $i++) {
        __obscure(\$$self[$i], 1);
    }
    return ();
}


=head1 READ ACCESSORS

=head2 addr

Returns the byte offset from the bottom of the process memory space.

You probably need to subtract the match length from this to get the
exact address.  It is not well tested.

=head2 hexaddr

Returns L</addr> formatted as a hexadecimal string with leading C<0x>.

=cut

sub addr {
    my ($self) = @_;
    return $$self[0];
}

sub hexaddr {
    my ($self) = @_;
    return sprintf('0x%x', $$self[0]);
}


=head2 txt(@idx)

Returns captured text(s) of specified 0-based index or indices, from
the match pattern given to L<Devel::MemScan/scan>.

In scalar context, the default is C<@idx = (0)>.  In list context the
default is all available capture elements.

In scalar context, multiple elements are concatenated.  In list
context they are returned as a list, as with array L<perldata/Slices>.

(These context semantics may be too overloaded.  If they need to
change, a new method will be added and this one deprecated.)

=cut

sub txt {
    my ($self, @idx) = @_;
    if (!@idx) {
        # defaults
        @idx = wantarray ? (1 .. $#{$self}) : (1);
    } else {
        # convert to @$self index
        @idx = map { $_ + 1 } @idx;
    }
    my @txt = @$self[ @idx ];
    for (my $i=0; $i<@txt; $i++) {
        __obscure(\$txt[$i], 0);
    }
    return(wantarray
           ? @txt
           : join '', map { defined $_ ? $_ : '' } @txt);
}


=head2 dumpable()

Object method.  Return a listref of C<(hexaddr, txt)> suitable for
sending to a data dumper.

=cut

sub dumpable {
    my ($self) = @_;
    return [ $self->hexaddr, $self->txt ];
}


# An extended rot13-alike, hoping to reduce self-match hits.
# This wouldn't be needed if searcher ran outside searchee.
sub __obscure { # selfsearch
    my ($txtref, $hide) = @_;
    $$txtref =~ tr/\x00-\x7f\x80-\xff/\x80-\xff\x00-\x7f/
      if defined $$txtref;
    return ();
}


1;
