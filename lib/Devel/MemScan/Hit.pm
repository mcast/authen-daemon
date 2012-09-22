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

=head1 READ ACCESSORS

=head2 addr

Returns the byte offset from the bottom of the process memory space.

=head2 hexaddr

Returns L</addr> formatted as a hexadecimal string with leading C<0x>.

=head2 txt

Returns the captured text, or C<undef> if not available.

=cut

sub new {
    my ($proto, $self) = @_;
    $self ||= [];
    bless $self, ref($proto) || $proto;
    $self->_hide if @$self > 1;
    return $self;
}

sub _hide {
    my ($self) = @_;
    __obscure(\$$self[1], 1);
    return ();
}

sub addr {
    my ($self) = @_;
    return $$self[0];
}

sub hexaddr {
    my ($self) = @_;
    return sprintf('0x%x', $$self[0]);
}

sub txt {
    my ($self) = @_;
    my $txt = $$self[1];
    __obscure(\$txt, 0);
    return $txt;
}

# An extended rot13-alike, hoping to reduce self-match hits.
# This wouldn't be needed if searcher ran outside searchee.
sub __obscure { # selfsearch
    my ($txtref, $hide) = @_;
    $$txtref =~ tr/\x00-\x7f\x80-\xff/\x80-\xff\x00-\x7f/;
    return ();
}


1;
