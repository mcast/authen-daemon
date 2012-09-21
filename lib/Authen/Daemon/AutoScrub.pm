package Authen::Daemon::AutoScrub;
use strict;
use warnings;

=head1 NAME

Authen::Daemon::AutoScrub - temporary storage for a sensitive string

=head1 SYNOPSIS

 use Authen::Daemon::AutoScrub;
 my $P1 = Authen::Daemon::AutoScrub->new();
 my $P2 = Authen::Daemon::AutoScrub->new([ 'sekrit' ]);
 $P1->[0] = $P2->[0]; # copy contents
 undef $P2; # one copy left
 undef $P1; # secret is forgotten (hopefully)

=head1 DESCRIPTION

This class makes objects C<$obj> which are to be de-referenced as
C<$obj->[0]> for reading or writing.  It scrubs that first element
clean when the reference is DESTROYed.

This tool is intended to help other code not litter memory with copies
of a password.  There are some tests to see whether it is effective,
but it does seem to be a tricky thing to do.


=head1 METHODS

=head2 new()

As a class method, return a new blank object.

As an object method, return a new copy of the given object.

=head2 new($listref)

C<$listref> should be a reference to a one-element unblessed list.  It
will be blessed into this class, becoming the object returned.

Works the same whether called as a class or object method.

=cut

sub new {
    my ($proto, $self) = @_;
    $self = [ ] unless ref($self) eq 'ARRAY';
    bless $self, ref($proto) || $proto;
    @$self = ('') unless 1 == @$self;
    $$self[0] = $$proto[0] if ref($proto) && 1 == @_;
    return $self;
}


=head2 scrub()

Destroy the contents of the object, so far as is possible.

Leaves the object containing the empty string.  Returns nothing.

=cut

sub scrub {
    my ($self) = @_;
    my $L = length($$self[0]);
    for (my $i=0; $i<$L; $i++) {
        substr($$self[0], $i, 1) = "\x00";
    }
    $$self[0] = ''; # blank it, don't replace the SCALAR
    return ();
}


=head2 is_blank()

Predicate returns true when content is the empty string.

Being true suggests any previous data was scrubbed away, but it may
not have been.  There is no record of whether that was actually done.

=cut

sub is_blank {
    my ($self) = @_;
    return $$self[0] eq '';
}


sub __per_char(&$) {
    my ($code, $txtref) = @_;
    my $L = length($$txtref);
    for (my $i=0; $i<$L; $i++) {
        $code->() for substr($$txtref, $i, 1);
    }
    return ();
}

=head2 rot13() and rot128()

These methods are to assist unit testing.  Efficiency is not expected
to be great.

As object methods they operate on the contents.  Otherwise they may
also be passed a reference to an arbitrary scalar.

=cut

sub rot13 {
    my ($called, $txtref) = @_;
    return __per_char { tr/a-zA-Z/n-za-mN-ZA-M/ }
      ($txtref || \$called->[0]);
}

sub rot128 {
    my ($called, $txtref) = @_;
    return __per_char { tr/\x00-\xFF/\x80-\xFF\x00-\x7F/ }
      ($txtref || \$called->[0]);
}


sub DESTROY {
    my ($self) = @_;
    $self->scrub;
}

1;


=head1 CAVEATS

=over 4

=item * Nothing is (yet) done to support wide characters.  This will
affect L</rot13> and L</rot128>.

=item * Lists are expected to always contain one element.  Other
elements may be carelessly removed or ignored - behaviour is not
defined.

=back

=cut
