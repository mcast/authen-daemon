use strict;
use warnings;
package Authen::Daemon::AutoScrub;
use Carp;

=head1 NAME

Authen::Daemon::AutoScrub - temporary storage for a sensitive string

=head1 SYNOPSIS

 use Authen::Daemon::AutoScrub;
 my $P1 = Authen::Daemon::AutoScrub->new();
 my $P2 = Authen::Daemon::AutoScrub->new([ 'sekrit' ]);
 $$P1[0] = $$P2[0]; # copy contents
 undef $P2; # one copy left
 undef $P1; # secret is forgotten (hopefully)

=head1 DESCRIPTION

This class makes objects C<$obj> which contain one scalar which is to
be scrubbed clean when C<$obj> is C<DESTROY>ed.

It is intended to help other code not litter memory with copies of a
password.  There are some tests to see whether it is effective, but it
does seem to be a tricky thing to do.


=head1 ACCESSORS

It is unclear whether these accessors are as safe, in the sense of not
creating copies of data transferred, as direct access.  For this
reason I recommend not using them yet.

=head2 get()

Returns a copy of the contents as a scalar.

=head2 set($value)

Set C<$value> into the object.  Caller is responsible for ensuring the
input is not left around.

=cut

sub get {
    my ($self) = @_;
    return $$self[0];
}
sub get_ { $_[0]->[0] }
sub set { $_[0]->[0] = $_[1] }

sub set_ {
    my $self = shift;
    croak "Need one value" unless 1 == @_;
    $$self[0] = $_[0];
    eval { _scrub(\$_[0]); }; # scrub it, but beware constants (read-only)
    return ();
}


=head2 Direct access - possibly deprecated?

The entire point of this class is to ensure that temporary values
passed around are not abandoned in unused memory.

This initially seemed to require direct arrayref access, so there were
no accessors and the object was de-referenced as C<$obj->[0]> for
reading or writing.

Testing showed that normal accessors can work without leaving copies
around, but those tests are fragile - cause of failure unknown.

For this reason I suggest accessing the value as C<$$foo[0]> with a
controlled set of names C<foo>, so they may be found and replaced more
easily later.


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
    return _scrub(\$$self[0]);
}

sub _scrub {
    my $scref = $_[-1]; # as method or sub
    my $L = length($$scref);
    for (my $i=0; $i<$L; $i++) {
        substr($$scref, $i, 1) = "\x00";
    }
    $$scref = '';
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


sub __per_char {
    my ($txtref, $code) = @_;
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
    return __per_char($txtref || \$called->[0],
                      sub { tr/a-zA-Z/n-za-mN-ZA-M/ });
}

sub rot128 {
    my ($called, $txtref) = @_;
    return __per_char($txtref || \$called->[0],
                      sub { tr/\x00-\xFF/\x80-\xFF\x00-\x7F/ });
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
