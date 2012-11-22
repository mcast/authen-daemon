use strict;
use warnings;
package Authen::Daemon::PassStash;
use Carp;
use Authen::Daemon::AutoScrub;

=head1 NAME

Authen::Daemon::PassStash - hold plaintext password for a daemon

=head1 DESCRIPTION

See L<Authen::Daemon> for the overview.


=head1 METHODS

=head2 new($recip, @args)

C<$recip> is a CODEref, to be called by L</utilise>.  Blessed CODErefs
are also acceptable.

C<@args> are additional arguments to pass to $recip.  They are
shallow-copied into the object.

=cut

sub new {
    my ($proto, $recip, @args) = @_;

    my $self = bless { _recip => $recip, _args => [ @args ] },
      ref($proto) || $proto;

    return $self;
}


=head2 utilise(@argmore)

Obtains the password internally, then calls

 $recip->($recip, [ $password ], @args, @argmore)

propagating the C<wantarray>, where C<@args> are from L</new>.

A copy of the password is passed in a one-element ARRAYref.  This will
be scrubbed clean when you drop the last reference to it.

L</utilise> returns the output of C<$recip>.

=head2 set([ $pass ])

Note that the password is given as a reference to a one-element ARRAY.
The contents are destructively overwritten during the set operation,
after the password is copied into this object.

=cut

{
    my %pass;
    sub utilise {
        my ($self, @argmore) = @_;
        croak "Password is not set"
          unless defined $pass{$self};
        my $code = $self->{_recip};
        croak "I have no recipient for the password"
          unless defined $code;
        my $pw = $pass{$self}->new; # clone
        return $code->($code, $pw, @{ $self->{_args} }, @argmore);
    }
    sub set {
        my ($self, $pass_aref) = @_;
        if (defined $pass_aref) {
            eval { 1 == @$pass_aref } or
              croak 'Requires an ARRAY ref';
            $pass_aref = Authen::Daemon::AutoScrub->new($pass_aref);
            $pass{$self} = $pass_aref->new; # copy
            $pass_aref->scrub;
        } else {
            delete $pass{$self};
        }
        return defined $pass{$self} && $pass{$self}->[0] ne '';
    }
}


=head2 clear()

Forget the password.  This is also done during C<DESTROY>.

=cut

sub clear {
    my ($self) = @_;
    $self->set(undef);
    return ();
}

sub DESTROY {
    my ($self) = @_;
    $self->clear;
}


=head2 set_from_term($prompt, $timeout)

C<$prompt> defaults to C<Password: >.

This method attempts to set the password using
L<Term::ReadPassword::Win32> or L<Term::ReadPassword>, or dies if
neither is found.

Returns true iff a non-empty password is obtained and stored.

=cut

sub set_from_term {
    my ($self, $prompt, $timeout) = @_;
    $prompt ||= 'Password: ';
    $timeout ||= 0;

    my $loaded =
      (eval { require Term::ReadPassword::Win32; 'Term::ReadPassword::Win32' } ||
       eval { require Term::ReadPassword; 'Term::ReadPassword' });
    croak "Could not load a Term::ReadPassword: $@" unless $loaded;

    $loaded->import('read_password');

    my @pass = read_password($prompt, $timeout);
    return $self->set(\@pass);
}

1;


=head1 CAVEATS

=over 4

=item * Doesn't use L<SecretPipe> (the code or the trick)

=item * Uses L<Term::ReadPassword::Win32> opportunistically over
L<Term::ReadPassword> because it seems to be newer

This is not a promise that the code is maintained for Win32.

=item * Currently relies heavily on L<Authen::Daemon::AutoScrub> to do
various passing around and cleaning of password values.

Some of these uses could change - don't rely on it.

=back

=cut
