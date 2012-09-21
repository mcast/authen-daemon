package # internal test tool
  RecipOTron;
use strict;
use warnings;
use Carp;

use Authen::Daemon::AutoScrub;

# for passStash.t

sub new {
    my ($proto) = @_;
    my @storage;
    my $obj;
    $obj = sub {
        my (@arg) = @_;
        return $obj->called(\@storage, @arg);
    };
    bless $obj, ref($proto) || $proto;
    bless \@storage, 'RecipOTron::Storage'; # diagnostic - has no methods
    return $obj;
}

sub called {
    my ($self, $storage, @coderef_arg) = @_;
    my ($obj, $pw, @arg) = @coderef_arg;
    carp "obj $obj is not me" unless $obj == $self;
    carp "pw $pw cannot scrub (_=@_)" unless eval { $pw->can('scrub') };
    my $copy = $pw->new; # clone
    $copy->rot13;
    push @$storage, { pw_ref => $pw,
                      pw_copy => $copy,
                      arg => [ @arg ] };
    return wantarray ? ($storage) : 'scalar context';
}

sub forget {
    my ($self) = @_;
    my ($storage) = $self->($self, Authen::Daemon::AutoScrub->new);
    @$storage = ();
    return ();
}

1;
