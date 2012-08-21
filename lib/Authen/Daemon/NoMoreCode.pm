package Authen::Daemon::NoMoreCode;
use strict;
use warnings;
use Carp;

=head1 NAME

Authen::Daemon::NoMoreCode - prevent code load after main compilation

=head1 SYNOPSIS

 # manual
 use Authen::Daemon::NoMoreCode;
 use Other::Stuff;
 BEGIN { Authen::Daemon::NoMoreCode->embargo }
 use Late::Stuff; # boom

 # auto
 use Authen::Daemon::NoMoreCode 'auto';
 use Other::Stuff;
 require Late::Stuff; # boom

=head1 DESCRIPTION

This module I<bolts the door> to prevent more code coming in.

The intention is to not leave a window open, through which changes to
the filesystem can affect late compilation in a running program.  Once
code is loaded and compiled, that is the end of it.

=head1 CAVEATS

It only works against accidental C<requires>, because the effect is
easily reversed or circumvented.

This trick breaks any code expecting to lazy-load its dependencies, so
we pay for security with brittleness.

It might be better used in test suites and left off during production?

=cut

sub embargo {
    my ($pkg) = @_;
    $pkg->_noinc(__whence());
    return;
}

sub __whence {
    return sprintf("%s line %s", (caller(1))[1,2]);
}

sub _noinc {
    my ($pkg, $whence) = @_;
    unshift @INC, sub {
        my ($me, $file) = @_;
        croak "require($file): embargo from $whence via $pkg";
    };
    return;
}

my $auto = 0;
sub import {
    my ($pkg, @opt) = @_;
    while (my $sw = shift @opt) {
        if ($sw eq 'auto') {
            $auto = __whence();
        } else {
            croak "Unknown $pkg import '$sw'";
        }
    }
    return;
}

INIT {
    __PACKAGE__->_noinc($auto) if $auto;
}


# ensure stuff we need is loaded!
sub _bodge {
    eval { croak "ribbit" };
    return;
}

_bodge();

1;
