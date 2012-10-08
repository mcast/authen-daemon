package # internal test tool
  DiagDump;
use strict;
use warnings;

use base 'Exporter';
our @EXPORT_OK = qw( diagdump );

my $dump =
  ((eval { require YAML     } && \&YAML::Dump    ) ||
   (eval { require YAML::XS } && \&YAML::XS::Dump) ||
   require Data::Dumper && sub { Data::Dumper->Dump([ \@_ ], [ 'data' ]) });

sub diagdump {
    my %info;
    if (@_ == 1) {
        # hashref - take its contents
        my ($h) = @_;
        %info = %$h;
        %$h = ();
    } else {
        # hash elements to show
        %info = @_;
    }
    return main::diag $dump->(\%info);
}

1;
