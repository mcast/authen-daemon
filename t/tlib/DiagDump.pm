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
    my %info = @_;
    return main::diag $dump->(\%info);
}

1;
