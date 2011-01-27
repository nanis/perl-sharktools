use 5.008001;
use ExtUtils::MakeMaker;
use warnings; use strict;

use lib qw(inc);
use Devel::CheckLib;

# No support for Win32 yet
die "OS unsupported\n" if $^O eq 'MSWin32';

use File::Spec::Functions qw( catfile );
use Getopt::Long;

my %argv;
GetOptions(
    \%argv,
    'sharktools-src=s',
    'wireshark-src=s',
    'lib-path=s@',
    'inc-path=s@',
);

unless ( defined $argv{'sharktools-src'} ) {
    $argv{'sharktools-src'} = catfile(
        $ENV{HOME}, qw(sharktools sharktools-0.1.5 src) );
}

unless ( defined $argv{'wireshark-src'} ) {
    $argv{'wireshark-src'} = catfile(
        $ENV{HOME}, qw(sharktools wireshark-1.4.2) );
}

unless ( defined $argv{'lib-path'} ) {
    $argv{'lib-path'} = [ qw( /usr/lib ) ];
}

unless ( defined $argv{'inc-path'} ) {
    $argv{'inc-path'} = [qw(
        /usr/include/glib-2.0
        /usr/lib/glib-2.0/include
    )];
}

my @LIBS = qw(sharktools glib-2.0 wireshark wiretap wsutil);
my @HEADERS = qw(glib.h sharktools_core.h epan/ftypes/ftypes.h);

my $LIBS = join ' ', (
    (map "-L$_", $argv{'sharktools-src'}, @{ $argv{'lib-path'} }),
    (map "-l$_", @LIBS),
);

my $INC = join ' ', (map "-I$_", 
    @{ $argv{'inc-path'} }, 
    $argv{'wireshark-src'},
    catfile($argv{'wireshark-src'}, 'wiretap'),
    $argv{'sharktools-src'},
);

# Check some canaries to see if we have the required environment

check_lib_or_exit(
    lib => \@LIBS,
    header => \@HEADERS,
    LIBS => $LIBS,
    INC => $INC,
);





WriteMakefile(
    NAME              => 'Net::Sharktools',
    VERSION_FROM      => 'lib/Net/Sharktools.pm',

    BUILD_REQUIRES    => {
        'File::Spec::Functions' => 0,
        'Getopt::Long'          => 0,
    },

    PREREQ_PM         => {},
    MIN_PERL_VERSION => '5.008001',

    ($] >= 5.005 ? 
      (ABSTRACT_FROM  => 'lib/Net/Sharktools.pm', 
       AUTHOR         => 'A. Sinan Unur <nanis@cpan.org>') : ()),
    
    LIBS              => [ $LIBS ],
    
    CCFLAGS           => '-Wall -Werror',
    DEFINE            => '', 
    
    INC               => $INC,
);
