use 5.008001;
use ExtUtils::MakeMaker;
use warnings; use strict;

WriteMakefile(
    NAME              => 'Net::Sharktools',
    VERSION_FROM      => 'lib/Net/Sharktools.pm',
    PREREQ_PM         => {},
    ($] >= 5.005 ? 
      (ABSTRACT_FROM  => 'lib/Net/Sharktools.pm', 
       AUTHOR         => 'A. Sinan Unur <nanis@cpan.org>') : ()),
    LIBS              => [ join ' ', (
        "-L$ENV{HOME}/sharktools/sharktools-0.1.5/src", qw(
        -L/usr/lib
        -lsharktools
        -lglib-2.0
        -lwireshark -lwiretap -lwsutil
    ))],
    CCFLAGS           => '-Wall -Werror',
    DEFINE            => '', 
    INC               => join(' ', qw(
        -I.
        -I/usr/include/glib-2.0
        -I/usr/lib/glib-2.0/include
    ),  "-I$ENV{HOME}/sharktools/wireshark-1.4.2",
        "-I$ENV{HOME}/sharktools/wireshark-1.4.2/wiretap",
        "-I$ENV{HOME}/sharktools/sharktools-0.1.5/src",
    ),
);
