
= Introduction =

"Sharktools" is the name given to a small set of tools that allow use of
Wireshark's deep packet inspection capabilities in interpreted
programming languages.  The two currently supported interpreted
programming languages are Python and Matlab; "pyshark" is the name
of the tool for Python, and "matshark" is the name of the tool for
Matlab.

Sharktools is written in C.

= Basic Operational Concept =

1) A user collects packets using a packet sniffer (e.g. Wireshark or tcpdump)
and saves them in a pcap file.

2) Given an arbitrary pcap file, Sharktools uses Wireshark's Display Filter
technology (which knows how to parse thousands of common and obscure
network protocols) to cherry-pick packet fields of interest.

3) Sharktools then provides this data as a cell array of structs in Matlab, or
a list of dictionaries in Python.

4) A user can then plot packet fields with respect to time or carry out more
complicated analysis of packet captures in their favorite programming
environment.

= Authors =

Armen Babikyan of MIT Lincoln Laboratory <armenb@mit.edu>, for
* Sharktools core
* matshark
* pyshark
* bug fixes

Nathaniel Jones of MIT Lincoln Laboratory <njones@ll.mit.edu>, for
* bug fixes to Sharktools core and matshark

= Links = 

Sharktools makes use of the following third-party programs:

* Wireshark, http://www.wireshark.org
* libpcap, http://en.wikipedia.org/wiki/Pcap#libpcap
* Matlab, http://www.mathworks.com/products/matlab
* Python, http://www.python.org

= Known-working Platforms/Environments =

This software should work on both 32-bit and 64-bit Linux systems, with
relatively new versions of Matlab (R2007+), with relatively new versions of
Python (> 2.4) and relatively new versions of Wireshark (> 1.0).

Specifically, as of this writing, this software has been tested and is
confirmed working on:
 - RHEL5.5 + Matlab R2010a + Wireshark 1.0.11
 - RHEL5.5 + Matlab R2010a + Wireshark 1.2.7
 - RHEL5.5 + Python 2.4.3 + Wireshark 1.2.7
 - RHEL5.5 + Python 2.4.3 + Wireshark 1.4.0
 - Ubuntu 10.04.1 LTS + Python 2.6.5 + Wireshark 1.2.7
 - MacOSX 10.6 + Python 2.4.3 + Wireshark 1.4.0 (see README.MacOSX)
 - MacOSX 10.6 + Matlab R2010a + Wireshark 1.4.0 (see README.MacOSX)

See the FAQ below for answers to common problems/questions. For more
information, contact Armen Babikyan (armenb@ll.mit.edu).

= Features and Usage =

== Example Usage in Matlab ==

Pass matshark a pcap file, a list of wireshark fields of interest, and a
display filter string. matshark will return a cellarray of structs.

Example usage:

>> b = matshark('capture1.pcap', {'frame.number', 'ip.version', 'tcp.seq', 'udp.dstport', 'frame.pkt_len'}, 'ip.version eq 4')

b =

1x76 struct array with fields:
    frame_number
    ip_version
    tcp_seq
    udp_dstport
    frame_pkt_len

>> b(3)

ans =

     frame_number: 6
       ip_version: 4
          tcp_seq: []
      udp_dstport: 60000
    frame_pkt_len: 60

>>

Another example, showing usage of time fields and conversion of struct members
to an array:

>> c = matshark('capture1.pcap', {'frame.number', 'frame.time', 'frame.time_relative', 'frame.len', 'frame.protocols'}, '' )

c =

1x100 struct array with fields:
    frame_number
    frame_time
    frame_time_relative
    frame_len
    frame_protocols

>> c(9)

ans =

           frame_number: 9
             frame_time: 1.0664e+09
    frame_time_relative: 0.0228
              frame_len: 60
        frame_protocols: ''

>> t = [c.frame_time_relative];
>> t = t - t(1);
>> t(9)                        

ans =

    0.0228

>> 

Sometimes you can request pieces of data that are impossible to find in
packets.  For example, you should never have a tcp.seq and udp.dstport in the
same packet.  In this case, matshark will insert an empty list in its place;
pyshark will insert a None object in its place.

== Example Usage in Python ==

>>> import pyshark
>>> b = pyshark.read('capture1.pcap', ['frame.number', 'ip.version', 'tcp.seq', 'udp.dstport', 'frame.pkt_len'], 'ip.version eq 4')
>>> b[2]
{'frame.number': 6, 'tcp.seq': None, 'frame.pkt_len': 60, 'udp.dstport': 60000, 'ip.version': 4}
>>> c = pyshark.read('capture1.pcap', ['frame.number', 'frame.time', 'frame.time_relative', 'frame.len', 'frame.protocols'], '' )
>>> c[8]
{'frame.number': 9, 'frame.len': 60, 'frame.time': 1066402442.768941, 'frame.time_relative': 0.022801999999999999, 'frame.protocols': None}
>>>

== Using Wireshark's "Decode As" feature ==

Wireshark's packet dissection engine uses a combination of heuristics and
convention to determine what dissector to use for a particular packet. For
example, IP packets with TCP port 80 are, by default, parsed as HTTP packets.
If you wish to have TCP port 800 packets parsed as HTTP packets, you need to
tell the Wireshark engine your explicit intent.

Wireshark adds a "decode as" feature in its GUI that allows for users to
specify this mapping (Analyze Menu -> Decode As...).  Sharktools attempts to
provide a basic interface to this feature as well.  By adding a 4th (optional)
argument to both the matshark and pyshark commands, a user can achieve the
desired effect.  For example, the following "decode as" string will parse TCP
port 60000 packets as HTTP packets: 'tcp.port==60000,http'

= Building/Installation instructions =

You'll need a few things:

1) Install Wireshark, the packet capture tool:
     Ubuntu 10.04.1 LTS: apt-get install wireshark wireshark-dev
     RedHat Enterprise Linux 5: yum install wireshark

   See the FAQ below for MacOSX installation instructions.

   Make note of the version number.

   NB: The wireshark-dev package on Ubuntu creates the /usr/lib/wireshark/libwireshark.so
   symlink (among doing other things); this is necessary so pyshark and matshark
   can be built.

2) Install Glib-2.0 development package, which contains headers and libraries
   necessary for sharktools.  Practically all Linux distributions have glib-2.0,
   named something like glib2-devel (rpm-based systems) or libglib2.0-dev (deb-
   based systems).  On MacOSX, you will need Macports (preferred) or fink, but
   either distribution's glib2 should work fine.

   NB: glib 1.* and glib 2.* usaully coexist on Linux and MacOSX systems; you need
   the latter.

3) Install bison, flex, and libpcap-dev packages on your system:
      apt-get install bison flex libpcap-dev
      yum install bison flex libpcap-devel

   NB: These are only needed for the next step

4) Download, unpack, and run ./configure on the Wireshark source from
   http://www.wireshark.org.

   Be sure that you download the version of Wireshark that is roughly(*) the
   same as the version of Wireshark installed by your package management
   system.  The source to Wireshark is needed because your distribution's
   wireshark-dev package is generally not sufficient(**) to build sharktools.

   Unpack the tarball by running:
       tar -zxf wireshark-<version>.tar.gz
   Change into the soruce directory and run the following command(***):
       ./configure --disable-wireshark

   (*) Make sure the Major, Minor, and Sub-Minor numbers are the same.  For
        example, if you have the wireshark-1.0.8-1.el5_3.1 RPM package
        installed, you should download wireshark-1.0.8.tar.gz.  1.0.7 or 1.0.9
        won't cut it.

   (**) sharktools uses some data structures in wireshark's headers that are
        unfortunately not packaged with wireshark-dev package (e.g. cfile.h,
        file.h, print.h).  You only need these headers to build the software,
        and you can remove them afterwards.

   (***) Since we aren't actually building Wireshark, we need the
        "--disable-wireshark" argument to instruct the configure script to
        ignore the lack of gtk2 development headers and libraries on your
        system.  The word "wireshark" in --disable-wireshark is referring to
        the GUI frontend program. If you insist on leaving this argument off,
        note that you'll probably have to install the gtk2-dev(el) package
        on your system, or the configure script will thrown an error.

5) (Optional - needed for matshark) Install Matlab.  You will need its "mex"
   (Matlab EXternal) tool, which allows Matlab-accessible functions to be
   written in C.  For the most part, "mex" just wraps your C code, links
   in the proper libraries and headers, and calls gcc on your behalf.
   Make sure the "mex" program is in your path.

6) (Optional - needed for pyshark) Install Python and Python development
   packages on your system.  It is likely that python is already installed
   on your system.  The development packages can be downloaded and installed
   as simply as:
     apt-get install python-dev
     yum install python-devel

Clearly, you will want either Step 5 or Step 6 to be optional and not both.
By default, both are created.  You can disable one or the other by passing
--disable-{py,mat}shark to Sharktool's ./configure.

Once Glib, Wireshark, Matlab and Python have been installed:

  :~$ cd /path/to/wireshark-x.y.z

  :/path/to/wireshark-x.y.z$ ./configure --disable-wireshark

  :/path/to/wireshark-x.y.z$ cd /path/to/sharktools

  :/path/to/sharktools$ ./configure --with-wireshark-src=/path/to/wireshark-x.y.z

  :/path/to/sharktools$ make

  :/path/to/sharktools$ mv matshark.<suffix> /path/to/your/matlab/path

Where <suffix> is:
* "mexglx" on 32-bit Linux
* "mexa64" on 64-bit Linux
* "mexmaci" on 32-bit MacOSX
* "mexmaci64" on 64-bit MacOSX

You can add an arbitrary directory to your matlab path by adding the
following lines to your ~/matlab/startup.m file and restarting Matlab:

        % Add matshark to Matlab's path
        addpath /path/to/matshark

  :/parth/to/sharktools$ mv pyshark.so /path/to/your/pythonmodules

The PYTHONPATH environment variable is searched by the python interpreter for
external Python modules.  Be sure to run:

  $ export PYTHONPATH=/path/to/your/pythonmodules

To test this out, run:

  % matlab
  >> matshark
  ??? Must provide filename, cell array of fieldnames, and display filter
  
  >>

= FAQ/Troubleshooting =

Q: When I try to run matshark in Matlab, I get an error about 
   libwireshark/libwiretap not being found! What's wrong?

A: Make sure you have Wireshark libraries installed.  Usually a distribution
   will put them in /usr/lib, but if you know they are definitely somewhere
   else, set your LD_LIBRARY_PATH before running Matlab.

   NB: pyshark may have this same problem, and the solution is the same.

Q: mex is giving me an error:
    Warning: You are using gcc version "3.4.6".  The earliest gcc version
    supported with mex is "4.0.0".  The latest version tested for use with mex
    is "4.2.0". How do I fix this problem?

A: Either upgrade your gcc or downgrade your Matlab, because the binary output
   might not work.

   In particular, keep in mind the latest version of gcc that RHEL4 provides
   is 3.4.6.  RHEL5 provides gcc 4.*

Q: MacOSX support?

A: There has been a successful port of sharktools to MacOSX; see the
   INSTALL.MacOSX file for details.

Q: Windows support?

A: No effort has been made to port this tool to Windows.  Sticking to a
   un*x-like Operating system is probably your best bet, but reasonable
   patches are welcome.

= Notes and General Design Information =

This tool is comprised of two pieces:

1) A "core" which exports the functionality of libwireshark into a simple API.
   This core is compiles into libsharktools.a, a static library which dynamically
   links to libwireshark.so and libwiretap.so.

2) An environment-specific portion which links to either the Matlab or Python
   environments.

   In Matlab, the output of this is matshark.mex{glx, a64}, which is the Matlab
   module that is the final product. This Matlab module staticly links to
   libsharktools.a. The glx vs. a64 extension is Matlab's way of identifying
   32-bit vs. 64-bit code on Linux.  Other OS's will have different extensions.

   In Python, the output is pyshark.so, which is a shared library that is
   dynamically loaded by the python interpreter

In the past, when this tool was called "ll-matlab-wireshark", this tool
   operated as follows:

   1) Open a (potentially giant) pcap file
   2) Read the whole thing into memory as a linked list
   3) Close the pcap file
   4) Create a memory structure for the interpreted programming language
   5) Copy from the giant linked list to the interpreted language's native structure
   6) Delete the internal linked list
   7) Return control back to the interpreter.

This approach was simple, but was very memory inefficient.  Since then,
sharktools has evolved to implement a set of callbacks that are registered by
the environment-specific portion of the code, and run by the "core".  This
approach reduces the overall memory footprint of the tool at the cost of some
complexity (and in the case of Matlab, time; see matshark.c for notes).

This tool attempts to create native objects in the host environment and
efficiently copy data to them.  For this reason, we have different copy
conversion routines for different data types (e.g. ints vs. doubles). Some
types, e.g. MAC addresses, have no native type, so they are simply copied
as strings.

== Versioning nightmare? ==

You may have noticed that this tool seems very particular about the versions
of gcc, Matlab, and Wireshark that are used.  Unfortunately this is necessary.

=== Wireshark versioning problem ===

The first problem is that Wireshark is provided as a monolithic package with
1) Executable binaries ("wireshark", "tshark", "rawshark", etc), and
2) Some dynamic libraries ("libwireshark.so", "libwiretap.so", etc.) that are
   used by those executables.

Unfortunately, the Wireshark project does this for memory efficiency and not
for modularity: the API between the executables and the libraries has the
potential to change with every release of Wireshark, which makes dealing with
libwireshark.so itself a version-dependent effort.  The configure script
knows how to deal with some specific versions, and tries to figure out
what version of Wireshark is being used, and passes appropriate -D tags to
the compiler to include and exclude chunks of code based on whats needed for
each of these versions.  This technique may not be possible in the future
if/when the Wireshark decides to radically change their API.  Hopefully
they'll eventually come to a stable API and commit to providing some backwards
compatibility in the future.

See above for the versions we've tested on.

=== Matlab versioning problem ===

Each version of Matlab comes with a version of mex, which is its external
module building script/tool.  mex started requiring newer versions of gcc
between R2006* and R2007*, and RHEL4 does not provide these, whereas RHEL5
does.

== Future work ==

Fixing memory leaks, of course.

The Python wrapper could use more miles of use. Send Armen feedback!

The Python implementation currently does not use Python iterators.  By doing
so, we could be much more memory efficient. More information about python
iterators is at:

  http://www.ibm.com/developerworks/library/l-pycon.html
  http://heather.cs.ucdavis.edu/~matloff/Python/PyIterGen.pdf

These past TODO items have already been addressed:

*Identified inefficiency:  some data types are rendered as strings, only to be
*rendered back by pyshark or matshark.  This definitely does not need to happen
*for certain classes of data types (integers and floats in particular).

*The wireshark engine uses callbacks to get information. These callbacks could
*call back into the interpreted language modules and create native data
*structures, and this technique could greatly reduce the amount of memory taken
*used by the module.

*The Matlab module uses a superlinear amount of memory (with respect to pcap
*file size). This is probably a fault of this module, but apparently Matlab
*could be the problem (since it has a reputation for leaking memory).  Nathan
*has a hack around this right now (tshark_read_block), but fixing here would
*be the best idea.

= Other Notes =

sharktools generally runs CPU-bound and not IO-bound.

As previously mentioned, mex calls gcc on a user's behalf.  Unfortunately,
for whatever reason, mex passes the -ansi flag to gcc by default, which
prevents the use of //-style comments.  If a user really wants to use
//-style comments, they will have to edit $MATLAB_HOME/bin/mexopts.sh.
The magic incantation can also be done via command line, e.g. adding this
line to the SConstruct file:
envMex['MEXFLAGS'] = "-v -g CFLAGS='-fPIC -D_GNU_SOURCE -pthread -fexceptions -m32'"

