#!/usr/bin/perl

use strict;
use warnings;

open(my $in, '<', 'crypt.ind');
open(my $out, '>', 'crypt.ind.tmp');
my $a = <$in>;
print {$out} "$a\n\\addcontentsline{toc}{chapter}{Index}\n";
while (<$in>) {
   print {$out} $_;
}
close $out;
close $in;
system("mv -f crypt.ind.tmp crypt.ind");

