#!/usr/bin/env perl

# tests source files for unwanted issues:
# - CRLF newlines
# - tabs \t
# - trailing spaces
# - unresolved merge conflicts

use strict;
use warnings;

use Test::More;
use File::Find 'find';
use File::Basename 'basename';
use File::Glob 'bsd_glob';

sub read_file {
  my $f = shift;
  open my $fh, "<:raw", $f or die "FATAL: read_rawfile() cannot open file '$f': $!";
  return do { local $/; <$fh> };
}

my @all_files = (bsd_glob("makefile*"), bsd_glob("*.sh"), bsd_glob("*.pl"));
find({ wanted=>sub { push @all_files, $_ if -f $_ }, no_chdir=>1 }, qw/src testprof demos/);

my $fails = 0;
for my $file (sort @all_files) {
  next unless $file =~ /\.(c|h|pl|py|sh)$/ || basename($file) =~ /^makefile/i;
  my $troubles = {};
  my $lineno = 1;
  my $content = read_file($file);
  push @{$troubles->{crlf_line_end}}, '?' if $content =~ /\r/;
  for my $l (split /\n/, $content) {
    push @{$troubles->{merge_conflict}}, $lineno if $l =~ /^(<<<<<<<|=======|>>>>>>>)([^<=>]|$)/;
    push @{$troubles->{trailing_space}}, $lineno if $l =~ / $/;
    push @{$troubles->{tab}}, $lineno            if $l =~ /\t/ && basename($file) !~ /^makefile/i;
    $lineno++;
  }
  for my $k (sort keys %$troubles) {
    warn "FAIL: [$k] $file line:" . join(",", @{$troubles->{$k}}) . "\n";
    $fails++;
  }
}

warn $fails > 0 ? "FAILED $fails\n" : "PASS\n";