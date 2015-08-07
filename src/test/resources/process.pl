#!/usr/bin/env perl

my $current_curve = "";
my $k = "";
my $x = "";
my $y = "";

while (<STDIN>) {
  my $line = $_;
  chomp ($line);

  $line =~ s/-//g;

  if ($line =~ m/^ Curve: (.*)$/) {
    $current_curve = $1;
    next;
  }

  if ($line =~ m/^$/) {
    $k = "";
    $x = "";
    $y = "";
    next;
  }

  if ($line =~ m/^k = (.*)$/) {
    $k = $1;
    next;
  }

  if ($line =~ m/^x = (.*)$/) {
    $x = $1;
    next;
  }

  if ($line =~ m/^y = (.*)$/) {
    $y = $1;
  }

  if (($current_curve =~ m/^$/) || ($k =~ m/^$/) || ($x =~ m/^$/) || ($y =~ m/^$/)) {
    die "Input is invalid";
  }
  else {
    print "$current_curve,$k,$x,$y\n";
  }
}
