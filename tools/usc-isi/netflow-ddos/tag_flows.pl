#!/usr/bin/perl
# Input path to a folder containing netflow files and another path to
# a folder containing attack information. All netflow data will be parsed
# into -o pipe format and the code will attach label A for attack or
# B for benign.
#
# IMPORTANT: This program should be run on a machine with nfdump installed
#

use Socket;

$usage="$0 path-to-folder-w-netflow path-to-folder-w-attack-files\n";

if ($#ARGV < 1)
{
    print $usage;
    exit 1;
}
# Read attack names and signatures
my $fh = new IO::File("maptags.txt");
%filters=();
%attacks=();
while(<$fh>)
{
    my @items = split /\s+/, $_;
    $filters{$items[0]}{'proto'} = $items[3];
    $filters{$items[0]}{'sport'} = $items[4];
    $filters{$items[0]}{'dport'} = $items[5];
    $filters{$items[0]}{'flags'} = $items[6];
}
close($fh);
# Read and remember attack data
opendir($dh, $ARGV[1]);
my @files=readdir($dh);
for $f (@files)
{
    if ($f =~ /^\./)
    {
	next;
    }
    open(my $fh, $ARGV[1] . "/" . $f);
    $i=0;
    while(<$fh>)
    {
	my @items = split /\s+/, $_;
	if ($i == 0)
	{
	    $target = $items[1];
	}
	elsif($i == 1)
	{
	    # assumes start time is unique per attack target
	    $start = $items[1];
	    $attacks{$start}{'target'} = $target;
	}
	elsif($i == 2)
	{
	    $end = $items[1];
	    $attacks{$start}{'start'} = $start;
	    $attacks{$start}{'end'} = $end;
	}
	elsif($i == 3)
	{
	    $j=1;
	    while ($j <= $#items)
	    {
		$type = $items[$j];
		if (!exists($attacks{$start}{'filter'}))		    
		{
		    %{$attacks{$start}{'filter'}} = ();
		}
		$attacks{$start}{'filter'}{$j-1}{'type'} = $type;
		$attacks{$start}{'filter'}{$j-1}{'proto'} = $filters{$type}{'proto'};
		$attacks{$start}{'filter'}{$j-1}{'sport'} = $filters{$type}{'sport'};
		$attacks{$start}{'filter'}{$j-1}{'dport'} = $filters{$type}{'dport'};
		$attacks{$start}{'filter'}{$j-1}{'flags'} = $filters{$type}{'flags'};
		$j++;
	    }
	    last;
	}
	$i++;
    }
}
closedir($dh);
# Read netflow data
opendir($dh, $ARGV[0]);
my @files=readdir($dh);
for $f (sort @files)
{
    if ($f =~ /^\./)
    {
        next;
    }
    open(my $ih, "nfdump -r $ARGV[0]/$f -o pipe |");
    while(<$ih>)
    {
	$line = $_;
	$line =~ s/\n//;
	my @items = split /\|/, $line;
	$stime = $items[1];
	$etime = $items[3];
	$proto = $items[5];
	$src = $items[9];
	$src = inet_ntoa(pack('N',$src));
	$sport = $items[10];
	$dst = $items[14];
	$dst = inet_ntoa(pack('N',$dst));
	$dport = $items[15];
	$flags = $items[20];
	$pkts = $items[22];
	$bytes = $items[23];

	$label = 'B';
	for $s (sort {$a <=> $b} keys %attacks)
	{
	    $c1 = (($attacks{$s}{'start'} >= $stime) && ($attacks{$s}{'start'} <= $etime));
	    $c2 = (($attacks{$s}{'end'} >= $stime) && ($attacks{$s}{'end'} <= $etime));
	    $c3 = (($attacks{$s}{'start'} <= $stime) && ($attacks{$s}{'end'} >= $stime));
	    $c4 = (($attacks{$s}{'start'} <= $etime) && ($attacks{$s}{'end'} >= $etime));
	    # Match on target and time
	    if ($attacks{$s}{'target'} eq $dst && ($c1 || $c2 || $c3 || $c4))
	    {
		# Match on attacks
		for $j (keys %{$attacks{$s}{'filter'}})
		{
		    if (($attacks{$s}{'filter'}{$j}{'proto'} == $proto || $attacks{$s}{'filter'}{$j}{'proto'} eq "*") &&
			($attacks{$s}{'filter'}{$j}{'sport'} == $sport || $attacks{$s}{'filter'}{$j}{'sport'} eq "*") &&
			($attacks{$s}{'filter'}{$j}{'dport'} == $dport || $attacks{$s}{'filter'}{$j}{'dport'} eq "*") &&
			(($attacks{$s}{'filter'}{$j}{'flags'} & $flags) || $attacks{$s}{'filter'}{$j}{'flags'} eq "*"))
		    {			
			$label = 'A';
			last;
		    }
		}
	    }
	}
	print "$line|$label\n";
    }
}
