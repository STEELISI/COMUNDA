#!/usr/bin/perl
# Input path to a file with labeled netflow files, and how
# many samples we want per A and B category.  Input more than you
# actually need, since some flows will be discarded at output time
# if they have had very little traffic. The code will
# generate vectors for training and testing ML algorithms for DDoS detection.
# Each vector will contain received number of packets per second, in the last
# vector_size seconds (one element of the vector = one second), for the given
# destination and traffic type

use Socket;
$vector_size = 60;
%samples=();
%type_samples=();
%collected=();
$collected{'B'} = 0;
$collected{'A'} = 0;
$total = 0;
$min_samples = $vector_size/4;

# This function selects which vectors to output and prepares them for output
# export_vector($dst, $s, $t, $label)
sub export_vector{
    ($dst, $s, $t, $label) = @_;
    # don't export vectors that have lots of zeros bc there was no traffic to that dst
    if (scalar(keys %{$traffic{$dst}{$s}}) < $min_samples && $label eq "B")
    {
	return;
    }
    $line = "";    
    for (my $i=$t-$vector_size+1; $i<=$t; $i++)
    {
	if (!exists($traffic{$dst}{$s}{$i}))
	{
	    $line .= "0,";
	}
	else
	{
	    $line .= "$traffic{$dst}{$s}{$i},";
	}
    }
    $line .= "$label\n";
    my $i=-1;
    if ($type_samples{$label} == 0)
    {
	return;
    }
    
    $r = rand();
    $n = $num_samples/$type_samples{$label};
    
    if ($r < $num_samples/$type_samples{$label})
    {
	$i = $collected{$label};
	$collected{$label}++;
    }
    if ($i > -1)
    {
	$rt = $total/($type_samples{'A'} + $type_samples{'B'});
	$samples{$label}{$i} = $line;
    }
}


$usage="$0 file-w-labeled-netflow num-samples\n";

if ($#ARGV < 1)
{
    print $usage;
    exit 1;
}
$num_samples = int($ARGV[1]);
if ($num_samples == 0)
{
    $num_samples = 1000;
}
my $fh = new IO::File("maptags.txt");
%filters=();
%traffic=();
while(<$fh>)
{
    my @items = split /\s+/, $_;
    $filters{$items[0]}{'proto'} = $items[3];
    $filters{$items[0]}{'sport'} = $items[4];
    $filters{$items[0]}{'dport'} = $items[5];
    $filters{$items[0]}{'flags'} = $items[6];
}
close($fh);
$firstt = 0;
$trained = 0;
# Measure prevalence of A and B samples in the population
# so we could set the sampling rate accordingly
open(my $fh, "grep A\$ $ARGV[0] | wc |");
$line=<$fh>;
@items = split /\s+/, $line;
$type_samples{'A'} = $items[1];
close($fh);
open(my $fh, "grep B\$ $ARGV[0] | wc |");
$line=<$fh>;
@items = split /\s+/, $line;
$type_samples{'B'} = $items[1];
# Read from labeled netflow and add to statistics
open(my $ih, "<", $ARGV[0]);
while(<$ih>)
{
    $line = $_;
    $line =~ s/\n//;
    my @items = split /\|/, $line;
    $stime = $items[1];
    $etime = $items[3];
    if ($firstt == 0)
    {
	$firstt = $etime;
    }
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
    $label = $items[24];
    $t = $etime - $firstt;
    $gap = $etime - $stime + 1;
    # did we collect enough samples from the very start
    # so that we can consider exporting vectors?
    if ($t >= $vector_size)
    {
	$trained = 1;	    
    }
    # since these are flows we have to divide the number of
    # total packets with the flow duration to get pkts per sec
    $p = $pkts/$gap;
    if ($p < 1)
    {
	$p = 1;
    }
    # Find out which attack this may fit
    # using its signature. If nothing fits we don't have to track
    # this type of traffic. Each traffic type is tracked separately, bc
    # some attacks create low volume of pkts or bytes but still
    # overwhelm some key resource
    for $s (keys %filters)
    {	    
	if (($filters{$s}{'proto'} == $proto || $filters{$s}{'proto'} eq "*") &&
	    ($filters{$s}{'sport'} == $sport || $filters{$s}{'sport'} eq "*") &&
	    ($filters{$s}{'dport'} == $dport || $filters{$s}{'dport'} eq "*") &&
	    (($filters{$s}{'flags'} & $flags) || $filters{$s}{'flags'} eq "*"))
	{
	    $traffic{$dst}{$s}{$t} += $p;
	    if ($trained == 1)
	    {
		export_vector($dst, $s, $t, $label);
	    }		
	}
    }
    $total++;
}
# Now print everything we collected. There still may be some
# imbalance between A and B classes. We will correct that in
# learning.
for (my $ti=0; $ti<$vector_size; $ti++)
{
    print "$ti,"
}   
print "label\n";
for (my $i=0; $i<$num_samples; $i++)
{
    print $samples{'A'}{$i};
    print $samples{'B'}{$i};
}
