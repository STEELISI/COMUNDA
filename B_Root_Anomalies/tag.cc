// This code calls stats and tags attack records

#include<sys/time.h>
#include<vector>
#include<deque>
#include<algorithm>

#include "utils.h"

bool first = true;
bool attacksources = false;
long int starttime = 0;
long int endtime = 0;
long int lasttime = 0;

string readfolder = "";
string infile = "";
string atfile = "";
string extension = "";

set<string> queries;
set<string> attackers;
long int total = 0;
long int afiltered = 0, apassed = 0;
long int gfiltered = 0, gpassed = 0;
long int passed = 0;

// We store delimiters in this array
int* delimiters;


void loadattackers(string infile)
{
  ifstream in(infile, std::ofstream::in);
  while (in.good())
    {
      char ip[50];
      int req;
      in>>ip;
      if (!in.good())
	break;
      attackers.insert(ip);
      //cout<<"Inserted attacker "<<ip<<endl;
    }
  in.close();
}




int process(char* buffer, double &outtime, int& outlen, int& outttl)
{
  string ip = "";

  bool isquery;
  char queryname[MAXLEN];
  char recordID[MAXLEN];

  bool toprocess = shouldprocess2(buffer, outtime, outlen, delimiters,
				  ip, starttime, endtime, isquery, queryname, outttl);

  strcpy(recordID, buffer);
  if (!toprocess)
    {
      return 1;
    }

    bool isattack = false;
    if(!isquery || outlen > 256)
      isattack = true;
    if (isquery == 2 && queries.size() == 0)
      isattack = true;
    for (auto qit = queries.begin(); qit != queries.end(); qit++)
      if (strstr(queryname, qit->c_str()) != 0)
	{
	  isattack = true;	  
	}
    if (attackers.find(ip) != attackers.end() && attacksources)
      {
	isattack = true;
      }
    cout<<recordID<<" ";
    if (isattack)
      cout<<"A\n";
    else
      cout<<"B\n";
    return 0;
}


void printHelp()
{
  printf ("tag\n(C) 2022 University of Southern California.\n\n");

  printf ("-h                             Print this help\n");
  printf ("-r <folder>                    Folder with pcap.xz files to use in training\n");
  printf ("-s <epoch>                     Start processing from this epoch time in UTC\n");
  printf ("-e <epoch>                     End at this epoch time in UTC\n");
  printf ("-E <ext>                       Only process files with this extension in the name (e.g., lax, mia)\n");
  printf ("-a <file>                      Optionally read attack IPs from this file\n");
  printf ("-A                             Tag all traffic from attack IPs as attack\n");
  printf ("-q <query>                     This is a substring occuring in attack queries, you can repeat this arg spec multiple times\n");
}


// This is deployment version, we load trained values
// and use them to block resolvers that are more aggressive than
// their model

int main(int argc, char** argv)
{
  delimiters = (int*) malloc(AR_LEN*sizeof(int));
  char c;
  set<string> wildtrain;
  set<string> HCFtrain;
  set<string> URtrain;
  set<string> FQtrain;

  for (int i = 0; i<argc; i++)
    cout<<argv[i]<<" ";
  cout<<endl;
  while ((c = getopt (argc, argv, "hs:e:E:a:q:r:A")) != '?')
    {
      if ((c == 255) || (c == -1))
	break;

      switch (c)
	{
	case 'h':
	  printHelp ();
	  return (0);
	  break;
	case 'r':
	  readfolder = optarg;
	  break;
	case 'A':
	  attacksources = true;
	  break;
	case 'q':
	  queries.insert(optarg);
	  break;
	case 'a':
	  atfile = optarg;
	  break;
	case 's':
	  starttime = atol(optarg);
	  break;
	case 'e':
	  endtime = atol(optarg);
	  break;
	case 'E':
	  extension = optarg;
	  break;
	default:
	  break;
	}
    }
  if (readfolder == "")
    {
      cout<<"You must specify a directory with pcap.xz files\n";
      exit(0);
    }
  // Assume the attack has started and this is why we're being invoked
  // If we are testing it helps to use a file with attackers
  if (atfile != "")
    loadattackers(atfile);

  //Use for pcap
  loadfiles(readfolder.c_str(), process, extension, starttime, endtime);
}
  

