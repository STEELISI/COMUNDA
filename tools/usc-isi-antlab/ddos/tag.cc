// This code calls stats and tags attack records

#include<sys/time.h>
#include<vector>
#include<deque>
#include<map>
#include<algorithm>

#include "utils.h"

bool first = true;
bool attacksources = false;
bool atlist = false;
int PERIOD = 60;
long int starttime = 0;
long int endtime = 0;
double lasttime = 0;

string readfolder = "";
string infile = "";
string atfile = "";
string extension = "";

set<string> queries;

int attackers[(int)pow(2,27)];

long int total = 0;
long int afiltered = 0, apassed = 0;
long int gfiltered = 0, gpassed = 0;
long int passed = 0;

// We store delimiters in this array
int* delimiters;

void loadattackers(string infile)
{
  memset(attackers, 0, pow(2,24)*8);
  int i = 0;
  ifstream in(infile, std::ofstream::in);
  while (in.good())
    {
      char ip[50];
      int req;
      in>>ip;
      if (!in.good())
	break;
      unsigned int ipi=todec(ip);
      attackers[int(ipi/32)] = attackers[int(ipi/32)] | (1 >> (ipi % 32));
      i++;
      if (i % 100000 == 0)
	cout<<"Inserted attacker "<<ip<<endl;
    }
  in.close();
}

string process(char* buffer, double &outtime, int& outlen, int& outttl, std::ofstream& output)
{
  string ip = "";

  int isquery;
  char queryname[MAXLEN];
  char recordID[MAXLEN];

  bool toprocess = shouldprocess2(buffer, outtime, outlen, delimiters,
				  ip, starttime, endtime, isquery, queryname, outttl);


  strcpy(recordID, buffer);
  if (!toprocess)
    return "";

  bool isattack = false;
  if((!isquery || outlen > 256) && queries.size() == 0)
    isattack = true;
  //cout<<"For "<<buffer<<" is query "<<isquery<<" queries size "<<queries.size()<<endl;
  if (isquery == 2 && queries.size() == 0)
    isattack = true;
  for (auto qit = queries.begin(); qit != queries.end(); qit++)
    if (strstr(queryname, qit->c_str()) != 0)
      {
	isattack = true;
      }

  if (attacksources && isattack && !atlist)
    {
      unsigned int ipi=todec(ip);
      attackers[int(ipi/32)] = attackers[int(ipi/32)] | (1 >> (ipi % 32));
    }
  if (attacksources && !isattack)
    {      
      unsigned int ipi=todec(ip);
      int cur = attackers[int(ipi/32)] & (1 >> (ipi % 32));
      if (cur > 0)
	{
	  isattack = true;
	}
    }
  // Periodic reset
  if ((outtime > lasttime + PERIOD) && !atlist && attacksources)
    {
      memset(attackers, 0, pow(2,24)*8);
      lasttime = outtime;
    }
  char outs[MAXLEN];

  if (isattack)
    sprintf(outs, "%s A\n", recordID);
  else
    sprintf(outs, "%s B\n", recordID);

  return outs;
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
	  atlist = true;
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

  if (atlist)
    loadattackers(atfile);
  
  //Use for pcap
  loadfiles(readfolder.c_str(), process, extension, starttime, endtime);
}
  

