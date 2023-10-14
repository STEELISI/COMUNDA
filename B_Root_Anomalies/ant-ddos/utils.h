#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <cmath>
#include <ctype.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define AR_LEN 300 // highest number of delimiters in a string parsed with parse function
#define MAXLEN 20000

#define CUSUMTHRESH 5
#define MINSAMPLES 5
#define ATTHRESH 5
#define N 10
#define ASAMPLES 10
#define NL 9
#define NR 65536
#define NUMSTD 5

using namespace std;

struct item
{
  double avg[NL];
  double ss[NL];
  int samples[NL];
};


struct record
{
  // Every so often remember what you know
  // and start again
  // Historical values keep the highest
  // measure we have
  double avg[NL];
  double ss[NL];
  int samples[NL];
  int r[NL];
  long int time[NL];
  int start;
  int lasttime;
  int at;
  double xcd;
  bool blocked;
};

// Directory entry
struct dirrecord
{
  char dir[200];
  struct dirent** namelist;
  int n;
};

// Utility functions
bool nottime(char* buffer);
unsigned int todec(string ip);
bool checkdigits(const char* str);
int gettwo(char* src);
int parse(char* input, char delimiter, int** array);
void loadfile2(char* fname, string (*process)(char*, double&, int&, int&, ofstream&));
void loadfiles(const char* file, string (*process)(char*, double&, int&, int&, ofstream&),
	       string, long int, long int);
unsigned long getepoch(string filename);
int filter(const struct dirent *dir);
bool shouldprocess2(char* buffer, double& outtime, int& outlen, int*& delimiters, string& ip,
		    double starttime, double endtime, int& isquery, char* queryname, int& outttl);

string trim(string s);

#endif
