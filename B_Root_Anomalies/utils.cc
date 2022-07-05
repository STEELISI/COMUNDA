#include "utils.h"

// Convert string to address                                                                                                                                                            
unsigned int todec(string ip)
{
  int res = 0;
  int dec = 0;
  for (int i=0; i<strlen(ip.c_str()); i++)
    if (isdigit(ip[i]))
      dec = dec*10+(ip[i]-'0');
    else
      {
        res = res*256+dec;
        dec = 0;
      }
  res = res*256+dec;
  return (unsigned int) res;
}

// Trim whitespaces from a string
string trim(string s)
{
  int i = 0;
  while(i < s.length() && s[i] == ' ')
    i++;
  int j = s.length() - 1;
  while(j > 0 && (s[j] == ' ' || s[j] == '\n'))
    j--;
  string ns = "";
  if (j < 0 || j <= i)
    return ns;
  if (s[j] == '.')
    j--;
  ns = s.substr(i, j-i+1);
  return ns;
}

// Check if all chars are digits                                                        
bool checkdigits(const char* str)
{
  for (int i=0; i<strlen(str); i++)
    {
      if (!isdigit(str[i]))
        return false;
    }
  return true;
}

// Convert IPv4 or IPv6 address into an index
// up to 2^16 so we can speed up hashing
int gettwo(char* src)
{
  int res = 0;
  int mult = 256;
  int cur = 0;
  int j = 0;
  for (int i = 0; i < strlen(src); i++)
    {
      if (src[i] == '.' || src[i] == ':')
	{
          if (src[i] == ':')
            {
              mult = 65536;
              break;
            }
          else
            {
              mult = 256;
              break;
            }
        }
    }
  for (int i = 0; i < strlen(src); i++)
    {
      if (src[i] == '.' || src[i] == ':')
        {
          if (src[i] == ':')
            {
              mult = 65536;
            }
          res = res*mult+cur;
          j++;
          if (mult == 65536 || j == 2)
            return res;
          cur = 0;
     }
      else
        {
          if (mult == 256)
            {
              cur = cur*10 + src[i] - '0';
            }
          else
            {
              if (src[i] >= 'a' && src[i] <= 'f')
                cur = cur*16 + src[i] - 'a';
              else if (src[i] >= 'A' && src[i] <= 'F')
                cur = cur*16 + src[i] - 'A';
              else
                cur = cur*16 + src[i] - '0';
            }
        }
    }
  return res;
}


// Something like strtok but it doesn't create new
// strings. Instead it replaces delimiters with 0
// in the original string                                                               
int parse(char* input, char delimiter, int** array)
{
  int pos = 0;
  memset(*array, 255, AR_LEN);
  int len = strlen(input);
  int found = 0;
  for(int i = 0; i<len; i++)
    {
      if (input[i] == delimiter)
        {
          (*array)[pos] = i+1;
          input[i] = 0;
          pos++;
          found++;
        }
    }
  return found;
}

// Load a file using pcap functionalities
void loadfile2(char* fname, string (*process)(char*, double&, int&, int&, ofstream&), char* oname)
{
  cout<<"Reading "<<fname<<endl;
  long int curtime = 0;
  int stats = 0;

  FILE *infile = fopen(fname, "r");


  char buffer[MAXLEN];
  bool done = false;
  
  string cmd = "unxz -c " + (string)fname + " | ./stats - ";

  char ofname[MAXLEN];
  sprintf(ofname, "%s.tag", oname);
  std::ofstream output(ofname, std::ofstream::out);
  
  FILE* pipe = popen(cmd.c_str(), "r");
  int pkts = 0;
  int i = 0;
  const int MAX = 100000;
  string line[MAX];
	
  if (!pipe) throw std::runtime_error("popen() failed!");
    try {
      double oldtime = 0;
      int oldlen = 0;
      int oldttl = 0;
      while (fgets(buffer, sizeof buffer, pipe) != NULL) {
	if (!done)
	  {
	    double time = oldtime;
	    int len = oldlen;
	    int ttl = oldttl;
	    // We still read from pipe even after we are done
	    // because otherwise tcpdump pipe throws segfault
	    line[i++] = process(buffer, time, len, ttl, output);
	    if (i == MAX)
	      {
		for (int j=0; j<i; j++)
		  {
		    output << line[j];
		  }
		i = 0;
	      }
	    if (time > oldtime)
	      oldtime = time;
	    if (len > 0)
	      oldlen = len;
	    if (ttl > 0)
	      oldttl = ttl;
	  }
      }
    } catch (...) {
      pclose(pipe);
      throw;
    }
    pclose(pipe);
    for (int j=0; j<i; j++)
      {
	output << line[j];
      }
    output.close();
    return;  
}

// Load files from dir
void loadfiles(const char* file, string (*process)(char*, double&, int&, int&, ofstream& ), string extension, long int starttime, long int endtime)
{
  bool done = false;
  int nd = 0;
  int nfiles = 0;
  struct dirrecord dirs[100];
  strcpy(dirs[nd].dir,file);
  unsigned char isFile =0x8;
  dirs[nd].n = scandir(dirs[nd].dir, &(dirs[nd].namelist), filter, alphasort);
  if (dirs[nd].n > 0)
    nfiles += dirs[nd].n;
  nd++;
  for (int i = 0; i<nfiles; i++)
    {
      int total = 0;
      int d = 0;
      for (; d < nd; d++)
        {
          if (total + dirs[d].n > i)
            break;
          total += dirs[d].n;
        }
      int nf = i - total;
      char filename[200];
      long now = time(0);
      sprintf(filename, "%s/%s", dirs[d].dir, dirs[d].namelist[nf]->d_name);
      // Assumed file name structure is 20170221-033949-00603104.lax.pcap.xz            
      // Check if the file ends in xz, if not drop it                                   
      if(((string)filename).substr(((string)filename).find_last_of(".") + 1) != "xz")
        {
          continue;
        }
      // We assume that all xz files in a directory should be processed. If extension is specified
      // we will drop files that don't have a given location extension, e.g., lax       
      if (extension != "" && ((string)filename).find(extension) == string::npos)
        {
          continue;
        }
      long myepoch = getepoch(dirs[d].namelist[nf]->d_name);
      if (myepoch < starttime - 30)
        {
          continue;
        }
      if (myepoch >=  endtime + 300)
        {
          done = true;
        }
      if (done)
        break;
      loadfile2(filename, process, dirs[d].namelist[nf]->d_name);
      long diff = time(0) - now;
    }
}


const int NQ=10;
char* querytypes[NQ]= {"A?", "AAAA?", "CNAME?", "PTR?", "NS?", "SOA?", "MX?", "DS?", "SRV?", "TXT?"};

// Is given string epoch time
bool nottime(char* buffer)
{
  if (strlen(buffer) < 17)
    return true;
  for(int i=0; i<17; i++)
    {
      if ((i <= 9 || i > 10) && !isdigit(buffer[i]))
	return true;
      if (i == 10 && buffer[i] != '.')
	return true;
    }
  return false;
}

// More elegant way to process with libpcap
bool shouldprocess2(char* buffer, double& outtime, int& outlen, int*& delimiters, string& ip,
		    double starttime, double endtime, int& isquery, char* queryname, int& outttl)
{
  //std::cout<<"Got buffer "<<buffer<<std::endl;
  int n = parse(buffer,' ', &delimiters);

  //sprintf(retval, "%s %lf %d %s %d %d %s", recordID, ts, size_payload, sourceIP, ttl, isquery, query.c_str());
  //Not enough fields
  
  if (n < 6)
    return false;
  
  outtime = atof(buffer+delimiters[0]);
  outlen = atoi(buffer+delimiters[1]);
  ip = buffer+delimiters[2];
  outttl = atoi(buffer+delimiters[3]);
  isquery = atoi(buffer+delimiters[4]);
  //std::cout<<"Delimiters "<<n<<endl;
  if (n >= 6)
    {
      strcpy(queryname, buffer+delimiters[5]);
      //std::cout<<"queryname "<<queryname<<std::endl;
    }   
  if (outtime > 0 && outtime < starttime)
    {
      //cout<<"time too early "<<std::fixed<<time<<" starttime "<<starttime<<"\n";
      return false;
    }
  
  if (outtime >= endtime)
    {
      return false;
    }
  
  // Do a format check, is the first item epoch time
  if (nottime(buffer))
    {
      return false;
    }
  return true;
}



// Filter files with a given name
int filter(const struct dirent *dir)
{
  const char *s = dir->d_name;
  if (strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
    return 1;
  else
    return 0;
}

// Get epoch from filename
unsigned long getepoch(string filename)
{
  int pos1 = filename.find("-");
  int pos2 = filename.find("-", pos1+1);
  //20170221-033949-00603104.lax.pcap.xz
  string date = filename.substr(0, pos1);
  string clock = filename.substr(pos1+1, pos2-pos1-1);
  struct tm t;
  time_t epoch;
  t.tm_year = (atoi(date.c_str()) / 10000) - 1900;
  t.tm_mon = ((atoi(date.c_str()) % 10000)/100) - 1;
  t.tm_mday = atoi(date.c_str()) % 100;
  t.tm_hour = (atoi(clock.c_str()) / 10000);
  t.tm_min = ((atoi(clock.c_str()) % 10000)/100);
  t.tm_sec = atoi(clock.c_str()) % 100;
  t.tm_isdst = 0;
  epoch = mktime(&t) - timezone;
  return epoch;
}

