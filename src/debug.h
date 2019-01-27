#include <stdio.h>
#pragma once

enum verboselevel {
  lvlNONE,
  lvlERROR,
  lvlINFO,
  lvlDEBUG,
};

extern int loglevel;
#define RAWLOG(fmt, args...)\
  fprintf(stderr, fmt, ##args);

#define INFOLOG(fmt, args...)\
  if (loglevel >= lvlINFO) { \
    RAWLOG("[INF] " fmt "\n", ##args);\
  }

#define DEBUGLOG(fmt, args...)\
  if (loglevel >= lvlDEBUG) { \
    RAWLOG("[DBG] " fmt "\n", ##args);\
  }

#define ERRORLOG(fmt, args...)\
  if (loglevel >= lvlERROR) { \
    RAWLOG("[ERR] " fmt "\n", ##args);\
  }

