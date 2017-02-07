#ifndef cwmp_h
#define cwmp_h

//extern size_t sess_private_data_offset;

#define CWMP_SESS_PRIVATE_DATA(c)					\
  ((Cwmp_Sess_Private_Data *) ((char *)(c) + cwmp_sess_private_data_offset))

typedef struct req REQ;
struct req
  {
    REQ *next;
    int method;
    char *uri;
    int uri_len;
    char *contents;
    int contents_len;
    char extra_hdrs[50];	/* plenty for "Content-length: 1234567890" */
    int extra_hdrs_len;
    int cpe_action;
  };

typedef struct burst BURST;
struct burst
  {
    BURST *next;
    int num_reqs;
    Time user_think_time;
    REQ *req_list;
  };

typedef struct Cwmp_Sess_Private_Data
  {
    u_int num_calls_in_this_burst; /* # of calls created for this burst */
    u_int num_calls_target;	/* total # of calls desired */
    u_int num_calls_destroyed;	/* # of calls destroyed so far */
    struct Timer *timer;		/* timer for session think time */

    u_int cwmp_failed : 1;      /* did session fail? */

    int total_num_reqs;		/* total number of requests in this session */

    BURST *current_burst;	/* the current burst we're working on */
    REQ *current_req;		/* the current request we're working on */
    int trans_seq;
    int current_cpe_action;    
    char *cwmpID;
    char *serial;
  } Cwmp_Sess_Private_Data;

enum
{
    CPE_INFORM_START = 0,
    CPE_INFORM_DONE,
    CPE_REP_ALL_PARAM_NAME,
    CPE_REP_ALL_PARAM_VALUE,
    CPE_MAX
};

static const char *cwmp_cpe_action_name[] =
  {
    "INFORM_START", "INFORM_DONE", "REP_ALL_PARAM_NAME", "REP_ALL_PARAM_VALUE"
  };

#endif /* cwmp_h */
