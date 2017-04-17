#ifndef cwmp_h
#define cwmp_h

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
    char *status;
    int status_len;
    char *add_hdrs;
    int add_hdrs_len;
    int noreply;
  };

typedef struct burst BURST;
struct burst
  {
    BURST *next;
    int num_reqs;
    Time user_think_time;
    REQ *req_list;
  };

typedef enum cwmp_ret_e
{
    CWMP_ERR_NONE = 0,          /* No error */
    CWMP_ERR_WORKFLOW,          /* Cwmp session workflow is abnormal */
    CWMP_ERR_BAD_REQ,           /* ACS consider CPE's request is bad */
    CWMP_ERR_NO_RESP,           /* ACS does not respond */
    CWMP_ERR_OTHERS             /* Unknown error */
} cwmp_ret_t;

typedef struct Cwmp_Sess_Private_Data
  {
    u_int num_calls_in_this_burst; /* # of calls created for this burst */
    u_int num_calls_target;	/* total # of calls desired */
    u_int num_calls_destroyed;	/* # of calls destroyed so far */
    struct Timer *timer;		/* timer for session think time */

    cwmp_ret_t cwmp_result;     /* did session fail? */

    int total_num_reqs;		/* total number of requests in this session */

    BURST *current_burst;	/* the current burst we're working on */
    REQ *current_req;		/* the current request we're working on */
    int current_cpe_action;    
    char *cwmpID;
    char *serial;
    int cpe_port;
    int current_sess_template;
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
