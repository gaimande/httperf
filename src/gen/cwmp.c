/*
    httperf -- a tool for measuring web server performance
    Copyright 2000-2007 Hewlett-Packard Company

    This file is part of httperf, a web server performance measurment
    tool.

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.
    
    In addition, as a special exception, the copyright holders give
    permission to link the code of this work with the OpenSSL project's
    "OpenSSL" library (or with modified versions of it that use the same
    license as the "OpenSSL" library), and distribute linked combinations
    including the two.  You must obey the GNU General Public License in
    all respects for all of the code used other than "OpenSSL".  If you
    modify this file, you may extend this exception to your version of the
    file, but you are not obligated to do so.  If you do not wish to do
    so, delete this exception statement from your version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  
    02110-1301, USA
*/

#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <generic_types.h>

#include <object.h>
#include <timer.h>
#include <httperf.h>
#include <conn.h>
#include <call.h>
#include <core.h>
#include <localevent.h>
#include <rate.h>
#include <session.h>

/* Maximum number of sessions that can be defined in the configuration
   file.  */
#define MAX_SESSION_TEMPLATES	1000

#ifndef TRUE
#define TRUE  (1)
#endif
#ifndef FALSE
#define FALSE (0)
#endif

#define SESS_PRIVATE_DATA(c)						\
  ((Sess_Private_Data *) ((char *)(c) + sess_private_data_offset))

#define CWMP_SERIAL_MAX_LEN     32
#define CWMP_SERIAL_STR         "%s%05d"

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

typedef struct Sess_Private_Data Sess_Private_Data;
struct Sess_Private_Data
  {
    u_int num_calls_in_this_burst; /* # of calls created for this burst */
    u_int num_calls_target;	/* total # of calls desired */
    u_int num_calls_destroyed;	/* # of calls destroyed so far */
    struct Timer *timer;		/* timer for session think time */

    int total_num_reqs;		/* total number of requests in this session */

    BURST *current_burst;	/* the current burst we're working on */
    REQ *current_req;		/* the current request we're working on */
    int current_cpe_action;
    char *cwmpID;
    char *serial;
  };

/* Methods allowed for a request: */
enum
  {
    HM_DELETE, HM_GET, HM_HEAD, HM_OPTIONS, HM_POST, HM_PUT, HM_TRACE,
    HM_LEN
  };

static const char *call_method_name[] =
  {
    "DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT", "TRACE"
  };

enum
{
    CPE_INFORM = 0,
    CPE_DONE,
    CPE_REP_ALL_PARAM,
    CPE_REP_ALL_VALUE,
    CPE_MAX
};

static const char *cwmp_cpe_action_name[] =
  {
    "INFORM", "DONE", "REP_ALL_PARAM", "REP_ALL_VALUE"
  };


static size_t sess_private_data_offset;
static int num_sessions_generated;
static int num_sessions_destroyed;
static Rate_Generator rg_cwmp;

/* This is an array rather than a list because we may want different
   httperf clients to start at different places in the sequence of
   sessions. */
static Sess_Private_Data session_templates;

static int
cwmp_get_cwmpID (const char *msg, Sess_Private_Data *priv)
{
    const char *cwmp_node = "<cwmp:ID soap-env:mustUnderstand=\"1\">";
    char *ptr_s, *ptr_e;
    
    if (NULL != (ptr_s = strstr (msg, cwmp_node)))
    {
        ptr_s += strlen(cwmp_node);
        if (NULL != (ptr_e = strstr (ptr_s, "</cwmp:ID>")))
        {
            ptr_e[0] = '\0';
        }
    }
    
    if (NULL == ptr_e)
    {
        return -1;
    }
    
    priv->cwmpID = strdup(ptr_s);
    return 0;
}

static int
cwmp_build_inform_msg (const REQ *template, Sess_Private_Data *priv)
{
    int len = 0;
    int ret = 0;

    len = sizeof(char) * (strlen(template->contents) + 2 * strlen(priv->serial) - 3);    

    if (priv->current_req->contents != NULL)
    {
        free(priv->current_req->contents);
        priv->current_req->contents = NULL;
    }
    
    priv->current_req->contents = calloc(1, len);
    if (NULL == priv->current_req->contents)
    {
        fprintf (stderr, "not enough memory to allocate\n");
        return -1;
    }
    
    ret = snprintf (priv->current_req->contents, len, template->contents, priv->serial, priv->serial);
    
    if (ret >= len)
    {
        fprintf (stderr, "snprintf error\n");
        return -1;
    }

    priv->current_req->contents_len = len;
    priv->current_req->method = template->method;
    priv->current_req->uri = template->uri;
    priv->current_req->uri_len = template->uri_len;
    priv->current_req->cpe_action = template->cpe_action;
    
    return 0;
}

static int
cwmp_build_reply_all_param_name (const REQ *template, Sess_Private_Data *priv)
{
    int len = 0;
    int ret = 0;

    len = sizeof(char) * (strlen(template->contents) + strlen(priv->cwmpID) - 1);

    if (priv->current_req->contents != NULL)
    {
        free(priv->current_req->contents);
        priv->current_req->contents = NULL;
    }
    
    priv->current_req->contents = calloc(1, len);
    if (NULL == priv->current_req->contents)
    {
        fprintf (stderr, "not enough memory to allocate\n");
        return -1;
    }

    ret = snprintf (priv->current_req->contents, len, template->contents, priv->cwmpID);
    if (ret >= len)
    {
        fprintf (stderr, "snprintf error\n");
        return -1;
    }

    priv->current_req->contents_len = len;
    priv->current_req->method = template->method;
    priv->current_req->uri = template->uri;
    priv->current_req->uri_len = template->uri_len;
    priv->current_req->cpe_action = template->cpe_action;
    
    return 0;
}

static int
cwmp_build_reply_all_param_value (const REQ *template, Sess_Private_Data *priv)
{
    int len = 0;
    int ret = 0;

    len = sizeof(char) * (strlen(template->contents) + strlen(priv->cwmpID) + strlen(priv->serial) - 3);

    if (priv->current_req->contents != NULL)
    {
        free(priv->current_req->contents);
        priv->current_req->contents = NULL;
    }
    
    priv->current_req->contents = calloc(1, len);
    if (NULL == priv->current_req->contents)
    {
        fprintf (stderr, "not enough memory to allocate\n");
        return -1;
    }
    
    ret = snprintf (priv->current_req->contents, len, template->contents, priv->cwmpID, priv->serial);
    if (ret >= len)
    {
        fprintf (stderr, "snprintf error\n");
        return -1;
    }

    priv->current_req->contents_len = len;
    priv->current_req->method = template->method;
    priv->current_req->uri = template->uri;
    priv->current_req->uri_len = template->uri_len;
    priv->current_req->cpe_action = template->cpe_action;

    return 0;
}


static void
sess_destroyed (Event_Type et, Object *obj, Any_Type regarg, Any_Type callarg)
{
  Sess_Private_Data *priv;
  Sess *sess;

  assert (et == EV_SESS_DESTROYED && object_is_sess (obj));
  sess = (Sess *) obj;

  priv = SESS_PRIVATE_DATA (sess);
  if (priv->timer)
    {
      timer_cancel (priv->timer);
      priv->timer = 0;
    }

  if (priv->current_req->contents != NULL)
  {
        free (priv->current_req->contents);
        priv->current_req->contents = NULL;
  }

  if (priv->current_req != NULL)
  {
        free (priv->current_req);
        priv->current_req = NULL;
  } 

  if (++num_sessions_destroyed >= param.cwmp.num_sessions)
    core_exit ();
}

REQ *
cwmp_find_req_template (int cpe_action)
{
    int i;
    REQ *req, *req_list_bk;

    req = req_list_bk = session_templates.current_burst->req_list;
    for (i = 0; i < session_templates.current_burst->num_reqs; i++)
    {        
        if (req->cpe_action == cpe_action)
        {
            return req;
        }

        req = req->next;        
    }

    session_templates.current_burst->req_list = req_list_bk;
    return req;
}

static void
issue_calls (Sess *sess, Sess_Private_Data *priv)
{
  int i, retval, n, length;
  const char *method_str;
  Call *call;
  REQ *req, *req_template;
  char *contents;

  /* Mimic browser behavior of fetching html object, then a couple of
     embedded objects: */  
  
  priv->num_calls_in_this_burst++; 

  call = call_new ();
  if (!call)
  {
    sess_failure (sess);
    return;
  }

  req = priv->current_req;

  req_template = cwmp_find_req_template(sess->current_cpe_action);
  if (req_template == NULL)
    panic ("%s: internal error, cannot find request template for %s\n",
        prog_name, cwmp_cpe_action_name[sess->current_cpe_action]);

  /* fill in the new call: */  
  if (CPE_INFORM == sess->current_cpe_action)
  {            
      cwmp_build_inform_msg (req_template, priv);
  }
  else if (CPE_DONE == sess->current_cpe_action)
  {
      if (req->contents != NULL)
      {
          free(req->contents);
          req->contents = NULL;
      }
      
      req->contents_len = 0;
      req->contents = strdup("");
  }
  else if (CPE_REP_ALL_PARAM== sess->current_cpe_action)
  {
      cwmp_build_reply_all_param_name (req_template, priv);
  }
  else if (CPE_REP_ALL_VALUE== sess->current_cpe_action)
  {
      cwmp_build_reply_all_param_value (req_template, priv);
  }
  else
  {
      return;
  }
  
  snprintf (req->extra_hdrs, sizeof(req->extra_hdrs), "Content-length: %d\r\n", req->contents_len);
  req->extra_hdrs_len = strlen (req->extra_hdrs);
  
  method_str = call_method_name[req->method];
  call_set_method (call, method_str, strlen (method_str));
  call_set_uri (call, req->uri, req->uri_len);
  
  /* add "Content-length:" header and contents, if necessary: */
  call_append_request_header (call, req->extra_hdrs,
  			      req->extra_hdrs_len);
  call_set_contents (call, req->contents, req->contents_len);
 
  if (DBG > 0)
  fprintf (stderr, "%s: accessing URI `%s'\n", prog_name, req->uri);
  
  retval = session_issue_call (sess, call);
  
  call_dec_ref (call);
  
  if (retval < 0)
  return;
      
}

static void
call_recv_data (Event_Type et, Object *obj, Any_Type regarg, Any_Type callarg)
{
  Sess_Private_Data *priv;
  const char *cp;
  struct iovec *line;
  Sess *sess;
  Call *call;
  
  assert (et == EV_CALL_RECV_DATA && object_is_call (obj));
  call = (Call *) obj;
  sess = session_get_sess_from_call (call);
  priv = SESS_PRIVATE_DATA (sess);
  
  line = callarg.vp;    
  cp = line->iov_base;
  
  if (NULL != strstr(cp, "InformResponse"))
  {
        sess->current_cpe_action = CPE_DONE;
  }
  else if (NULL != strstr(cp, "</cwmp:GetParameterNames>"))
  {
        cwmp_get_cwmpID (cp, priv);
        sess->current_cpe_action = CPE_REP_ALL_PARAM;
  }
  else if (NULL != strstr(cp, "</cwmp:GetParameterValues>"))
  {
        sess->current_cpe_action = CPE_REP_ALL_VALUE;
  }
  else
  {
        sess->current_cpe_action = CPE_INFORM;
  }
}

static void
user_think_time_expired (struct Timer *t, Any_Type arg)
{
  Sess *sess = arg.vp;
  Sess_Private_Data *priv;

  assert (object_is_sess (sess));

  priv = SESS_PRIVATE_DATA (sess);
  priv->timer = 0;
  issue_calls (sess, priv);
}

/* Create a new session and fill in our private information.  */
static int
sess_create (Any_Type arg)
{
  char serial[CWMP_SERIAL_MAX_LEN] = {0};
  Sess_Private_Data *priv;
  Sess *sess;

  if (num_sessions_generated++ >= param.cwmp.num_sessions)
    return -1;

  sess = sess_new ();

  priv = SESS_PRIVATE_DATA (sess);
  priv->current_burst = session_templates.current_burst;
  priv->total_num_reqs = session_templates.total_num_reqs;
  priv->num_calls_target = session_templates.current_burst->num_reqs;
  
  priv->current_req = (REQ *) malloc (sizeof(REQ));
  if (NULL == priv->current_req)
  {
     fprintf (stderr, "not enough emeory to allocate\n");
     return -1;
  }
  memset (priv->current_req, 0x0, sizeof(REQ));

  snprintf (serial, sizeof(serial), CWMP_SERIAL_STR, "QQQ", num_sessions_generated);

  priv->serial = strdup(serial);
  if (NULL == priv->serial)
  {
        fprintf (stderr, "Not enough memory.\n");
        return -1;
  }
  
  sess->current_cpe_action = CPE_INFORM;
  
  if (DBG > 0)
    fprintf (stderr, "Starting session, first burst_len = %d\n",
	     priv->num_calls_target);

  issue_calls (sess, priv);
  return 0;
}

static void
prepare_for_next_burst (Sess *sess, Sess_Private_Data *priv)
{
  Time think_time;
  Any_Type arg;

  if (priv->current_burst != NULL)
    {
      think_time = priv->current_burst->user_think_time;

      /* advance to next burst: */
      priv->current_burst = priv->current_burst->next;

      if (priv->current_burst != NULL)
	{
	  priv->current_req = priv->current_burst->req_list;
	  priv->num_calls_in_this_burst = 0;
	  priv->num_calls_target += priv->current_burst->num_reqs;

	  assert (!priv->timer);
	  arg.vp = sess;
	  priv->timer = timer_schedule (user_think_time_expired,
					arg, think_time);
	}
    }
}

static void
call_destroyed (Event_Type et, Object *obj, Any_Type regarg, Any_Type callarg)
{
  Sess_Private_Data *priv;
  Sess *sess;
  Call *call;

  assert (et == EV_CALL_DESTROYED && object_is_call (obj));
  call = (Call *) obj;
  sess = session_get_sess_from_call (call);
  priv = SESS_PRIVATE_DATA (sess);

  if (sess->failed)
    return;

  ++priv->num_calls_destroyed;

  if (priv->num_calls_destroyed >= priv->total_num_reqs)
    /* we're done with this session */
    sess_dec_ref (sess);
  else if (priv->num_calls_in_this_burst < priv->current_burst->num_reqs)
    issue_calls (sess, priv);
  else if (priv->num_calls_destroyed >= priv->num_calls_target)
    prepare_for_next_burst (sess, priv);
}

/* Allocates memory for a REQ and assigns values to data members.
   This is used during configuration file parsing only.  */
static REQ*
new_request (char *uristr)
{
  REQ *retptr;

  retptr = (REQ *) malloc (sizeof (*retptr));
  if (retptr == NULL || uristr == NULL)
    panic ("%s: ran out of memory while parsing %s\n",
	   prog_name, param.cwmp.file);  

  memset (retptr, 0, sizeof (*retptr));
  retptr->uri = uristr;
  retptr->uri_len = strlen (uristr);
  retptr->method = HM_GET;
  return retptr;
}

/* Like new_request except this is for burst descriptors.  */
static BURST*
new_burst (REQ *r)
{
  BURST *retptr;
    
  retptr = (BURST *) malloc (sizeof (*retptr));
  if (retptr == NULL)
    panic ("%s: ran out of memory while parsing %s\n",
	   prog_name, param.cwmp.file);  
  memset (retptr, 0, sizeof (*retptr));
  retptr->user_think_time = param.cwmp.think_time;
  retptr->req_list = r;
  return retptr;
}

/* Read in session-defining configuration file and create in-memory
   data structures from which to assign uri_s to calls. */
static void
parse_config (void)
{
  FILE *fp;
  int lineno, i, reqnum;
  Sess_Private_Data *sptr;
  char line[500000];	/* some uri's get pretty long */
  char uri[500000];	/* some uri's get pretty long */
  char method_str[1000];
  char cpe_action_str[1000];
  char this_arg[500000]; 
  char contents[500000];
  double think_time;
  int bytes_read;
  REQ *reqptr;
  BURST *bptr, *current_burst = 0;
  char *from, *to, *parsed_so_far;
  int ch;
  int single_quoted, double_quoted, escaped, done;

 
  fp = fopen (param.cwmp.file, "r");
  if (fp == NULL)
    panic ("%s: can't open %s\n", prog_name, param.cwmp.file);  

  sptr = &session_templates;

  for (lineno = 1; fgets (line, sizeof (line), fp); lineno++)
    {
      if (line[0] == '#')
	continue;		/* skip over comment lines */

      if (sscanf (line,"%s%n", uri, &bytes_read) != 1)
	{
	  /* must be a session-delimiting blank line */
	  if (sptr->current_req != NULL)
	    sptr++;		/* advance to next session */
	  continue;
	}
      /* looks like a request-specifying line */
      reqptr = new_request (strdup (uri));

      if (sptr->current_req == NULL)
	{
	  current_burst = sptr->current_burst = new_burst (reqptr);
	}
      else
	{
	  if (!isspace (line[0]))
	    /* this uri starts a new burst */
	    current_burst = (current_burst->next = new_burst (reqptr));
	  else
	    sptr->current_req->next = reqptr;
	}
      /* do some common steps for all new requests */
      current_burst->num_reqs++;
      sptr->total_num_reqs++;
      sptr->current_req = reqptr;

      /* parse rest of line to specify additional parameters of this
	 request and burst */
      parsed_so_far = line + bytes_read;
      while (sscanf (parsed_so_far, " %s%n", this_arg, &bytes_read) == 1)
	{
	  if (sscanf (this_arg, "method=%s", method_str) == 1)
	    {
	      for (i = 0; i < HM_LEN; i++)
		{
		  if (!strncmp (method_str,call_method_name[i],
				strlen (call_method_name[i])))
		    {
		      sptr->current_req->method = i;
		      break;
		    }
		}
	      if (i == HM_LEN)
		panic ("%s: did not recognize method '%s' in %s\n",
		       prog_name, method_str, param.cwmp.file);  
	    }
          else if (sscanf (this_arg, "cwmp=%s", cpe_action_str) == 1)
	    {
	      for (i = 0; i < CPE_MAX; i++)
		{
		  if (!strncmp (cpe_action_str,cwmp_cpe_action_name[i],
				strlen (cwmp_cpe_action_name[i])))
		    {
		      sptr->current_req->cpe_action = i;
		      break;
		    }
		}
	      if (i == CPE_MAX)
		panic ("%s: did not recognize cpe action '%s' in %s\n",
		       prog_name, cpe_action_str, param.cwmp.file);  
	    }
	  else if (sscanf (this_arg, "think=%lf", &think_time) == 1)
	    current_burst->user_think_time = think_time;
	  else if (sscanf (this_arg, "contents=%s", contents) == 1)
	    {
	      /* this is tricky since contents might be a quoted
		 string with embedded spaces or escaped quotes.  We
		 should parse this carefully from parsed_so_far */
	      from = strchr (parsed_so_far, '=') + 1;
	      to = contents;
	      single_quoted = FALSE;
	      double_quoted = FALSE;
	      escaped = FALSE;
	      done = FALSE;
	      while ((ch = *from++) != '\0' && !done)
		{
		  if (escaped == TRUE)
		    {
		      switch (ch)
			{
			case 'n':
			  *to++ = '\n';
			  break;
			case 'r':
			  *to++ = '\r';
			  break;
			case 't':
			  *to++ = '\t';
			  break;
			case '\n':
			  *to++ = '\n';
			  /* this allows an escaped newline to
			     continue the parsing to the next line. */
			  if (fgets(line,sizeof(line),fp) == NULL)
			    {
			      lineno++;
			      panic ("%s: premature EOF seen in '%s'\n",
				     prog_name, param.cwmp.file);  
			    }
			  parsed_so_far = from = line;
			  break;
			default:
			  *to++ = ch;
			  break;
			}
		      escaped = FALSE;
		    }
		  else if (ch == '"' && double_quoted)
		    {
		      double_quoted = FALSE;
		    }
		  else if (ch == '\'' && single_quoted)
		    {
		      single_quoted = FALSE;
		    }
		  else
		    {
		      switch (ch)
			{
			case '\t':
			case '\n':
			case ' ':
			  if (single_quoted == FALSE &&
			      double_quoted == FALSE)
			    done = TRUE;	/* we are done */
			  else
			    *to++ = ch;
			  break;
			case '\\':		/* backslash */
			  escaped = TRUE;
			  break;
			case '"':		/* double quote */
			  if (single_quoted)
			    *to++ = ch;
			  else
			    double_quoted = TRUE;
			  break;
			case '\'':		/* single quote */
			  if (double_quoted)
			    *to++ = ch;
			  else
			    single_quoted = TRUE;
			  break;
			default:
			  *to++ = ch;
			  break;
			}
		    }
		}
	      *to = '\0';
	      from--;		/* back up 'from' to '\0' or white-space */
	      bytes_read = from - parsed_so_far;	      
              sptr->current_req->contents_len = strlen (contents);
              sptr->current_req->contents = strdup (contents);
	    }
	  else
	    {
	      /* do not recognize this arg */
	      panic ("%s: did not recognize arg '%s' in %s\n",
		     prog_name, this_arg, param.cwmp.file);  
	    }
	  parsed_so_far += bytes_read;
	}
    }
  fclose (fp);
}

static void
init (void)
{
  Any_Type arg;

  parse_config ();

  sess_private_data_offset = object_expand (OBJ_SESS,
					    sizeof (Sess_Private_Data));
  rg_cwmp.rate = &param.rate;
  rg_cwmp.tick = sess_create;
  rg_cwmp.arg.l = 0;

  arg.l = 0;
  event_register_handler (EV_SESS_DESTROYED, sess_destroyed, arg);
  event_register_handler (EV_CALL_DESTROYED, call_destroyed, arg);
  event_register_handler (EV_CALL_RECV_DATA, call_recv_data, arg);

  /* This must come last so the session event handlers are executed
     before this module's handlers.  */
  session_init ();
}

static void
start (void)
{
  rate_generator_start (&rg_cwmp, EV_SESS_DESTROYED);
}

Load_Generator cwmp =
  {
    "creates TR069 session workload",
    init,
    start,
    no_op
  };
