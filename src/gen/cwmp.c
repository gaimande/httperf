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
#include <cwmp.h>

/* Maximum number of sessions that can be defined in the configuration
   file.  */
#define MAX_SESSION_TEMPLATES	1000

#ifndef TRUE
#define TRUE  (1)
#endif
#ifndef FALSE
#define FALSE (0)
#endif

#define CWMP_MAX_CPE_DIGIT_NUMBER       7           /* Maximum milion devices */
#define CWMP_SERIAL_STR                 "%s%0*d"

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

size_t cwmp_sess_private_data_offset;
u_int cwmp_num_sessions_generated;
static int num_sessions_destroyed;
static int num_active_sess;
static Rate_Generator rg_cwmp;

/* This is an array rather than a list because we may want different
   httperf clients to start at different places in the sequence of
   sessions. */
static int num_templates;
static Cwmp_Sess_Private_Data session_templates[MAX_SESSION_TEMPLATES] =
  {
    { 0, }
  };

static void printchar(char **str, int size, int curr_size, int c)
{   
    **str = c;
    if (curr_size < (size - 1))
        ++(*str);
}

static int prints(char **out, int size, int curr_size, const char *string)
{   
    int cnt = 0;
    
    for ( ; *string ; ++string)
    {   
        printchar (out, size, ++curr_size, *string);
        cnt++;
    }
    
    return cnt;
}

int cwmp_snprintf (char *outFile, int size, const char *format, Cwmp_Sess_Private_Data *priv)
{   
    char **out = &outFile;
    char *buf = format;
    int cnt = 0;

    if (NULL == format || NULL == outFile || NULL == priv)
    {
        return -1;
    }
    
    for (; *buf != 0; buf++)
    {   
        if (*buf == '%')
        {   
            buf++;
            if (*buf == '\0')
                break;
            
            if (*buf == '%')
            {   
                printchar (out, size, cnt, *buf);
                cnt++;
            }
            else if (*buf == 's')
            {   
                cnt += prints (out, size, cnt, priv->serial ? priv->serial : "(NULL)");
                continue;
            }
            else if (*buf == 'i')
            {   
                cnt += prints (out, size, cnt, priv->cwmpID ? priv->cwmpID : "(NULL)");
                continue;
            }
        }
        else
        {   
            printchar (out, size, cnt, *buf);
            cnt++;
        }
    }

    if (out) **out = '\0';

    return cnt;
}

static int
cwmp_get_cwmpID (const char *msg, Cwmp_Sess_Private_Data *priv)
{
    const char *cwmp_node = "<cwmp:ID soap-env:mustUnderstand=\"1\">";
    char *ptr_s, *ptr_e;

    /* We just need to get cwmp ID one time */
    if (strncmp (priv->cwmpID, priv->serial, sizeof (priv->serial)))
    {
        return 0;
    }
    
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
cwmp_build_reply_msg (const REQ *template, Cwmp_Sess_Private_Data *priv)
{
    int ret;
    char buf[500000];
    int buf_len = sizeof(buf);

    /* Use a random cwmpID for the first message */
    if (NULL == priv->cwmpID)
    {
        priv->cwmpID = priv->serial;
    }    

    /* Build URI */
    memset (buf, 0x0, buf_len);

    ret = cwmp_snprintf (buf, buf_len, template->uri, priv);
    if (ret >= buf_len)
    {
        fprintf (stderr, "cwmp_snprintf error, output was truncated\n");
        return -1;
    }    

    priv->current_req->uri = strdup (buf);
    priv->current_req->uri_len = strlen (buf);
    
    /* Build content */
    memset (buf, 0x0, buf_len);  
    
    ret = cwmp_snprintf (buf, buf_len, template->contents, priv);
    if (ret >= buf_len)
    {
        fprintf (stderr, "cwmp_snprintf error, output was truncated\n");
        return -1;
    }

    priv->current_req->contents = strdup (buf);
    priv->current_req->contents_len = strlen (buf);
    
    priv->current_req->method = template->method;
    priv->current_req->cpe_action = template->cpe_action;

    return 0;
}


static void
sess_destroyed (Event_Type et, Object *obj, Any_Type regarg, Any_Type callarg)
{
  Cwmp_Sess_Private_Data *priv;
  Sess *sess;

  assert (et == EV_SESS_DESTROYED && object_is_sess (obj));
  sess = (Sess *) obj;  

  priv = CWMP_SESS_PRIVATE_DATA (sess);
  if (priv->timer)
    {
      timer_cancel (priv->timer);
      priv->timer = 0;
    }

  if (priv->serial != NULL)
  {
        free (priv->serial);
        priv->serial = NULL;
  }  

  num_active_sess--;

  if (++priv->current_sess_template >= num_templates)
  {
    priv->current_sess_template = 0;
  }

  if (0 == param.forever &&
      ++num_sessions_destroyed >= param.cwmp.num_sessions)
  {
    core_exit ();
  }
}

static void
sess_failed (Event_Type et, Object *obj, Any_Type regarg, Any_Type callarg)
{
  Cwmp_Sess_Private_Data *priv;
  Sess *sess;

  assert (et == EV_SESS_FAILED && object_is_sess (obj));
  sess = (Sess *) obj;

  priv = CWMP_SESS_PRIVATE_DATA (sess);
  priv->cwmp_result = CWMP_ERR_NO_RESP;
}

static REQ *
cwmp_find_req_template (Cwmp_Sess_Private_Data *priv)
{
    int i, req_idx;
    int num_req_so_far = 0;
    BURST *bptr;
    REQ *rptr;
    Cwmp_Sess_Private_Data *template;

    template = &session_templates[priv->current_sess_template];

    for (bptr = template->current_burst; bptr != NULL; bptr = bptr->next)
    {
        num_req_so_far += bptr->num_reqs;
        rptr = bptr->req_list;
        
        if (priv->num_calls_destroyed >= num_req_so_far)
        {            
            continue;
        }
        
        req_idx = bptr->num_reqs - (num_req_so_far - priv->num_calls_destroyed);

        for (i = 0; i < req_idx; i++)
        {
            rptr = rptr->next;
        }
        break;
    }

    return rptr;
}

static void
issue_calls (Sess *sess, Cwmp_Sess_Private_Data *priv)
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

  req_template = cwmp_find_req_template(priv);

  if (req_template == NULL)
    panic ("%s: internal error, cannot find request template for %s\n",
        prog_name, cwmp_cpe_action_name[priv->current_cpe_action]); 

  cwmp_build_reply_msg (req_template, priv);

  req = priv->current_req;
  
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
  Cwmp_Sess_Private_Data *priv;
  const char *cp;
  struct iovec *line;
  Sess *sess;
  Call *call;
  
  assert (et == EV_CALL_RECV_DATA && object_is_call (obj));
  call = (Call *) obj;
  sess = session_get_sess_from_call (call);
  priv = CWMP_SESS_PRIVATE_DATA (sess);
  
  line = callarg.vp;    
  cp = line->iov_base;

  if (NULL != strstr(cp, "<cwmp:InformResponse>"))
  {
        if (priv->current_cpe_action > CPE_INFORM_DONE)
        {
            priv->num_calls_destroyed = priv->total_num_reqs;
            return;
        }
        
        priv->current_cpe_action = CPE_INFORM_DONE;
  }
  else if (NULL != strstr(cp, "<cwmp:GetParameterNames>"))
  {
        if (priv->current_cpe_action > CPE_REP_ALL_PARAM_NAME)
        {
            priv->num_calls_destroyed = priv->total_num_reqs;
            return;
        }

        priv->current_cpe_action = CPE_REP_ALL_PARAM_NAME;
  }
  else if (NULL != strstr(cp, "<cwmp:GetParameterValues>"))
  {
        priv->current_cpe_action = CPE_REP_ALL_PARAM_VALUE;
  }
  else
  {
        return;
  }

  cwmp_get_cwmpID (cp, priv);
}

static void
call_recv_start (Event_Type et, Object *obj, Any_Type regarg, Any_Type callarg)
{
  Cwmp_Sess_Private_Data *priv;
  Sess *sess;
  Call *call;
  char *buf = NULL;
  u_int status;
  static int success, failed;
  
  assert (et == EV_CALL_RECV_START && object_is_call (obj));
  call = (Call *) obj;
  sess = session_get_sess_from_call (call);
  priv = CWMP_SESS_PRIVATE_DATA (sess);  

  buf = call->conn->line.iov_base;
  
  if (sscanf (buf, "HTTP/%*u.%*u %u ", &status) == 1)
  {
    if ((status / 100) > 3)
    {
        priv->cwmp_result = CWMP_ERR_BAD_REQ;

        /* Close this session */
        priv->num_calls_destroyed = priv->total_num_reqs;
    }
    else if (204 == status) /* No Content */
    {
        if (priv->num_calls_destroyed == (priv->total_num_reqs- 1))
        {
            priv->cwmp_result = CWMP_ERR_NONE;
        }
        else
        {
            priv->cwmp_result = CWMP_ERR_WORKFLOW;
            
            /* Close this session */
            priv->num_calls_destroyed = priv->total_num_reqs;
        }
    }
    else
    {
        priv->cwmp_result = CWMP_ERR_OTHERS;
    }
  }
}

static void
user_think_time_expired (struct Timer *t, Any_Type arg)
{
  Sess *sess = arg.vp;
  Cwmp_Sess_Private_Data *priv;

  assert (object_is_sess (sess));

  priv = CWMP_SESS_PRIVATE_DATA (sess);
  priv->timer = 0;

  issue_calls (sess, priv);
}

/* Create a new session and fill in our private information.  */
static int
sess_create (Any_Type arg)
{ 
  static int first_time, cpe_idx;
  int ret, serial_len;
  Cwmp_Sess_Private_Data *priv, *template;
  Sess *sess;

  if (0 == first_time)
  {
     first_time++;
     sess_time_start = timer_now();
  }

  if (param.max_sess != 0 && num_active_sess >= param.max_sess)
  {
     return 0;
  }

  if (cpe_idx >= param.cwmp.num_sessions)
  {
     if (param.forever)
     {
        cpe_idx = 0;
     }
     else
     {        
        return -1;
     }
  }

  sess = sess_new ();

  num_active_sess++;
  if (++cwmp_num_sessions_generated == param.cwmp.num_sessions)
  {
     sess_time_stop = timer_now();
  }

  priv = CWMP_SESS_PRIVATE_DATA (sess);

  priv->current_sess_template = 0;
  template = &session_templates[priv->current_sess_template];
  
  priv->current_burst = template->current_burst;
  priv->total_num_reqs = template->total_num_reqs;
  priv->num_calls_target = template->current_burst->num_reqs;
  
  priv->current_req = (REQ *) malloc (sizeof(REQ));
  if (NULL == priv->current_req)
  {
     fprintf (stderr, "not enough emeory to allocate\n");
     return -1;
  }
  memset (priv->current_req, 0x0, sizeof(REQ));

  serial_len = strlen(param.cwmp.serial_prefix) + CWMP_MAX_CPE_DIGIT_NUMBER + 1;
  priv->serial = malloc (serial_len);
  if (NULL == priv->serial)
  {
        fprintf (stderr, "Not enough memory.\n");
        return -1;
  }

  ret = snprintf (priv->serial, serial_len, CWMP_SERIAL_STR,
                  param.cwmp.serial_prefix, CWMP_MAX_CPE_DIGIT_NUMBER,
                  ++cpe_idx);
  if (ret >= serial_len)
  {
     fprintf (stderr, "snprintf was truncated.\n");
     return -1;
  }    
  
  if (DBG > 0)
    fprintf (stderr, "Starting session, first burst_len = %d\n",
	     priv->num_calls_target);

  issue_calls (sess, priv);
  return 0;
}

static void
prepare_for_next_burst (Sess *sess, Cwmp_Sess_Private_Data *priv)
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
          priv->current_req = (REQ *) malloc (sizeof(REQ));
          if (NULL == priv->current_req)
          {
             fprintf (stderr, "not enough emeory to allocate\n");
             return -1;
          }
          memset (priv->current_req, 0x0, sizeof(REQ));
          
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
  Cwmp_Sess_Private_Data *priv;
  Sess *sess;
  Call *call;

  assert (et == EV_CALL_DESTROYED && object_is_call (obj));
  call = (Call *) obj;
  sess = session_get_sess_from_call (call);
  priv = CWMP_SESS_PRIVATE_DATA (sess);

  if (sess->failed)
    return;

  ++priv->num_calls_destroyed;

  if (priv->current_req->contents != NULL)
  {
    free (priv->current_req->contents);
    priv->current_req->contents = NULL;
  }
  
  if (priv->current_req->uri != NULL)
  {
    free(priv->current_req->uri);
    priv->current_req->uri = NULL;
  }

  if (priv->current_req != NULL)
  {
    free(priv->current_req);
    priv->current_req = NULL;
  }

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
  Cwmp_Sess_Private_Data *sptr;
  char line[500000];	/* some uri's get pretty long */
  char uri[500000];	/* some uri's get pretty long */
  char method_str[1000];
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

  num_templates = 0;
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
          num_templates++;
	  if (num_templates > MAX_SESSION_TEMPLATES)
	    panic ("%s: too many sessions (%d) specified in %s\n",
		   prog_name, num_templates, param.wsesslog.file); 
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

  cwmp_sess_private_data_offset = object_expand (OBJ_SESS,
					    sizeof (Cwmp_Sess_Private_Data));

  rg_cwmp.rate = &param.rate;
  rg_cwmp.tick = sess_create;
  rg_cwmp.arg.l = 0;

  arg.l = 0;
  event_register_handler (EV_SESS_DESTROYED, sess_destroyed, arg);
  event_register_handler (EV_CALL_DESTROYED, call_destroyed, arg);
  event_register_handler (EV_CALL_RECV_DATA, call_recv_data, arg);
  event_register_handler (EV_CALL_RECV_START, call_recv_start, arg);
  event_register_handler (EV_SESS_FAILED, sess_failed, arg);

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
