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

/* Cwmp statistics collector.  */

#include "config.h"

#include <assert.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <generic_types.h>

#include <object.h>
#include <timer.h>
#include <httperf.h>
#include <call.h>
#include <conn.h>
#include <localevent.h>
#include <session.h>
#include <stats.h>
#include <cwmp.h>

static struct
  {
    u_int num_succeeded;
    Time lifetime_sum;

    u_int num_failed;

    u_int num_inform_completed;
    size_t req_bytes_sent;
  }
st;

#define CWMP_STAT_SESS_PRIVATE_DATA(c)						\
  ((Cwmp_Stat_Sess_Private_Data *) ((char *)(c) + cwmp_stat_sess_private_data_offset))

#define DEFAULT_SCREEN_WIDTH     80 /* How wide we assume the screen is if termcap fails. */
#define PERCENT_FORMAT_LENGTH    4  /* The maximum number of percent value format can ever yield */
#define WHITESPACE_LENGTH        3  /* Amount of screen width taken up by whitespace for each bar */
#define BAR_BORDER_WIDTH         2  /* The amount of width taken up by the border of the bar component */

typedef struct Cwmp_Stat_Sess_Private_Data
  {
    u_int num_cwmp_completed;	/* how many calls completed? */
    u_int num_cwmp_failed;	/* how many calls failed? */
    Time birth_time;		/* when this session got created */
  }
Cwmp_Stat_Sess_Private_Data;

static size_t cwmp_stat_sess_private_data_offset = -1;
extern size_t cwmp_sess_private_data_offset;

static unsigned int 
get_screen_width (void)
{
  struct winsize w;
  
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) < 0)
  {
    return DEFAULT_SCREEN_WIDTH;
  }
  
  return w.ws_col;
}

static void
increase_bar (int value, int max, int bar_width)
{
  int i;
  int cur_width = value * bar_width / max;
        
  if (value > max)
  {
     return;
  }

  putchar ('[');

  for (i = 0; i < cur_width; i ++)
  {
    putchar ('|');
  }
  
  for (i = cur_width; i < bar_width; i ++)
  {
    putchar (' ');
  }

  printf ("] %3d%%  ", value * 100 / max);
}

static void
process_bar_print (void)
{
  static int first_time = 0;
  int screen_width = get_screen_width();
  int colum_width = screen_width / 2;
  int bar_width = colum_width  - BAR_BORDER_WIDTH - PERCENT_FORMAT_LENGTH - WHITESPACE_LENGTH;  
  int num_completed = st.num_succeeded + st.num_failed;

  if (0 == first_time)
  {
    first_time = 1;
    printf ("\n%-*s%-*s\n", colum_width, "Inform completed", colum_width, "Session completed");
  }
  
  putchar ('\r');
  increase_bar (st.num_inform_completed, param.cwmp.num_sessions, bar_width);
  increase_bar (num_completed, param.cwmp.num_sessions, bar_width);
  fflush (stdout);

  if (param.cwmp.num_sessions == num_completed)
  {
     printf ("\n\n");
  }
}

static void
sess_created (Event_Type et, Object *obj, Any_Type regarg, Any_Type callarg)
{
  Cwmp_Stat_Sess_Private_Data *stat_priv;
  Sess *sess;

  assert (et == EV_SESS_NEW && object_is_sess (obj));
  sess = (Sess *) obj;
  stat_priv = CWMP_STAT_SESS_PRIVATE_DATA (sess);
  stat_priv->birth_time = timer_now ();
}

static void
sess_destroyed (Event_Type et, Object *obj, Any_Type regarg, Any_Type callarg)
{
  size_t old_size, new_size;
  Cwmp_Stat_Sess_Private_Data *stat_priv;
  Cwmp_Sess_Private_Data *cwmp_priv;
  Sess *sess;
  Time delta, now = timer_now ();

  assert (et == EV_SESS_DESTROYED && object_is_sess (obj));
  sess = (Sess *) obj;
  stat_priv = CWMP_STAT_SESS_PRIVATE_DATA (sess);  
  cwmp_priv = CWMP_SESS_PRIVATE_DATA (sess);

  delta = (now - stat_priv->birth_time);
  
  if (sess->failed || cwmp_priv->cwmp_failed)
  {
    ++st.num_failed;
  }
  else
  {
    ++st.num_succeeded;
    st.lifetime_sum += delta;

    char str[1024] = {0};
    sprintf (str, "echo %s >> abc", cwmp_priv->serial);
    system (str);
  }
  
  process_bar_print();
}

static void
call_destroyed (Event_Type et, Object *obj, Any_Type regarg, Any_Type callarg)
{
  Cwmp_Stat_Sess_Private_Data *stat_priv;
  Cwmp_Sess_Private_Data *cwmp_priv;
  Sess *sess;
  Call *call;  

  assert (et == EV_CALL_DESTROYED && object_is_sess (obj));
  call = (Call *) obj;
  sess = session_get_sess_from_call (call);
  stat_priv = CWMP_STAT_SESS_PRIVATE_DATA (sess);
  cwmp_priv = CWMP_SESS_PRIVATE_DATA (sess);

  if (CPE_INFORM_DONE == cwmp_priv->current_cpe_action)
  {
    st.num_inform_completed++;
  }
  
  process_bar_print();
}

static void
send_stop(Event_Type et, Object * obj, Any_Type reg_arg, Any_Type call_arg)
{
  Call *c = (Call *) obj;

  assert(et == EV_CALL_SEND_STOP && object_is_call(c));

  st.req_bytes_sent += c->req.size;
}

static void
init (void)
{
  Any_Type arg;
  size_t size;

  cwmp_stat_sess_private_data_offset = object_expand (OBJ_SESS,
					    sizeof (Cwmp_Stat_Sess_Private_Data));
  
  arg.l = 0;
  event_register_handler (EV_SESS_NEW, sess_created, arg);
  event_register_handler (EV_SESS_DESTROYED, sess_destroyed, arg);
  event_register_handler (EV_CALL_DESTROYED, call_destroyed, arg);
  event_register_handler (EV_CALL_SEND_STOP, send_stop, arg);
}

static void
dump (void)
{
  double min, avg, stddev, delta, rate_succeeded;
  int i;
  time_t start_t = (time_t)test_time_start;
  time_t stop_t = (time_t)test_time_stop;
  char start_s[20], stop_s[20];

  delta = test_time_stop - test_time_start;

  putchar ('\n');

  strftime(start_s, sizeof(start_s), "%Y-%m-%d %H:%M:%S", localtime(&start_t));
  strftime(stop_s, sizeof(stop_s), "%Y-%m-%d %H:%M:%S", localtime(&stop_t));
  printf ("Cwmp testing plan: begin %s end %s\n", start_s, stop_s);

  avg = 0.0;
  if (st.num_succeeded > 0)
    avg = st.lifetime_sum/st.num_succeeded;
  printf ("Cwmp session lifetime [s]: %.1f\n", avg);

  rate_succeeded = st.num_succeeded * 100 / param.cwmp.num_sessions;
  printf ("Cwmp session succeeded [sess]: total %d (%.1f%)\n",
          st.num_succeeded, rate_succeeded);
  printf ("Cwmp session failed [sess]: total %d (%.1f%)\n",
          st.num_failed, 100 - rate_succeeded);
  printf ("Cwmp size sent rate [B/sess]: %d (total %d)\n",
          st.req_bytes_sent / param.cwmp.num_sessions, st.req_bytes_sent);
}

Stat_Collector cwmp_stat =
{
    "collects cwmp-related statistics",
    init,
    no_op,
    no_op,
    dump
};

