#!/usr/bin/python3
import requests
import logging
import http.client
import os
import sys
import datetime
import hashlib
import json
import argparse
#from wsgiref import simple_server, util

class Bearer(requests.auth.AuthBase):
  def __init__(self, access_token):
    self.access_token = access_token
  def __call__(self, r):
    if isinstance(self.access_token, str):
      r.headers['Authorization'] = b'Bearer ' + self.access_token.encode('utf-8')
    else: # assume bytes/bytearray
      r.headers['Authorization'] = b'Bearer ' + self.access_token
    return r

def read_config(filename):
  rv = dict()
  try:
    with open(filename, 'r') as cfg:
      for line in cfg:
        if line.strip()[0] != "#":
          dt = line.split('=', 1)
          val = dt[1].strip()
          rv[dt[0].strip()] = val if len(val) > 0 else None
  except:
    print("Could not read {}".format(filename))
  return rv

def write_config(filename, vals):
  with open(filename, 'w') as cfg:
    for k, v in vals.items():
      print("{}={}".format(k, v if v != None else ""), file = cfg)

def hash_file(filename):
  with open(filename, 'rb') as f:
    return hashlib.sha1(f.read()).hexdigest()

def hash_str(t):
  return hashlib.sha1(t).hexdigest()

class Spotify(object):
  def __init__(self, basedir, debug = False):
    self.basedir = basedir
    if debug:
      http.client.HTTPConnection.debuglevel = 1
      logging.basicConfig()
      logging.getLogger().setLevel(logging.DEBUG)
      requests_log = logging.getLogger("requests.packages.urllib3")
      requests_log.setLevel(logging.DEBUG)
      requests_log.propagate = True
    self.keys = read_config(os.path.join(basedir, "keys"))
    self.load_tokens()
  def save_tokens(self):
    write_config(os.path.join(self.basedir, "session"), self.session)
  def load_tokens(self):
    self.session = read_config(os.path.join(self.basedir, "session"))
  def perform_token_refresh(self):
    r = requests.post('https://accounts.spotify.com/api/token',
                      auth = (self.keys['client_id'], self.keys['client_secret']),
                      data = {'grant_type': 'refresh_token',
                              'refresh_token': self.session['refresh_token']})
    jsb = r.json()
    if r.status_code != 200:
      return False
    self.session['access_token'] = jsb['access_token']
    if 'refresh_token' in jsb:
      self.session['refresh_token'] = jsb['refresh_token']
    self.save_tokens()
    return True
  def _make_request(self, getr):
    trying = 2
    while trying > 0:
      r = requests.get(getr, auth = Bearer(self.session['access_token']))
      if r.status_code == 401 or r.status_code == 400:
        if self.perform_token_refresh():
          trying -= 1
        else:
          trying = 0
      else:
        trying = 0
    rv = r.text
    return rv
  def _find_list_in_json(self, jd, name):
    for pl in jd['items']:
      if pl['name'] == name:
        return pl['id']
    return None
  def find_playlist(self, name):
    req = "https://api.spotify.com/v1/me/playlists"
    while req != None:
      tmp = self._make_request(req)
      jd = json.loads(tmp)
      id = self._find_list_in_json(jd, name)
      if id != None:
        return id
      req = jd['next']
    return None
  def get_playlist(self, playlist):
    return self._make_request("https://api.spotify.com/v1/playlists/{}/tracks".format(playlist))

def get_playlist_filename_from_week_year(week, year = None):
  return "DW-{}_W{}.pl".format(year if year != None else datetime.datetime.now().year, week)

def get_playlist_filename_from_date(dt, is_early = True, extra = None):
  week_date = dt + datetime.timedelta(days = 1) if is_early and dt.weekday() == 6 else dt
  return "{}{}.pl".format(week_date.strftime("DW-%Y_W%W"), "" if extra == None else "-{}".format(extra))

def get_playlist_filename_from_date_str(dt, is_early = True, extra = None):
  added = datetime.datetime.strptime(dt[0:19], '%Y-%m-%dT%H:%M:%S')
  return get_playlist_filename_from_date(added, is_early, extra)

def get_playlist_filename_from_json(plj, is_early = True, extra = None):
  return get_playlist_filename_from_date_str(plj['items'][0]['added_at'][0:19], is_early, extra)

def get_this_week():
  return datetime.datetime.now().strftime("%W")

def get_config_or_default(cfg, name, default = None):
  try:
    v = cfg[name]
    return v if v != None else default
  except:
    return default

class WeeklySaver(object):
  def __init__(self, basedir):
    self.basedir = basedir
    self.cfg = read_config(os.path.join(basedir, "config"))
    self.playlist_dir = get_config_or_default(self.cfg, 'savedir', os.path.join(basedir, "playlists"))
    os.makedirs(self.playlist_dir, exist_ok = True)
    self.sptfy = Spotify(basedir = basedir)
  def get_weekly_id(self):
    self.cfg['playlist'] = self.sptfy.find_playlist("Discover Weekly")
    write_config(os.path.join(self.basedir, "config"), self.cfg)
    return self.cfg['playlist']
  def retrieve_weekly(self):
    if not 'playlist' in self.cfg or self.cfg['playlist'] == None:
      self.get_weekly_id()
    expected_filename = get_playlist_filename_from_date(datetime.datetime.now(), is_early = False)
    print("We would expect to get {}".format(expected_filename))
    if not os.path.exists(os.path.join(self.playlist_dir, expected_filename)):
      print("It seems like we don't have it, ask Spotify for it...")
      pl = self.sptfy.get_playlist(self.cfg['playlist'])
      new_hash = hash_str(pl.encode('utf-8'))
      new_name = get_playlist_filename_from_json(json.loads(pl))
      pl_filename = os.path.join(self.playlist_dir, new_name)
      if new_name != expected_filename:
        print("Hmm, seems like Spotify doesn't have it either...")
      print("Let's see if we already have what Spotify gave us...")
      count = 1
      while os.path.exists(pl_filename):
        old_hash = hash_file(pl_filename)
        if old_hash == new_hash:
          print("Same list different name!")
          return False
        # so, same name but different contents, we need a new name
        pl_filename = os.path.join(self.playlist_dir, get_playlist_filename_from_json(json.loads(pl), extra = count))
        count += 1
      with open(pl_filename, 'wb') as plf:
        plf.write(pl.encode('utf-8'))
      print("Great! We have a new one!")
      return True
    print("But we already have it, so let's not bother Spotify about it")
    return False
  def list_songs_for_week(self, weekno, year = None):
    pl_filename = get_playlist_filename_from_week_year(weekno, year)
    with open(os.path.join(self.playlist_dir, pl_filename), 'r') as plfile:
      pjl = json.load(plfile)
    for it in pjl['items']:
      track = it['track']
      print("{}/{}/{}".format(track['name'], ','.join([tn['name'] for tn in track['artists']]), track['album']['name']))

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description = 'WeeklySaver - saves your Spotify Discover Weekly')
  parser.add_argument('--show', action = 'store_true', default = False, help = 'show tracks for a week')
  parser.add_argument('-w', '--week', type = int, dest = 'week', default = None, help = 'week to show')
  args = parser.parse_args()
  basedir = os.path.join(os.path.expanduser("~"), ".weeklysaver")
  ws = WeeklySaver(basedir = basedir)
  if args.show:
    ws.list_songs_for_week(args.week if args.week != None else get_this_week())
  else:
    ws.retrieve_weekly()
