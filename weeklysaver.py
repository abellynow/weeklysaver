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
import urllib
from wsgiref import simple_server, util

class Bearer(requests.auth.AuthBase):
  def __init__(self, access_token):
    self.access_token = access_token
  def __call__(self, r):
    if isinstance(self.access_token, str):
      r.headers['Authorization'] = b'Bearer ' + self.access_token.encode('utf-8')
    else: # assume bytes/bytearray
      r.headers['Authorization'] = b'Bearer ' + self.access_token
    return r

def rand_ascii(count):
  chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  rnd = os.urandom(count)
  rv = ''
  for i in range(count):
    rv += chars[rnd[i] % len(chars)]
  return rv

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

def query_split(q):
  rv = dict()
  l = q.split('&')
  for a in l:
    k, v = a.split('=')
    rv[k] = urllib.parse.unquote(v)
  return rv

def hash_file(filename):
  with open(filename, 'rb') as f:
    return hashlib.sha1(f.read()).hexdigest()

def hash_str(t):
  return hashlib.sha1(t).hexdigest()

class Spotify(object):
  state_key = 'spotify_auth_state'

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
  def create_auth_uri(self, redirect_uri):
    state = rand_ascii(16)
    scope = 'playlist-read-private'
    query = "https://accounts.spotify.com/authorize?response_type=code&client_id={}&scope={}&redirect_uri={}&state={}".format(self.keys['client_id'], scope, redirect_uri, state)
    cookie = "{}={}".format(self.state_key, state)
    return query, cookie
  def authorize(self, code, redirect_uri):
    r = requests.post('https://accounts.spotify.com/api/token',
                    auth = (self.keys['client_id'], self.keys['client_secret']),
                    data = {'code': code, 'redirect_uri': redirect_uri, 'grant_type': 'authorization_code'})
    if r.status_code != 200:
      return False
    jsb = r.json()
    self.session['access_token'] = jsb['access_token']
    if 'refresh_token' in jsb:
      self.session['refresh_token'] = jsb['refresh_token']
    self.save_tokens()
    return True
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

def get_playlist_filename_from_week_year(week, year = None, extra = None):
  return "DW-{}_W{:02d}{}.pl".format(year if year != None else datetime.datetime.now().year, week, "" if extra == None else "-{}".format(extra))

def get_playlist_filename_from_date(dt, is_early = True, extra = None):
  week_date = dt + datetime.timedelta(days = 1) if is_early and dt.weekday() == 6 else dt
  return "{}{}.pl".format(week_date.strftime("DW-%Y_W%V"), "" if extra == None else "-{}".format(extra))

def get_playlist_filename_from_date_str(dt, is_early = True, extra = None):
  added = datetime.datetime.strptime(dt[0:19], '%Y-%m-%dT%H:%M:%S')
  return get_playlist_filename_from_date(added, is_early, extra)

def get_playlist_filename_from_json(plj, is_early = True, extra = None):
  return get_playlist_filename_from_date_str(plj['items'][0]['added_at'][0:19], is_early, extra)

def get_this_week():
  return datetime.datetime.now().strftime("%V")

def get_this_year():
  return datetime.datetime.now().strftime("%Y")

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
  def hash_tracks_for_playlist(self, pjl):
    sha1 = hashlib.sha1()
    for it in pjl['items']:
      track = it['track']
      sha1.update(track['uri'].encode('utf-8'))
    return sha1.digest()
  def hash_tracks_for_playlist_file(self, plf):
    with open(plf, 'r') as plfile:
      pjl = json.load(plfile)
    return self.hash_tracks_for_playlist(pjl)
  def retrieve_weekly(self):
    if not 'playlist' in self.cfg or self.cfg['playlist'] == None:
      self.get_weekly_id()
    expected_filename = get_playlist_filename_from_date(datetime.datetime.now(), is_early = False)
    print("We would expect to get {}".format(expected_filename))
    if not os.path.exists(os.path.join(self.playlist_dir, expected_filename)):
      print("It seems like we don't have it, ask Spotify for it...")
      pl = self.sptfy.get_playlist(self.cfg['playlist'])
      pjl = json.loads(pl)
      new_hash = self.hash_tracks_for_playlist(pjl)
      new_name = get_playlist_filename_from_json(pjl)
      pl_filename = os.path.join(self.playlist_dir, new_name)
      if new_name != expected_filename:
        print("Hmm, seems like Spotify doesn't have it either...")
      print("Let's see if we already have what Spotify gave us...")
      count = 1
      while os.path.exists(pl_filename):
        old_hash = self.hash_tracks_for_playlist_file(pl_filename)
        if old_hash == new_hash:
          print("Same list different name!")
          return False
        # so, same name but different contents, we need a new name
        pl_filename = os.path.join(self.playlist_dir, get_playlist_filename_from_json(pjl, extra = count))
        count += 1
      with open(pl_filename, 'wb') as plf:
        plf.write(pl.encode('utf-8'))
      print("Great! We have a new one!")
      return True
    print("But we already have it, so let's not bother Spotify about it")
    return False
  def list_songs_for_week(self, weekno, year = None, extra = None):
    try:
      pl_filename = get_playlist_filename_from_week_year(weekno, year, extra)
      with open(os.path.join(self.playlist_dir, pl_filename), 'r') as plfile:
        pjl = json.load(plfile)
      for it in pjl['items']:
        track = it['track']
        print("{}/{}/{}".format(track['name'], ','.join([tn['name'] for tn in track['artists']]), track['album']['name']))
    except FileNotFoundError:
      print("No playlist found for week {:02d} ({})".format(weekno, year if year else get_this_year()))
  def serve(self, port):
    self.port = port
    self.handlers = {'/': self._index, '/login': self._login, '/callback': self._callback, '/favicon.ico': self._not_found, '/success': self._success, '/failure': self._failure}
    self.httpd = simple_server.make_server('', port, self._serve)
    self.httpd.serve_forever()
  def _not_found(self, parts, environ, respond):
    respond('404 Not Found', [('Content-Type', 'text/plain')])
    return [b'not found']
  def _success(self, parts, environ, respond):
    doc = "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"UTF-8\">\n<title>WeeklySaver</title>\n<body>\n"
    doc += "<h2>Success! WeeklySaver can now save your Discover Weekly</h2>\n"
    doc += "<div><a href=\"/login\">Login to Spotify</a></div>"
    doc += "</body></html>"
    respond('200 OK', [('Content-Type', 'text/html')])
    return [doc.encode('utf-8')]
  def _failure(self, parts, environ, respond):
    doc = "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"UTF-8\">\n<title>WeeklySaver</title>\n<body>\n"
    doc += "<h2>Failure! WeeklySaver cannot access your Discover Weekly</h2>\n"
    doc += "<div><a href=\"/login\">Login to Spotify</a></div>"
    doc += "</body></html>"
    respond('200 OK', [('Content-Type', 'text/html')])
    return [doc.encode('utf-8')]
  def _index(self, parts, environ, respond):
    doc = "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"UTF-8\">\n<title>WeeklySaver</title>\n<body>"
    doc += "<div><a href=\"/login\">Login to Spotify</a></div>"
    doc += "</body></html>"
    respond('200 OK', [('Content-Type', 'text/html')])
    return [doc.encode('utf-8')]
  def _login(self, parts, environ, respond):
    redirect_uri = "http://localhost:{}/callback".format(self.port)
    auth_uri, cookie = self.sptfy.create_auth_uri(redirect_uri)
    respond('301 Moved Permanently', [('Location', auth_uri), ('Set-Cookie', "{}".format(cookie))])
    return [b'301 Moved Permanently']
  def _callback(self, parts, environ, respond):
    redirect_uri = "http://localhost:{}/callback".format(self.port)
    query = query_split(environ['QUERY_STRING'])
    cookies = query_split(environ['HTTP_COOKIE'])
    code = query.get('code')
    state = query.get('state')
    storedState = cookies.get(self.sptfy.state_key)
    end_uri = "/failure"
    if state == None or state != storedState:
      print("ERROR! Bad state")
    else:
      if self.sptfy.authorize(code, redirect_uri):
        print("Got me some tokens!")
        end_uri = "/success"
    respond('301 Moved Permanently', [('Location', end_uri)])
    return [b'301 Moved Permanently']
  def _serve(self, environ, respond):
    try:
      parts = [p for p in environ['PATH_INFO'].split('/') if len(p) > 0]
      f = self.handlers['/' + parts[0] if len(parts) > 0 else '/']
      return f(parts, environ, respond)
    except KeyError:
      respond('404 Not Found', [('Content-Type', 'text/plain')])
      return [b'not found']


def main_prog():
  parser = argparse.ArgumentParser(description = 'WeeklySaver - saves your Spotify Discover Weekly')
  parser.add_argument('--serve', action = 'store_true', default = False, help = 'serve web page')
  parser.add_argument('-p', '--port', type = int, dest = 'port', default = 8888, help = 'website port number')
  parser.add_argument('--show', action = 'store_true', default = False, help = 'show tracks for a week')
  parser.add_argument('-w', '--week', type = int, dest = 'week', default = None, help = 'week to show')
  parser.add_argument('-y', '--year', type = int, dest = 'year', default = None, help = 'year to show')
  parser.add_argument('-e', '--extra', type = int, dest = 'extra', default = None, help = 'extra to show')
  args = parser.parse_args()

  basedir = os.path.join(os.path.expanduser("~"), ".weeklysaver")
  ws = WeeklySaver(basedir = basedir)
  if args.show:
    ws.list_songs_for_week(args.week if args.week != None else get_this_week(), args.year if args.year != None else get_this_year(), args.extra)
  elif args.serve:
    ws.serve(args.port)
  else:
    ws.retrieve_weekly()

if __name__ == "__main__":
  main_prog()
