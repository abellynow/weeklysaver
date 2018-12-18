# WeeklySaver
Saving your Spotify Discover Weekly every week

## Audience
This if for those (like me) thinking that the best feature of Spotify is Discover Weekly and you try to keep up saving the best bits, but some weeks you simply don't have the time.

## Background
WeeklySaver is intended to be run as a cron job once (or maybe twice) a week. Currently it only supports storing your Discover Weekly offline, locally on the machine that runs it. It could be made to create a new permanent playlist each week (the Spotify REST API supports it) but that would mean putting potentially undesirable songs into the data used to create your next Discover Weekly.

## Setup
In order to use WeeklySaver atm you need to register for a Spotify Developer account and create a project to get a `client_id` and a `client_secret` that you can use to authenticate against the Spotify API. Once you have the `client_id`/`client_secret` you put the in a file called `keys`:
```
client_id=<your client_id>
client_secret=<your client_secret>
```
and put it in `~/.weeklysaver/`. Next you need a `refresh_token` (because WeeklySaver does not currently support creating one as it involves serving a HTTP server). Go through the Spotify Authentication sample to get it. You need to change the scope to `playlist-read-private` for WeeklySaver to work. Finally save the `refresh_token` you get from running the sample app (you can save the `access_token` as well). Put them in another file called `session`:
```
refresh_token=<the refresh_token you got>
access_token=<the access_token you got>
```
Finally setup a cron job to run weeklysaver.py once (or twice) a week, e.g.:
```
(crontab -l ; echo "* * * * 1,5 ~/bin/weeklysaver.py") | crontab -
```
will run WeeklySaver each Monday and Saturday.
