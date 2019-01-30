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
and put it in `~/.weeklysaver/`. Next you need a `refresh_token` (and an `access_token`). Run `weeklysaver.py` with:
```
$ ./weeklysaver.py --serve
```
Which will serve a very basic web server at port `8888`. Optionally you can supply the `--port <portno>` if the default is not good for you. You need to whitelist `http://localhost:8888` in your Spotify Developer account for the project you have created earlier. Then go to `http://localhost:8888/` with you browser, click on the `Login to Spotify` link and follow the steps. If all goes well you should get a success page.
Finally setup a cron job to run weeklysaver.py once (or twice) a week, e.g.:
```
(crontab -l ; echo "43 8 * * 1,5 ~/bin/weeklysaver.py") | crontab -
```
will run WeeklySaver each Monday and Saturday.
