# CTFBot
A discord.py bot providing ctf platform integration and points system for
users on a Discord server. Currently, there are commands for CTFTime, CTFd APIs,
and for team setup.

This bot keeps track of what server members are doing for CTFs. There is a point
system that awards points for when members compete with the team. The bot keeps
track of statistics like number of competitions competed in, points
(from point system), ranking on server, and more.

Future Platform Integration:
- CTFx
- rCTF
- XCTF
- redCTF

## Functionality
There are three types of command groups for CTFBot:

`!help rank`
info for all leaderboard commands

`!help ctftime`
info for all ctftime commands

`!help ctf`
info for all ctf commands

`!help`
print **this** help menu


### CTFTime Commands:
These commands gather information about upcoming competitions, current
competitions, and leaderboards.

`!ctftime upcoming [1-5]`
return info on a number of upcoming ctfs from ctftime.org

`!ctftime current`
return info on the currently running ctfs on ctftime.org

`!ctftime [countdown/timeleft]`
return specific times for the time until a ctf begins, or until a currently running ctf ends

`!ctftime top [year]`
display the leaderboards from ctftime from a certain year


### CTF Commands:
These commands only work with the CTFd platform at the time being. A member is
able to pull challenges, set credentials, join teams, and edit channel info
(if permissions allow).

`!ctf create https://ctftime.org/event/[EVENT_ID]`
create a text channel and role in the CTF category for a ctf (must have permissions to manage channels)*

`!ctf join [alias]`
user \"joins\" the ctf team for the specified channel with the *alias* being their username for CTFd.
the *alias* must be exactly what it is on the CTF platform

`!ctf leave`
removes channel role from user

`!ctf setcreds [ctfd username] [password] [https://ctf.url] "[server]" [channel]`
pin the message of ctf credentials, only runnable through DM with bot in order to preserve privacy

`!ctf challs`
get a list of the challenges in the ctf, and their statuses. *Updates DB every time this is called*

`!ctf archive`
move the ctf channel to the archive category

`!ctf delete`
delete the ctf role, and entry from the database for the ctf (must have permissions to manage channels)*

### Rank Commands:
The rank commands are used to determine ones rank among their peers. There are
options to their own profile with all scored included and leaderboards for each
category.

`!rank me`
display the user's ranking and point info

`!rank top5`
show the top 5 members and their overall score

`!rank top5 [category]`
show the top 5 members and their score for specified category

<img src="images/rank_me.PNG" alt="Rank Me Command">

<img src="images/category.PNG" alt="Category Leaderboard Example">


## Point System
The point system we have developed aims to be a reasonable system to grade a
member's value in each specific category. We have included 10 different categories
to have ratings on as we have encountered them throughout several CTF competitions.

**Categories:**

| ------- | --------- | ------------------- |
| ------- | --------- | ------------------- |
| Crypto  | Forensics |  Web Exploitation   |
|  OSINT  |  Reverse  | Binary Exploitation |
| Network | TryHackMe |   Cryptocurrency    |
|  Misc   |   Mobile  |                     |

Each of these categories will be put through the following formula to decide the
value for each user:

<img src="images/points_system_challs.PNG" alt="Point System Formula">

<img src="images/points_system_challs2.PNG" alt="Point System Overall Formula">

For each competition, the values for each category will be averages to make it equal.
To calculate the **Overall** value of a member, the bot will take the average of
all of the categories. The **Overall** value is the underlying value of the
leaderboard and determines a member's rank.

## Authors:
- itsecgary
- aldenschmidt

## Creds:
We included several utilities from NullCTF's bot. The integration of CTFTime and
CTFd is very useful to this bot and assists the point system as well.

[NullCTF Github](https://github.com/NullPxl/NullCTF)
