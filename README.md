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
<img src="images/help.PNG" alt="Help Info">

**CTFTime Commands:**
<img src="images/ctftime_help.PNG" alt="CTFTime Help Info">

These commands gather information about upcoming competitions, current
competitions, and leaderboards.

**CTF Commands:**
<img src="images/ctf_help.PNG" alt="CTF Help Info">

These commands only work with the CTFd platform at the time being. A member is
able to pull challenges, set credentials, join teams, and edit channel info
(if permissions allow).

**Rank Commands:**
<img src="images/rank_help.PNG" alt="Rank Help Info">

The rank commands are used to determine ones rank among their peers. There are
options to their own profile with all scored included and leaderboards for each
category.

<img src="images/rank_me.PNG" alt="Rank Me Command">

<img src="images/category.PNG" alt="Category Leaderboard Example">


## Point System
The point system we have developed aims to be a reasonable system to grade a
member's value in each specific category. We have included 10 different categories
to have ratings on as we have encountered them throughout several CTF competitions.

**Categories:**
- Crypto
- Forensics
- OSINT
- Web Exploitation
- Binary Exploitation
- Reverse
- TryHackMe
- Cryptocurrency
- Network

| Crypto  | Forensics |  Web Exploitation   |
|  OSINT  |  Reverse  | Binary Exploitation |
| Network | TryHackMe |   Cryptocurrency    |

Each of these categories will be put through the following formula to decide the
value for each user:

<img src="images/points_system_challs.PNG" alt="Point System Formula">

<img src="images/points_system_challs2.PNG" alt="Point System Overall Formula">

For each competition, the values for each category will be averages to make it equal.
To calculate the **Overall** value of a member, the bot will take the average of
all of the categories. The **Overall** value is the underlying value of the
leaderboard and determines a member's rank.

### Authors:
- itsecgary
- aldenschmidt

### Creds:
We included several utilities from NullCTF's bot. The integration of CTFTime and
CTFd is very useful to this bot and assists the point system as well.

[NullCTF Github](https://github.com/NullPxl/NullCTF)
