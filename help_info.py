leaderboard_help = '''
`>rank me`
display the user's ranking and point info
`>rank top5`
show the top 5 members and their overall score
`>rank top5 [category]`
show the top 5 members and their score for specified category
'''

ctf_help = '''
`>ctf create https://ctftime.org/event/[EVENT_ID]`
create a text channel and role in the CTF category for a ctf (must have permissions to manage channels)*
`>ctf join`
user \"joins\" the ctf general channel for the specific competition.
`>ctf form [team name]`
forms a team with specified team name (must have permissions to manage channels)*
`>ctf add @[user] [alias] [team name]`
adds user as specific alias to specific team (team name as shown for its channel) (must have permissions to manage channels)*
`>ctf rm @[user] [team name]`
removes user from specific team (team name as shown for its channel) (must have permissions to manage channels)*
`>ctf setcreds [ctfd username] [password] [https://ctf.url]`
give the bot access to your account (to grab info only) and pin the message of ctf credentials
`>ctf change [alias]`
change your alias in the database
`>ctf change [alias] @[user]`
change another user's alias (must have permissions)
`>ctf challs`
get a list of the challenges in the ctf, and their statuses. *Updates DB every time this is called*
`>ctf pull "[chall name]"`
pull information about a specific challenge along with the files associated to the challenge
`>ctf solve "[chall name]"`
this command is for competitions which only allow one sign-in per team
`>ctf leave`
removes channel role from user
`>ctf archive`
move the ctf channel to the archive category
`>ctf delete`
delete the ctf role, and entry from the database for the ctf (must have permissions to manage channels)*
'''

ctftime_help = '''
`>ctftime upcoming [1-5]`
return info on a number of upcoming ctfs from ctftime.org
`>ctftime current`
return info on the currently running ctfs on ctftime.org
`>ctftime [countdown/timeleft]`
return specific times for the time until a ctf begins, or until a currently running ctf ends
`>ctftime top [year]`
display the leaderboards from ctftime from a certain year
'''

help_page = '''
`>help rank`
info for all leaderboard commands
`>help ctftime`
info for all ctftime commands
`>help ctf`
info for all ctf commands
`>help`
print **this** help menu
'''

src = 'https://github.com/itsecgary/CTFBot'
