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
`>ctf join [alias]`
user \"joins\" the ctf team for the specified channel with the *alias* being their username for CTFd.
the *alias* must be exactly what it is on the CTF platform
`>ctf leave`
removes channel role from user
`>ctf setcreds [ctfd username] [password] [https://ctf.url] "[server]" [channel]`
pin the message of ctf credentials, only runnable through DM with bot in order to preserve privacy
`>ctf challs`
get a list of the challenges in the ctf, and their statuses. *Updates DB every time this is called*
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
