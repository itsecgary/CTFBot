leaderboard_help = '''
`>rank`
display the user's rank
`>top10`
show the top 10 members and their points
'''

ctf_help = '''
`>ctf create "CTF NAME"`
create a text channel and role in the CTF category for a ctf (must have permissions to manage channels)*
`>ctf [join/leave]`
give the user the role of the ctf channel they are in
`>ctf setcreds [ctfd username] [password] [https://ctfd.url]`
pin the message of ctf credentials, can be fetched by the bot later in order to use >ctf challenge list.
`>ctf creds`
gets the credentials from the pinned message.
`>ctf challenge list`
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
`>help leaderboard`
info for all leaderboard commands
`>help ctftime`
info for all ctftime commands
`>help ctf`
info for all ctf commands
`>help`
print **this** help menu
'''

src = 'https://github.com/itsecgary/CTFBot'
